/**
 * The audit engine: turns each tool call into a structured, framework-mapped
 * {@link AuditEvent} and fans it out to the configured sinks. It exposes a single
 * interceptor that is placed FIRST in the pipeline so that it records blocked
 * calls (short-circuited by later security interceptors) as well as allowed ones.
 *
 * @packageDocumentation
 */
import { randomUUID } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import type { CallToolResult } from "@modelcontextprotocol/server";
import type { ToolCallOutcome } from "../security/types.js";

import type { AuditConfig } from "../config/index.js";
import { BASTION_VERSION } from "../core/constants.js";
import { textResult } from "../internal/results.js";
import { logger } from "../observability/index.js";
import { findingKind, type Interceptor, type ToolCallContext } from "../security/index.js";
import { argsDigest, chainHash } from "./chain.js";
import { CheckpointSigner } from "./checkpoint.js";
import { frameworksFor, type ComplianceReport } from "./compliance.js";
import { prepareArgs, type IncludeArgs } from "./redaction.js";
import { createSinks } from "./sinks/index.js";
import {
  AUDIT_SCHEMA_VERSION,
  type AuditDecision,
  type AuditEvent,
  type AuditOutcome,
  type AuditRecord,
  type AuditRunStart,
  type AuditSink,
  type SinkHealth,
} from "./types.js";

export class AuditEngine {
  private seq = 0;
  private prevHash = "";
  /**
   * Durable, monotonic compliance totals — updated for every event and never
   * evicted, so a flood of benign calls cannot roll an earlier malicious event
   * off the report (which a bounded recent-events buffer would allow).
   */
  private readonly totals: ComplianceReport = {
    totalEvents: 0,
    byDecision: {},
    byOutcome: {},
    controls: { nistAiRmf: {}, owaspLlm: {} },
  };
  /** HMAC key for the integrity chain (out-of-band). Unset → unkeyed SHA-256 chain. */
  private readonly integrityKey: string | undefined;
  /** Identifies this run; carried by every record. */
  readonly runId = randomUUID();
  /** Chain v2: sinks record arguments differently, so the hash excludes the per-sink `args` view. */
  private readonly chainV2: boolean;
  private readonly signer: CheckpointSigner | undefined;
  private readonly checkpointSinks: AuditSink[];
  private readonly checkpointTimer: ReturnType<typeof setInterval> | undefined;
  private callCount = 0;
  private sinceCheckpoint = 0;

  /**
   * @throws Error if `checkpoint` is configured without a usable Ed25519 private key.
   */
  constructor(
    private readonly config: AuditConfig,
    private readonly sinks: readonly AuditSink[],
  ) {
    this.integrityKey = config.integrityKey ?? process.env.MCP_BASTION_AUDIT_KEY;
    const modes = new Set(sinks.map((sk) => sk.includeArgs ?? config.includeArgs));
    this.chainV2 = config.tamperEvident && modes.size > 1;
    if (this.chainV2 && !this.integrityKey) {
      logger.warn(
        "audit sinks record arguments differently and the chain has no integrityKey: arguments are not covered by the hash chain",
      );
    }

    const cp = config.checkpoint;
    if (cp) {
      this.signer = new CheckpointSigner(loadCheckpointKey(cp.privateKeyFile));
      this.checkpointSinks = createSinks(cp.sinks);
      this.writeRunStart(cp.stateFile);
      this.checkpointTimer = setInterval(() => {
        if (this.sinceCheckpoint > 0) this.checkpoint();
      }, cp.everySeconds * 1000);
      this.checkpointTimer.unref?.();
    } else {
      this.checkpointSinks = [];
    }
  }

  /** The interceptor to place first in the tool-call pipeline. */
  buildInterceptor(): Interceptor {
    return async (ctx, next) => {
      const traceId = randomUUID();
      const start = Date.now();
      if (this.config.onSinkFailure === "block" && this.allSinksDown()) {
        ctx.securityDecision = "blocked_audit_unavailable";
        logger.error(
          { tool: ctx.namespacedName },
          "call refused: no audit sink can deliver (onSinkFailure: block)",
        );
        const refused = textResult(
          `Blocked by mcp-bastion: the audit trail is unavailable, and this deployment refuses calls that ` +
            `cannot be recorded. Try again later or ask an operator to check the audit sinks.`,
          true,
        );
        this.record(ctx, traceId, 0, refused, false);
        return refused;
      }
      try {
        const result = await next();
        this.record(ctx, traceId, Date.now() - start, result, false);
        return result;
      } catch (err) {
        this.record(ctx, traceId, Date.now() - start, undefined, true);
        throw err;
      }
    };
  }

  /**
   * Record a call that was refused before the pipeline ran (e.g. a blocking delegation check, which
   * must stop the call before any upstream contact). `ctx.securityDecision` names the decision.
   */
  recordPreflight(ctx: ToolCallContext): void {
    this.record(ctx, randomUUID(), 0, undefined, false);
  }

  /** Durable, monotonic compliance report (backs `bastion__compliance`). */
  complianceReport(): ComplianceReport {
    return {
      totalEvents: this.totals.totalEvents,
      byDecision: { ...this.totals.byDecision },
      byOutcome: { ...this.totals.byOutcome },
      controls: {
        nistAiRmf: { ...this.totals.controls.nistAiRmf },
        owaspLlm: { ...this.totals.controls.owaspLlm },
      },
    };
  }

  /** Delivery health of every sink that reports it (backs `bastion__status`). */
  sinkHealth(): SinkHealth[] {
    return [...this.sinks, ...this.checkpointSinks].flatMap((s) => (s.health ? [s.health()] : []));
  }

  /** True when every sink reports health and none can deliver. A sink without health counts as up. */
  private allSinksDown(): boolean {
    return (
      this.sinks.length > 0 &&
      this.sinks.every((s) => s.health !== undefined && !s.health().healthy)
    );
  }

  /** Flush all sinks. */
  async flush(): Promise<void> {
    await Promise.allSettled([...this.sinks, ...this.checkpointSinks].map((s) => s.flush()));
  }

  /** Write a final checkpoint (when configured), then flush and close all sinks. */
  async close(): Promise<void> {
    if (this.checkpointTimer) clearInterval(this.checkpointTimer);
    if (this.signer) this.checkpoint();
    await Promise.allSettled([...this.sinks, ...this.checkpointSinks].map((s) => s.close()));
  }

  /** Sign the current chain head and write it to every sink and the checkpoint witnesses. */
  checkpoint(): void {
    if (!this.signer) return;
    const cp = this.signer.sign({
      runId: this.runId,
      seq: this.seq,
      head: this.prevHash,
      count: this.callCount,
    });
    this.sinceCheckpoint = 0;
    this.emitTo([...this.sinks, ...this.checkpointSinks], cp);
    const stateFile = this.config.checkpoint?.stateFile;
    if (stateFile) {
      try {
        writeFileSync(
          stateFile,
          JSON.stringify({ runId: this.runId, seq: this.seq, hash: this.prevHash }) + "\n",
          { mode: 0o600 },
        );
        chmodSync(stateFile, 0o600);
      } catch (err) {
        logger.warn(
          { stateFile, err: (err as Error)?.message ?? String(err) },
          "could not write the audit checkpoint state file",
        );
      }
    }
  }

  /** The chained first record of a run, linking to the previous run's last checkpoint when known. */
  private writeRunStart(stateFile: string | undefined): void {
    let prevRunHead: AuditRunStart["prevRunHead"];
    if (stateFile && existsSync(stateFile)) {
      try {
        const st = JSON.parse(readFileSync(stateFile, "utf8")) as {
          runId?: unknown;
          seq?: unknown;
          hash?: unknown;
        };
        if (
          typeof st.runId === "string" &&
          typeof st.seq === "number" &&
          typeof st.hash === "string"
        ) {
          prevRunHead = { runId: st.runId, seq: st.seq, hash: st.hash };
        }
      } catch (err) {
        logger.warn(
          { stateFile, err: (err as Error)?.message ?? String(err) },
          "unreadable audit checkpoint state file; starting an unlinked run",
        );
      }
    }
    const unhashed: Omit<AuditRunStart, "hash"> = {
      recordType: "run-start",
      schemaVersion: AUDIT_SCHEMA_VERSION,
      seq: 0,
      ts: new Date().toISOString(),
      runId: this.runId,
      bastionVersion: BASTION_VERSION,
      ...(prevRunHead ? { prevRunHead } : {}),
      prevHash: this.prevHash,
    };
    const hash = chainHash(this.prevHash, unhashed, this.integrityKey);
    this.prevHash = hash;
    this.emitTo(this.sinks, { ...unhashed, hash });
  }

  private record(
    ctx: ToolCallContext,
    traceId: string,
    durationMs: number,
    callOutcome: ToolCallOutcome | undefined,
    threw: boolean,
  ): void {
    // An MRTR continuation is neither ok nor error: it has no content yet. Record it as ok.
    const result =
      callOutcome && "content" in callOutcome ? (callOutcome as CallToolResult) : undefined;
    const decision: AuditDecision = ctx.securityDecision ?? "allowed";
    const outcome: AuditOutcome = threw
      ? "error"
      : ctx.securityDecision
        ? "blocked"
        : result?.isError
          ? "error"
          : "ok";

    const core: Omit<AuditEvent, "prevHash" | "hash"> = {
      schemaVersion: AUDIT_SCHEMA_VERSION,
      seq: ++this.seq,
      ts: new Date().toISOString(),
      traceId,
      server: ctx.server,
      tool: ctx.toolName,
      namespacedName: ctx.namespacedName,
      definitionHash: ctx.definitionHash,
      decision,
      outcome,
      durationMs,
      findings: ctx.findings?.map((f) => ({
        rule: f.rule,
        severity: f.severity,
        kind: findingKind(f.rule),
      })),
      ...(ctx.responseFindings?.length
        ? {
            responseFindings: ctx.responseFindings.map((f) => ({
              rule: f.rule,
              severity: f.severity,
              kind: findingKind(f.rule),
            })),
          }
        : {}),
      ...(ctx.redactedSecrets ? { redactedSecrets: ctx.redactedSecrets } : {}),
      ...(ctx.wouldBlock ? { wouldBlock: ctx.wouldBlock } : {}),
      frameworks: frameworksFor(decision, ctx.findings ?? []),
      // Chain v1 (and no chain): every sink records `audit.includeArgs`; per-sink views in emit().
      ...(this.chainV2
        ? {}
        : { args: prepareArgs(ctx.args, this.config.includeArgs, this.config.redactKeys) }),
      ...(ctx.forwardedHeaders?.length ? { forwardedHeaders: [...ctx.forwardedHeaders] } : {}),
      ...(ctx.delegation ? { delegation: ctx.delegation } : {}),
      ...(ctx.authorization ? { authorization: ctx.authorization } : {}),
      runId: this.runId,
      ...(this.chainV2 ? { chainVersion: 2 as const } : {}),
      ...(this.chainV2 && this.integrityKey
        ? { argsDigest: argsDigest(ctx.args, this.integrityKey) }
        : {}),
    };

    let event: AuditEvent = core;
    if (this.config.tamperEvident) {
      const unhashed = { ...core, prevHash: this.prevHash };
      const hash = chainHash(this.prevHash, unhashed, this.integrityKey);
      this.prevHash = hash;
      event = { ...unhashed, hash };
    }

    // Fold into the durable monotonic totals (never evicted).
    this.totals.totalEvents++;
    this.totals.byDecision[decision] = (this.totals.byDecision[decision] ?? 0) + 1;
    this.totals.byOutcome[outcome] = (this.totals.byOutcome[outcome] ?? 0) + 1;
    for (const c of core.frameworks.nistAiRmf)
      this.totals.controls.nistAiRmf[c] = (this.totals.controls.nistAiRmf[c] ?? 0) + 1;
    for (const c of core.frameworks.owaspLlm)
      this.totals.controls.owaspLlm[c] = (this.totals.controls.owaspLlm[c] ?? 0) + 1;

    this.emitEvent(event, ctx.args);
    this.callCount++;
    this.sinceCheckpoint++;
    if (this.signer && this.sinceCheckpoint >= (this.config.checkpoint?.everyEvents ?? Infinity)) {
      this.checkpoint();
    }
  }

  /** Write a call event, giving each sink its own `args` view when views can differ. */
  private emitEvent(event: AuditEvent, args: Record<string, unknown>): void {
    const perSink = this.chainV2 || !this.config.tamperEvident;
    for (const sink of this.sinks) {
      if (!perSink) {
        this.emitTo([sink], event);
        continue;
      }
      const mode: IncludeArgs = sink.includeArgs ?? this.config.includeArgs;
      const view = prepareArgs(args, mode, this.config.redactKeys);
      const { args: _shared, ...rest } = event;
      this.emitTo([sink], view === undefined ? rest : { ...rest, args: view });
    }
  }

  private emitTo(sinks: readonly AuditSink[], record: AuditRecord): void {
    for (const sink of sinks) {
      try {
        sink.write(record);
      } catch (err) {
        logger.warn(
          { sink: sink.name, err: (err as Error)?.message ?? String(err) },
          "audit sink write failed",
        );
      }
    }
  }
}

/** Read the checkpoint signing key from a file or `MCP_BASTION_CHECKPOINT_KEY`. */
function loadCheckpointKey(file: string | undefined): string {
  if (file) {
    try {
      return readFileSync(file, "utf8");
    } catch (err) {
      throw new Error(
        `audit checkpoint key file "${file}" is unreadable: ${(err as Error).message}`,
        { cause: err },
      );
    }
  }
  const pem = process.env.MCP_BASTION_CHECKPOINT_KEY;
  if (!pem) {
    throw new Error(
      "audit.checkpoint needs an Ed25519 private key: set audit.checkpoint.privateKeyFile or MCP_BASTION_CHECKPOINT_KEY (create one with `mcp-bastion audit keygen`)",
    );
  }
  return pem;
}
