/**
 * The audit engine: turns each tool call into a structured, framework-mapped
 * {@link AuditEvent} and fans it out to the configured sinks. It exposes a single
 * interceptor that is placed FIRST in the pipeline so that it records blocked
 * calls (short-circuited by later security interceptors) as well as allowed ones.
 *
 * @packageDocumentation
 */
import { randomUUID } from "node:crypto";
import type { CallToolResult } from "@modelcontextprotocol/server";
import type { ToolCallOutcome } from "../security/types.js";

import type { AuditConfig } from "../config/index.js";
import { logger } from "../observability/index.js";
import type { Interceptor, ToolCallContext } from "../security/index.js";
import { chainHash } from "./chain.js";
import { frameworksFor, type ComplianceReport } from "./compliance.js";
import { prepareArgs } from "./redaction.js";
import {
  AUDIT_SCHEMA_VERSION,
  type AuditDecision,
  type AuditEvent,
  type AuditOutcome,
  type AuditSink,
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

  constructor(
    private readonly config: AuditConfig,
    private readonly sinks: readonly AuditSink[],
  ) {
    this.integrityKey = config.integrityKey ?? process.env.MCP_BASTION_AUDIT_KEY;
  }

  /** The interceptor to place first in the tool-call pipeline. */
  buildInterceptor(): Interceptor {
    return async (ctx, next) => {
      const traceId = randomUUID();
      const start = Date.now();
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

  /** Flush all sinks. */
  async flush(): Promise<void> {
    await Promise.allSettled(this.sinks.map((s) => s.flush()));
  }

  /** Flush and close all sinks. */
  async close(): Promise<void> {
    await Promise.allSettled(this.sinks.map((s) => s.close()));
  }

  private record(
    ctx: ToolCallContext,
    traceId: string,
    durationMs: number,
    callOutcome: ToolCallOutcome | undefined,
    threw: boolean,
  ): void {
    // An MRTR continuation is neither ok nor error: it has no content yet. Record it as ok.
    const result = callOutcome && "content" in callOutcome ? (callOutcome as CallToolResult) : undefined;
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
      findings: ctx.findings?.map((f) => ({ rule: f.rule, severity: f.severity })),
      frameworks: frameworksFor(decision, ctx.findings ?? []),
      args: prepareArgs(ctx.args, this.config.includeArgs, this.config.redactKeys),
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

    this.emit(event);
  }

  private emit(event: AuditEvent): void {
    for (const sink of this.sinks) {
      try {
        sink.write(event);
      } catch (err) {
        logger.warn(
          { sink: sink.name, err: (err as Error)?.message ?? String(err) },
          "audit sink write failed",
        );
      }
    }
  }
}
