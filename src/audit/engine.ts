/**
 * The audit engine: turns each tool call into a structured, framework-mapped
 * {@link AuditEvent} and fans it out to the configured sinks. It exposes a single
 * interceptor that is placed FIRST in the pipeline so that it records blocked
 * calls (short-circuited by later security interceptors) as well as allowed ones.
 *
 * @packageDocumentation
 */
import { randomUUID } from "node:crypto";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { AuditConfig } from "../config/index.js";
import { logger } from "../observability/index.js";
import type { Interceptor, ToolCallContext } from "../security/index.js";
import { chainHash } from "./chain.js";
import { buildComplianceReport, frameworksFor, type ComplianceReport } from "./compliance.js";
import { prepareArgs } from "./redaction.js";
import {
  AUDIT_SCHEMA_VERSION,
  type AuditDecision,
  type AuditEvent,
  type AuditOutcome,
  type AuditSink,
} from "./types.js";

const MAX_RECENT = 1000;

export class AuditEngine {
  private seq = 0;
  private prevHash = "";
  private readonly recent: AuditEvent[] = [];

  constructor(
    private readonly config: AuditConfig,
    private readonly sinks: readonly AuditSink[],
  ) {}

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

  /** Aggregate compliance report over recent events (backs `bastion__compliance`). */
  complianceReport(): ComplianceReport {
    return buildComplianceReport(this.recent);
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
    result: CallToolResult | undefined,
    threw: boolean,
  ): void {
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
      const hash = chainHash(this.prevHash, unhashed);
      this.prevHash = hash;
      event = { ...unhashed, hash };
    }

    if (this.recent.push(event) > MAX_RECENT) this.recent.shift();
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
