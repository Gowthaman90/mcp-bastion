/**
 * An audit sink that exports events as OpenTelemetry **logs** over OTLP/HTTP
 * (JSON). Point `endpoint` at an OpenTelemetry Collector and events can be routed
 * from there to any backend (SIEM, cloud logging, object storage, …) — so this
 * one sink effectively unlocks the whole OTel ecosystem.
 *
 * Dependency-free: uses the global `fetch`. Events are batched; `write` never
 * blocks, and `flush`/`close` await in-flight exports. One retry on failure.
 *
 * @packageDocumentation
 */
import { BASTION_NAME, BASTION_VERSION } from "../../core/constants.js";
import { logger } from "../../observability/index.js";
import type { AuditEvent, AuditSink } from "../types.js";

export interface OtlpSinkOptions {
  /** Base OTLP/HTTP endpoint, e.g. `http://localhost:4318` (the `/v1/logs` path is appended). */
  endpoint: string;
  /** Extra headers (e.g. an auth token) sent with each export. */
  headers?: Record<string, string>;
  batchSize: number;
  timeoutMs: number;
}

/** An OTLP key/value attribute. */
function attr(key: string, value: string | number): { key: string; value: unknown } {
  return Number.isInteger(value)
    ? { key, value: { intValue: value } }
    : { key, value: { stringValue: String(value) } };
}

/** ISO timestamp → OTLP `timeUnixNano` (nanoseconds, as a string; BigInt avoids precision loss). */
function toUnixNano(iso: string): string {
  return (BigInt(new Date(iso).getTime()) * 1_000_000n).toString();
}

/**
 * Map audit events to an OTLP/HTTP logs JSON payload (resourceLogs → scopeLogs →
 * logRecords). Exported for testing.
 */
export function toOtlpLogs(events: readonly AuditEvent[]): unknown {
  return {
    resourceLogs: [
      {
        resource: { attributes: [attr("service.name", BASTION_NAME)] },
        scopeLogs: [
          {
            scope: { name: BASTION_NAME, version: BASTION_VERSION },
            logRecords: events.map((event) => {
              const isWarn = event.outcome !== "ok";
              const attributes: Array<{ key: string; value: unknown }> = [
                attr("mcp.server", event.server),
                attr("mcp.tool", event.tool),
                attr("mcp.decision", event.decision),
                attr("mcp.outcome", event.outcome),
                attr("duration_ms", event.durationMs),
                attr("trace_id", event.traceId),
              ];
              if (event.definitionHash) {
                attributes.push(attr("mcp.definition_hash", event.definitionHash));
              }
              for (const control of event.frameworks.nistAiRmf) {
                attributes.push(attr("compliance.nist_ai_rmf", control));
              }
              for (const control of event.frameworks.owaspLlm) {
                attributes.push(attr("compliance.owasp_llm", control));
              }
              return {
                timeUnixNano: toUnixNano(event.ts),
                severityNumber: isWarn ? 13 : 9, // WARN : INFO
                severityText: isWarn ? "WARN" : "INFO",
                body: {
                  stringValue: `${event.decision} ${event.server}/${event.tool} -> ${event.outcome}`,
                },
                attributes,
              };
            }),
          },
        ],
      },
    ],
  };
}

export class OtlpSink implements AuditSink {
  readonly name: string;
  private buffer: AuditEvent[] = [];
  private readonly pending = new Set<Promise<void>>();
  private readonly url: string;

  constructor(private readonly opts: OtlpSinkOptions) {
    this.url = `${opts.endpoint.replace(/\/+$/, "")}/v1/logs`;
    this.name = `otlp:${this.url}`;
  }

  write(event: AuditEvent): void {
    this.buffer.push(event);
    if (this.buffer.length >= this.opts.batchSize) this.dispatch();
  }

  async flush(): Promise<void> {
    this.dispatch();
    await Promise.all([...this.pending]);
  }

  async close(): Promise<void> {
    await this.flush();
  }

  private dispatch(): void {
    if (this.buffer.length === 0) return;
    const batch = this.buffer;
    this.buffer = [];
    const task = this.send(batch).finally(() => this.pending.delete(task));
    this.pending.add(task);
  }

  private async send(events: AuditEvent[], attempt = 0): Promise<void> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.opts.timeoutMs);
      try {
        const res = await fetch(this.url, {
          method: "POST",
          headers: { "content-type": "application/json", ...(this.opts.headers ?? {}) },
          body: JSON.stringify(toOtlpLogs(events)),
          signal: controller.signal,
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      if (attempt === 0) {
        await this.send(events, 1); // one retry
        return;
      }
      logger.warn(
        { sink: this.name, count: events.length, err: (err as Error)?.message ?? String(err) },
        "OTLP export failed",
      );
    }
  }
}
