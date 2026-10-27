/**
 * An audit sink that exports events as OpenTelemetry **logs** over OTLP/HTTP
 * (JSON). Point `endpoint` at an OpenTelemetry Collector and events can be routed
 * from there to any backend (SIEM, cloud logging, object storage, …) — so this
 * one sink effectively unlocks the whole OTel ecosystem.
 *
 * Dependency-free: uses the global `fetch`. Delivery (bounded queue, retry with
 * backoff, drop-oldest, health counters) is shared with the webhook sink.
 *
 * @packageDocumentation
 */
import { BASTION_NAME, BASTION_VERSION } from "../../core/constants.js";
import type { AuditEvent, AuditRecord } from "../types.js";
import { HttpBatchSink } from "./http-batch.js";

export interface OtlpSinkOptions {
  /** Base OTLP/HTTP endpoint, e.g. `http://localhost:4318` (the `/v1/logs` path is appended). */
  endpoint: string;
  /** Extra headers (e.g. an auth token) sent with each export. */
  headers?: Record<string, string>;
  batchSize: number;
  timeoutMs: number;
  /** Most events held while the collector is unreachable. Default 10 000. */
  maxQueue?: number;
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

/** A run-start or checkpoint record as an INFO log record (attributes carry the chain facts). */
function chainRecordToOtlp(record: Exclude<AuditRecord, AuditEvent>): unknown {
  const attributes = [
    attr("audit.record_type", record.recordType),
    attr("audit.run_id", record.runId),
  ];
  if (record.recordType === "checkpoint") {
    attributes.push(
      attr("audit.seq", record.seq),
      attr("audit.head", record.head),
      attr("audit.key_id", record.keyId),
    );
  }
  return {
    timeUnixNano: toUnixNano(record.ts),
    severityNumber: 9,
    severityText: "INFO",
    body: { stringValue: JSON.stringify(record) },
    attributes,
  };
}

/**
 * Map audit events to an OTLP/HTTP logs JSON payload (resourceLogs → scopeLogs →
 * logRecords). Exported for testing.
 */
export function toOtlpLogs(records: readonly AuditRecord[]): unknown {
  return {
    resourceLogs: [
      {
        resource: { attributes: [attr("service.name", BASTION_NAME)] },
        scopeLogs: [
          {
            scope: { name: BASTION_NAME, version: BASTION_VERSION },
            logRecords: records.map((record) => {
              if ("recordType" in record) return chainRecordToOtlp(record);
              const event: AuditEvent = record;
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

export class OtlpSink extends HttpBatchSink {
  readonly name: string;

  constructor(opts: OtlpSinkOptions) {
    const url = `${opts.endpoint.replace(/\/+$/, "")}/v1/logs`;
    super({
      url,
      headers: opts.headers,
      batchSize: opts.batchSize,
      timeoutMs: opts.timeoutMs,
      maxQueue: opts.maxQueue ?? 10_000,
    });
    this.name = `otlp:${url}`;
  }

  protected body(events: AuditRecord[]): unknown {
    return toOtlpLogs(events);
  }
}
