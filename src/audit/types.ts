/**
 * Types for the audit layer: the versioned event schema and the pluggable sink
 * interface. These two contracts are intentionally stable so that new sinks
 * (OTLP, SIEM, cloud) can be added without changing the event producers.
 *
 * @packageDocumentation
 */
import type { Severity } from "../security/index.js";

/** Version of the {@link AuditEvent} schema. Bump on any breaking change. */
export const AUDIT_SCHEMA_VERSION = 1;

/** The security decision recorded for a tool call. */
export type AuditDecision = "allowed" | "blocked_rug_pull" | "blocked_poisoning";

/** The observed outcome of a tool call. */
export type AuditOutcome = "ok" | "error" | "blocked";

/** Governance frameworks a decision maps to. */
export interface FrameworkMapping {
  /** NIST AI RMF functions (e.g. `MEASURE`, `MANAGE`). */
  nistAiRmf: string[];
  /** OWASP LLM Top 10 categories (e.g. `LLM01: Prompt Injection`). */
  owaspLlm: string[];
}

/** A single, structured audit record for one tool call. */
export interface AuditEvent {
  schemaVersion: number;
  /** Monotonic per-process sequence number. */
  seq: number;
  /** ISO-8601 timestamp. */
  ts: string;
  /** Correlation id for this call. */
  traceId: string;
  server: string;
  /** Original (un-namespaced) tool name. */
  tool: string;
  /** Client-visible namespaced name. */
  namespacedName: string;
  /** Fingerprint of the tool definition at call time, when known. */
  definitionHash?: string;
  decision: AuditDecision;
  outcome: AuditOutcome;
  durationMs: number;
  /** Security findings on the tool's description, when any. */
  findings?: { rule: string; severity: Severity }[];
  frameworks: FrameworkMapping;
  /** Tool arguments — omitted, redacted, or full per `audit.includeArgs`. */
  args?: Record<string, unknown>;
  /** Previous event's hash (present only when tamper-evidence is enabled). */
  prevHash?: string;
  /** This event's hash over its content + `prevHash` (tamper-evidence). */
  hash?: string;
}

/**
 * A destination for audit events. Implementations must make `write` non-blocking
 * (buffer internally); durability/delivery is finalized in `flush`/`close`.
 */
export interface AuditSink {
  /** Human-readable sink name, for logs. */
  readonly name: string;
  /** Record an event. MUST NOT block the caller. */
  write(event: AuditEvent): void;
  /** Flush any buffered events to their destination. */
  flush(): Promise<void>;
  /** Flush and release resources. */
  close(): Promise<void>;
}
