/**
 * Types for the audit layer: the versioned event schema and the pluggable sink
 * interface. These two contracts are intentionally stable so that new sinks
 * (OTLP, SIEM, cloud) can be added without changing the event producers.
 *
 * @packageDocumentation
 */
import type { FindingKind, Severity } from "../security/index.js";

/** Version of the {@link AuditEvent} schema. Bump on any breaking change. */
export const AUDIT_SCHEMA_VERSION = 1;

/** The security decision recorded for a tool call. */
export type AuditDecision =
  | "allowed"
  | "blocked_rug_pull"
  | "blocked_poisoning"
  | "blocked_response"
  | "blocked_schema"
  | "blocked_identity"
  | "blocked_dataflow"
  | "blocked_input_required"
  | "blocked_request_state"
  | "blocked_delegation"
  | "blocked_authorization"
  | "blocked_audit_unavailable";

/** The observed outcome of a tool call. */
export type AuditOutcome = "ok" | "error" | "blocked";

/** Governance frameworks a decision maps to. */
export interface FrameworkMapping {
  /** NIST AI RMF functions (e.g. `MEASURE`, `MANAGE`). */
  nistAiRmf: string[];
  /** OWASP LLM Top 10 categories (e.g. `LLM01: Prompt Injection`). */
  owaspLlm: string[];
}

/**
 * The "who acted for whom" record of one delegated call. Never holds the token, and no claim value
 * beyond these fields.
 */
export interface AuditDelegationRecord {
  /** `hmac:` + 16 hex of HMAC-SHA256(subjectKey, `iss|sub`), or `sub` itself under `recordSubject: "plain"`. */
  subject: string | null;
  issuer: string | null;
  /** The upstream's configured audience. */
  audience: string;
  /** `jti`, when present. */
  tokenId: string | null;
  /** `exp` as ISO-8601, when present. */
  expiresAt: string | null;
  /** Current actor first, then prior actors (agent ids). */
  actors: string[];
  chainDepth: number;
  /**
   * `structural`: claims checked, signature not verified. `signature`: the signature verified under
   * a trusted public key. `failed`: signature mode, and it did not verify.
   */
  verified: "structural" | "signature" | "failed";
  findings: { rule: string; severity: Severity }[];
}

/**
 * The runtime-authorization decision on one call. Rule ids and identity kinds only: never a user
 * `sub`, a token, or any other policy content.
 */
export interface AuditAuthorizationRecord {
  effect: "allow" | "deny";
  /** The deciding rule id (see `AuthorizationDecision.rule`), or `null`. */
  rule: string | null;
  /** Whether no rule decided (refused for lack of a grant, or allowed by `default: "allow"`). */
  byDefault: boolean;
  /** The authenticated client name (`listen.clients` key, `default`, `stdio` or `anonymous`). */
  client: string;
  /** Identity kinds the call carried, e.g. `["client", "user", "agent"]`. */
  identities: string[];
  /** `<kind>:<reason>` per refused identity (`denied`, `no-grant`, `argument`, `unverified`). */
  violations: string[];
  /**
   * The deciding rule per evaluated identity, e.g. `{ client: "orchestrator-files", user: "files-run" }`:
   * its matching deny, else the allow that admitted it; `null` when no rule decided (no grant, or
   * allowed by `default: "allow"`). Only identities the call carried have a key. Rule ids only.
   */
  rules?: Partial<Record<"client" | "user" | "agent", string | null>>;
}

/** One finding as recorded in an audit event. */
export interface AuditFinding {
  rule: string;
  severity: Severity;
  /** `heuristic` (pattern-based) or `deterministic` (exact check). */
  kind: FindingKind;
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
  /** Security findings on the call (definition, arguments and result), when any. */
  findings?: AuditFinding[];
  /** The subset of `findings` raised by scanning the tool's result, when any. */
  responseFindings?: AuditFinding[];
  /** Number of secret values inline DLP redacted from the tool's result, when any. */
  redactedSecrets?: number;
  /**
   * The decision the `balanced` profile would have recorded, on a call a `warn` action let through
   * (e.g. under `enforcementProfile: "observe"`). Absent when no such check fired.
   */
  wouldBlock?: AuditDecision;
  frameworks: FrameworkMapping;
  /** Tool arguments — omitted, redacted, or full per `audit.includeArgs`. */
  args?: Record<string, unknown>;
  /**
   * Upstream header names forwarded from the caller's request (gateway mode), e.g.
   * `["x-cso-identity"]`. Records that an identity was carried, never its value.
   */
  forwardedHeaders?: string[];
  /** Who acted for whom (keyless delegation checks), on calls to an upstream with `delegation`. */
  delegation?: AuditDelegationRecord;
  /** The runtime-authorization decision, when `authorization` is enabled. */
  authorization?: AuditAuthorizationRecord;
  /** Identifies this Bastion process run; every record of one run carries the same id. */
  runId?: string;
  /**
   * `2` when sinks record arguments differently (per-sink `includeArgs`): the chain hash then covers
   * the event WITHOUT `args`, plus `argsDigest`. Absent = v1, the hash covers `args` as recorded.
   */
  chainVersion?: 2;
  /** Chain v2 with an integrity key: HMAC-SHA256 of the full arguments, so every sink verifies the same chain. */
  argsDigest?: string;
  /** Previous event's hash (present only when tamper-evidence is enabled). */
  prevHash?: string;
  /** This event's hash over its content + `prevHash` (tamper-evidence). */
  hash?: string;
}

/**
 * First record of a run, written when `audit.checkpoint` is configured. Chained (seq 0) like an
 * event; `prevRunHead` links it to the last checkpoint of the previous run, so a deleted run breaks
 * the link.
 */
export interface AuditRunStart {
  recordType: "run-start";
  schemaVersion: number;
  seq: 0;
  ts: string;
  runId: string;
  bastionVersion: string;
  prevRunHead?: { runId: string; seq: number; hash: string };
  prevHash?: string;
  hash?: string;
}

/**
 * A signed statement of the chain head: "run `runId` had `count` call events up to `seq`, ending in
 * hash `head`". Not chained itself. Signed with Ed25519 over the canonical record without `sig`, so
 * anyone with the public key can verify it and only the key holder can make one.
 */
export interface AuditCheckpoint {
  recordType: "checkpoint";
  runId: string;
  seq: number;
  head: string;
  count: number;
  ts: string;
  /** First 16 hex chars of the SHA-256 of the signing public key (SPKI DER). */
  keyId: string;
  /** Base64url Ed25519 signature. */
  sig: string;
}

/** Anything written to a sink. Call events carry no `recordType`. */
export type AuditRecord = AuditEvent | AuditRunStart | AuditCheckpoint;

/**
 * A destination for audit events. Implementations must make `write` non-blocking
 * (buffer internally); durability/delivery is finalized in `flush`/`close`.
 */
export interface AuditSink {
  /** Human-readable sink name, for logs. */
  readonly name: string;
  /** Record an event (or a run-start / checkpoint record). MUST NOT block the caller. */
  write(event: AuditRecord): void;
  /** Flush any buffered events to their destination. */
  flush(): Promise<void>;
  /** Flush and release resources. */
  close(): Promise<void>;
  /** Delivery health, surfaced in `bastion__status` and used by `audit.onSinkFailure`. */
  health?(): SinkHealth;
  /** Per-sink argument recording, overriding `audit.includeArgs` (set by `createSinks`). */
  includeArgs?: "none" | "redacted" | "full";
}

/** Delivery health of one audit sink. */
export interface SinkHealth {
  name: string;
  /** `false` while the sink cannot deliver (stream error, or the last delivery attempt failed). */
  healthy: boolean;
  /** Events delivered (HTTP sinks) or written (file sink). */
  delivered: number;
  /** Events lost: queue overflow, a failed file stream, or undelivered at close. */
  dropped: number;
  /** Events waiting for delivery (HTTP sinks). */
  queued: number;
  /** Failed delivery attempts so far (HTTP sinks). */
  failedAttempts: number;
  lastError?: string;
}
