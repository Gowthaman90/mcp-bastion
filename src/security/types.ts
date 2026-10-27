/**
 * Types for the security layer: the interceptor pipeline and its findings.
 *
 * @packageDocumentation
 */
import type { CallToolResult, InputRequiredResult } from "@modelcontextprotocol/server";

import type { AuditAuthorizationRecord, AuditDelegationRecord } from "../audit/types.js";

/** What a tool call yields: a complete result, or an MRTR `input_required` continuation. */
export type ToolCallOutcome = CallToolResult | InputRequiredResult;

/** Severity of a security finding. */
export type Severity = "low" | "medium" | "high";

/**
 * Whether a finding comes from a heuristic (pattern-based, can misfire on benign text) or a
 * deterministic check (an exact comparison against a pin, a schema, a policy or a token's claims).
 */
export type FindingKind = "heuristic" | "deterministic";

/** Deterministic rules by exact id; prefixes cover rule families. Everything else is heuristic. */
const DETERMINISTIC_RULES: ReadonlySet<string> = new Set([
  // Definition integrity (pinning) and server identity.
  "tool-definition-changed",
  "server-identity-changed",
  "unverified-server-identity",
  "config-drift",
  // Arguments against the declared schema.
  "undeclared-parameter",
  "type-violation",
  "enum-violation",
  // Cross-server data flow (exact values seen earlier in another server's result).
  "cross-server-exfil",
  // MRTR structure (custody rules are covered by the `requeststate-` prefix).
  "mrtr-url-elicitation",
  // Transport, headers, cache hints, scopes.
  "insecure-transport",
  "cross-origin-request",
  "unvalidated-header-routing",
  "invalid-cache-ttl",
  "invalid-cache-scope",
  "excessive-cache-ttl",
  "public-cache-scope",
  "uncacheable-result-hints",
  "stale-cache-after-invalidation",
  "excessive-scope",
  "over-privileged-scope",
]);
const DETERMINISTIC_PREFIXES = ["delegation-", "authorization-", "header-", "requeststate-"];

/**
 * The kind of a finding, by rule id: poisoning, response, command-injection, DLP and steering
 * heuristics are `heuristic`; pinning, identity, schema, data-flow, custody, delegation and
 * authorization checks are `deterministic`. Unknown rules are `heuristic` (never overclaim).
 */
export function findingKind(rule: string): FindingKind {
  if (DETERMINISTIC_RULES.has(rule)) return "deterministic";
  return DETERMINISTIC_PREFIXES.some((p) => rule.startsWith(p)) ? "deterministic" : "heuristic";
}

/** A single suspicious signal detected in a tool definition. */
export interface SecurityFinding {
  /** Identifier of the rule that fired (e.g. `instruction-override`). */
  rule: string;
  /** How serious the signal is. */
  severity: Severity;
  /** A short excerpt of the offending text, for human review. */
  excerpt: string;
  /** `heuristic` or `deterministic` (see {@link findingKind}); set on reported findings. */
  kind?: FindingKind;
}

/** Pin state of a tool relative to the first definition Bastion approved (trust-on-first-use). */
export type PinStatus = "pinned" | "changed";

/** A per-tool security snapshot surfaced by `bastion__security`. */
export interface ToolSecurityReport {
  server: string;
  tool: string;
  /** `pinned` = matches the approved definition; `changed` = a possible rug pull. */
  status: PinStatus;
  /** Poisoning findings on the current definition. */
  findings: SecurityFinding[];
  /** Other servers exposing a tool with the same original name (possible shadowing). */
  shadowedBy: string[];
}

/** The decision a security check records when it blocks a call. */
export type SecurityDecision =
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

/** Context passed through the interceptor pipeline for a single tool call. */
export interface ToolCallContext {
  /** Owning upstream server name. */
  server: string;
  /** The tool's original (un-namespaced) name. */
  toolName: string;
  /** The client-visible, namespaced name. */
  namespacedName: string;
  /** Parsed tool arguments. */
  args: Record<string, unknown>;
  /** Calling principal (bearer-token subject hash, or `stdio`). Binds sealed requestState. */
  principal: string;
  /** MRTR retry: the client's answers to a previous `input_required` round. */
  inputResponses?: Record<string, unknown>;
  /** MRTR retry: the upstream's own continuation state, already unsealed by Bastion. */
  requestState?: string;
  /** Findings on the embedded requests of an `input_required` result. */
  mrtrFindings?: SecurityFinding[];
  /** Upstream header names forwarded from the downstream request (gateway mode). Names only. */
  forwardedHeaders?: string[];
  /** Who acted for whom, when the upstream has `delegation` configured and a token was carried. */
  delegation?: AuditDelegationRecord;
  /** The runtime-authorization decision, when `authorization` is enabled. */
  authorization?: AuditAuthorizationRecord;

  // --- Annotations populated by interceptors for downstream observers (e.g. audit) ---

  /** Fingerprint of the tool definition at call time. */
  definitionHash?: string;
  /** Poisoning findings on the tool's current definition. */
  findings?: SecurityFinding[];
  /** Heuristic findings on the tool's *result* (response-handling stage). */
  responseFindings?: SecurityFinding[];
  /** Number of secret values redacted from the tool's result by inline DLP (0/undefined = none). */
  redactedSecrets?: number;
  /** Set by a security interceptor when it blocks the call. */
  securityDecision?: SecurityDecision;
  /**
   * Set when a check found a problem but its action was `warn`, and the `balanced` profile would
   * have blocked the call with this decision (shadow mode). The first such check wins.
   */
  wouldBlock?: SecurityDecision;
}

/** Continuation that invokes the next interceptor (or the upstream call). */
export type NextFn = () => Promise<ToolCallOutcome>;

/**
 * A composable middleware around a tool call. It may observe, annotate, short-circuit
 * (return a result without calling `next`), or pass through by returning `next()`.
 */
export type Interceptor = (ctx: ToolCallContext, next: NextFn) => Promise<ToolCallOutcome>;
