/**
 * Types for the security layer: the interceptor pipeline and its findings.
 *
 * @packageDocumentation
 */
import type { CallToolResult, InputRequiredResult } from "@modelcontextprotocol/server";

/** What a tool call yields: a complete result, or an MRTR `input_required` continuation. */
export type ToolCallOutcome = CallToolResult | InputRequiredResult;

/** Severity of a security finding. */
export type Severity = "low" | "medium" | "high";

/** A single suspicious signal detected in a tool definition. */
export interface SecurityFinding {
  /** Identifier of the rule that fired (e.g. `instruction-override`). */
  rule: string;
  /** How serious the signal is. */
  severity: Severity;
  /** A short excerpt of the offending text, for human review. */
  excerpt: string;
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
  securityDecision?:
    | "blocked_rug_pull"
    | "blocked_poisoning"
    | "blocked_response"
    | "blocked_schema"
    | "blocked_identity"
    | "blocked_dataflow"
    | "blocked_input_required"
    | "blocked_request_state";
}

/** Continuation that invokes the next interceptor (or the upstream call). */
export type NextFn = () => Promise<ToolCallOutcome>;

/**
 * A composable middleware around a tool call. It may observe, annotate, short-circuit
 * (return a result without calling `next`), or pass through by returning `next()`.
 */
export type Interceptor = (ctx: ToolCallContext, next: NextFn) => Promise<ToolCallOutcome>;
