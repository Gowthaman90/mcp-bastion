/**
 * Types for the security layer: the interceptor pipeline and its findings.
 *
 * @packageDocumentation
 */
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

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

  // --- Annotations populated by interceptors for downstream observers (e.g. audit) ---

  /** Fingerprint of the tool definition at call time. */
  definitionHash?: string;
  /** Poisoning findings on the tool's current definition. */
  findings?: SecurityFinding[];
  /** Set by a security interceptor when it blocks the call. */
  securityDecision?: "blocked_rug_pull" | "blocked_poisoning";
}

/** Continuation that invokes the next interceptor (or the upstream call). */
export type NextFn = () => Promise<CallToolResult>;

/**
 * A composable middleware around a tool call. It may observe, annotate, short-circuit
 * (return a result without calling `next`), or pass through by returning `next()`.
 */
export type Interceptor = (ctx: ToolCallContext, next: NextFn) => Promise<CallToolResult>;
