/**
 * Least-privilege check on the scopes/permissions a tool requests.
 *
 * Flags **over-broad scopes**: destructive/administrative scopes (delete, admin, manage, wildcard)
 * are always suspicious, and mutating scopes (write, send, execute) are flagged when the tool
 * presents itself as read-only. This catches a tool that asks for far more authority than its stated
 * function needs — the "excessive agency / privilege escalation" pattern.
 *
 * @packageDocumentation
 */
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

import type { SecurityFinding } from "./types.js";

/** Scope tokens that are dangerous regardless of the tool's purpose. */
const ALWAYS_DANGEROUS =
  /(^|[.:_\-/])(delete|remove|drop|admin|superuser|manage|all|\*)$|(^|[.:_\-/])\*$/i;
/** Scope tokens that are dangerous only for a read-oriented tool. */
const MUTATING = /(^|[.:_\-/])(write|send|create|update|execute|exec)$/i;
/** A tool that presents itself as read-only. */
const READ_ONLY = /\b(read|get|list|view|fetch|search|lookup|query)\b/i;

/**
 * Check a tool's requested scopes against least-privilege. Returns findings (empty if proportionate).
 *
 * @param scopes Requested scope strings (e.g. `"calendar.write"`).
 * @param tool   Optional tool context; when it looks read-only, mutating scopes are also flagged.
 */
export function checkRequestedScopes(
  scopes: readonly unknown[] | undefined,
  tool?: Pick<Tool, "name" | "description">,
): SecurityFinding[] {
  if (!Array.isArray(scopes) || scopes.length === 0) return [];
  const readOnly = tool ? READ_ONLY.test(`${tool.name ?? ""} ${tool.description ?? ""}`) : false;

  const findings: SecurityFinding[] = [];
  for (const scope of scopes) {
    if (typeof scope !== "string") continue;
    if (ALWAYS_DANGEROUS.test(scope)) {
      findings.push({ rule: "excessive-scope", severity: "high", excerpt: scope });
    } else if (readOnly && MUTATING.test(scope)) {
      findings.push({ rule: "over-privileged-scope", severity: "high", excerpt: scope });
    }
  }
  return findings;
}
