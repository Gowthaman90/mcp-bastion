/**
 * Redaction of tool arguments before they are written to an audit sink. Audit
 * records may leave the process (to files, SIEMs, webhooks), so secrets and PII
 * in arguments must be handled deliberately.
 *
 * @packageDocumentation
 */

/** How argument values are recorded. */
export type IncludeArgs = "none" | "redacted" | "full";

const REDACTED = "[REDACTED]";

/**
 * Produce the argument object to record, according to policy.
 *
 * - `none`   → `undefined` (arguments are not recorded at all).
 * - `redacted` → sensitive keys (matched case-insensitively, at any depth) are
 *   replaced with `[REDACTED]`.
 * - `full`   → arguments recorded verbatim (use with care).
 *
 * @param args      The raw tool arguments.
 * @param mode      The recording policy.
 * @param redactKeys Key names considered sensitive (lower-cased for matching).
 */
export function prepareArgs(
  args: Record<string, unknown>,
  mode: IncludeArgs,
  redactKeys: readonly string[],
): Record<string, unknown> | undefined {
  if (mode === "none") return undefined;
  if (mode === "full") return args;

  const sensitive = new Set(redactKeys.map((k) => k.toLowerCase()));
  const redact = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        out[k] = sensitive.has(k.toLowerCase()) ? REDACTED : redact(v);
      }
      return out;
    }
    return value;
  };

  return redact(args) as Record<string, unknown>;
}
