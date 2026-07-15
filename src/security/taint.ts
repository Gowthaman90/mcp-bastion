/**
 * Cross-server data-flow (taint) tracking.
 *
 * A proxy that aggregates several upstream servers is the only vantage point that sees the *whole*
 * call sequence across trust boundaries. This tracks sensitive tokens (credential-shaped strings)
 * that a tool on server A returns, and flags the **same token** reappearing in an argument sent to a
 * *different* server B — the exfiltration leg of a cross-server / tool-transfer attack that no
 * single-server scanner can see.
 *
 * Propagation is by **exact token match** (a credential-shaped run of ≥16 chars), which keeps false
 * positives near zero: an unrelated benign forward, or a forward of non-sensitive data, does not
 * carry a tracked token. It is a heuristic for the *staging + egress* signal, not a proof.
 *
 * @packageDocumentation
 */
import type { SecurityFinding } from "./types.js";

/** A single observed tool call in a session, in order. */
export interface SequencedCall {
  /** Owning upstream server (the trust boundary that matters here). */
  server?: string;
  /** Tool name (for the excerpt). */
  name?: string;
  /** Call arguments. */
  arguments?: unknown;
  /** The tool's result, if already observed. */
  result?: { content?: Array<{ type?: string; text?: string }> };
}

/** AWS access-key shape — a high-confidence credential token. */
const AWS_KEY = /\bAKIA[0-9A-Z]{16}\b/g;
/** A credential-shaped run: ≥16 chars from a key alphabet, not an ordinary word. */
const TOKEN = /[A-Za-z0-9+/=_-]{16,}/g;

/** Whether a candidate looks like a secret (mixed character classes), not an English word/path. */
function looksSecret(s: string): boolean {
  const hasUpper = /[A-Z]/.test(s);
  const hasLower = /[a-z]/.test(s);
  const hasDigit = /[0-9]/.test(s);
  return [hasUpper, hasLower, hasDigit].filter(Boolean).length >= 2;
}

/**
 * Extract credential-shaped tokens from free text. Returns the distinct high-signal tokens; ordinary
 * words, paths, and short identifiers are excluded so they can't seed a false taint.
 */
export function extractSensitiveTokens(text: string): string[] {
  if (!text) return [];
  const out = new Set<string>();
  for (const m of text.match(AWS_KEY) ?? []) out.add(m);
  for (const m of text.match(TOKEN) ?? []) if (looksSecret(m)) out.add(m);
  return [...out];
}

/** Depth-first collection of string leaves in an arbitrary value. */
function stringLeaves(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) stringLeaves(v, out);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) stringLeaves(v, out);
  return out;
}

function callTexts(call: SequencedCall): { args: string[]; result: string[] } {
  const args = stringLeaves(call.arguments);
  const result = (call.result?.content ?? [])
    .filter((c) => c && c.type === "text" && typeof c.text === "string")
    .map((c) => c.text as string);
  return { args, result };
}

/**
 * Stateful tracker for a single proxy session. Feed each call's texts as they are observed; it
 * remembers which server produced which sensitive token and flags cross-server reuse.
 */
export class TaintTracker {
  /** token → source server that first produced it. */
  private readonly tainted = new Map<string, string>();

  /** Check outgoing argument texts for tokens tainted by a *different* server. */
  check(server: string | undefined, argTexts: readonly string[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const haystack = argTexts.join("\n");
    if (!haystack) return findings;
    for (const [token, source] of this.tainted) {
      if (source !== server && haystack.includes(token)) {
        findings.push({
          rule: "cross-server-exfil",
          severity: "high",
          excerpt: `data read from server "${source}" is being sent to server "${server ?? "?"}" (token ${token.slice(0, 8)}…)`,
        });
      }
    }
    return findings;
  }

  /** Record sensitive tokens produced by a call (its result and arguments), sourced to its server. */
  record(server: string | undefined, texts: readonly string[]): void {
    for (const text of texts)
      for (const token of extractSensitiveTokens(text))
        if (!this.tainted.has(token)) this.tainted.set(token, server ?? "?");
  }
}

/**
 * Scan an ordered call sequence for cross-server exfiltration. Each call's arguments are checked
 * against tokens tainted by *prior* calls on other servers, then the call's own result/arguments seed
 * new taint. Pure and stateless across invocations.
 */
export function scanCallSequence(calls: readonly SequencedCall[]): SecurityFinding[] {
  if (!Array.isArray(calls) || calls.length < 2) return [];
  const tracker = new TaintTracker();
  const findings: SecurityFinding[] = [];
  for (const call of calls) {
    const { args, result } = callTexts(call);
    findings.push(...tracker.check(call.server, args));
    tracker.record(call.server, [...result, ...args]);
  }
  return findings;
}
