/**
 * Heuristic detection of OS command-injection payloads in tool-call *argument values*.
 *
 * A tool that shells out (an "exec"-style tool) can be turned into arbitrary code execution when an
 * argument smuggles shell metacharacters — command substitution (`$(…)`, backticks), chaining
 * (`; rm …`, `| curl …`), or a read of a classic exfiltration target (`/etc/passwd`). This scans the
 * string leaves of a call's arguments for those payloads.
 *
 * The rules are deliberately **payload-shaped, not metacharacter-shaped**: a bare `;` or `|` does not
 * fire — a separator must be followed by an actual command verb, a `$(` must open a command, and a
 * backtick span must contain one. This keeps benign arguments (a filename, a sentence with a
 * semicolon, a markdown `` `snippet` ``) from tripping the check. Like the other heuristics it can
 * still produce false positives, so blocking is opt-in via `security.onSchemaViolation`.
 *
 * @packageDocumentation
 */
import type { SecurityFinding, Severity } from "./types.js";

interface Rule {
  rule: string;
  severity: Severity;
  pattern: RegExp;
}

/** Shell command verbs that make a separator/substitution look like real command injection. */
const CMD =
  "rm|curl|wget|nc|ncat|bash|sh|zsh|cat|chmod|chown|kill|dd|mkfs|scp|ssh|python|python3|perl|ruby|eval|export|env|nslookup|dig|base64|xxd|telnet";

/**
 * Payload-shaped rules. Each requires evidence of an actual command, not just a metacharacter,
 * so ordinary text and filenames do not match.
 */
const RULES: Rule[] = [
  // $(command …) — command substitution opening with a command-like token.
  { rule: "command-injection", severity: "high", pattern: /\$\(\s*[A-Za-z_./-]/ },
  // `… command …` — a backtick span that contains a shell command verb.
  {
    rule: "command-injection",
    severity: "high",
    pattern: new RegExp("`[^`]*\\b(" + CMD + ")\\b[^`]*`", "i"),
  },
  // separator (; | & newline) immediately followed by a shell command verb — the verb must be
  // followed by whitespace/quote/operator/end (not `=`, which would match URL query params).
  {
    rule: "command-injection",
    severity: "high",
    pattern: new RegExp("[;|&\\n]\\s*(" + CMD + ")(?=[\\s'\"|&;`]|$)", "i"),
  },
  // read of a classic credential-exfiltration target.
  { rule: "command-injection", severity: "high", pattern: /\/etc\/(passwd|shadow)\b/i },
];

function excerpt(text: string, match: RegExpMatchArray): string {
  const start = Math.max(0, (match.index ?? 0) - 12);
  return text
    .slice(start, start + 80)
    .replace(/\s+/g, " ")
    .trim();
}

/** Depth-first collection of every string leaf in an arbitrary arguments value. */
function stringLeaves(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) stringLeaves(v, out);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) stringLeaves(v, out);
  return out;
}

/**
 * Scan a tool call's argument values for command-injection payloads.
 *
 * @param args The parsed tool-call arguments.
 * @returns Findings (empty if clean). At most one finding per rule that matches.
 */
export function checkCommandInjection(args: unknown): SecurityFinding[] {
  const leaves = stringLeaves(args);
  if (leaves.length === 0) return [];

  const findings: SecurityFinding[] = [];
  const seen = new Set<string>();
  for (const { rule, severity, pattern } of RULES) {
    for (const text of leaves) {
      const match = text.match(pattern);
      if (match) {
        const ex = excerpt(text, match);
        const key = `${rule}:${ex}`;
        if (!seen.has(key)) {
          seen.add(key);
          findings.push({ rule, severity, excerpt: ex });
        }
        break; // one finding per rule is enough to flag the call
      }
    }
  }
  return findings;
}
