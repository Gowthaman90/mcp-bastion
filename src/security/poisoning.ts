/**
 * Heuristic detection of "tool poisoning" — malicious or manipulative instructions
 * hidden in a tool's name or description that try to steer the model into unsafe
 * behavior (data exfiltration, instruction override, secret access, etc.).
 *
 * These are HEURISTICS. They are intentionally conservative and can produce false
 * positives, which is why the default policy only warns; blocking is opt-in via
 * `security.onPoisoning`.
 *
 * @packageDocumentation
 */
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

import type { SecurityFinding, Severity } from "./types.js";

interface Rule {
  rule: string;
  severity: Severity;
  pattern: RegExp;
}

/**
 * Pattern rules over free text. Kept deliberately simple and linear-time; avoid
 * catastrophic-backtracking constructs since input can be adversarial.
 */
const RULES: Rule[] = [
  {
    rule: "instruction-override",
    severity: "high",
    pattern:
      /\b(ignore|disregard|forget|override)\b[^.]{0,40}\b(previous|prior|above|earlier|system)\b/i,
  },
  {
    rule: "secret-access",
    severity: "high",
    pattern:
      /(\.ssh\b|id_rsa|\.env\b|\bcredentials?\b|\bapi[_-]?keys?\b|\bpasswords?\b|\bsecret[_-]?keys?\b)/i,
  },
  {
    rule: "data-exfiltration",
    severity: "high",
    pattern:
      /\b(send|post|upload|exfiltrat\w*|leak|forward|transmit)\b[^.]{0,40}(https?:\/\/|\bendpoint\b|\bserver\b|\bwebhook\b)/i,
  },
  {
    rule: "covert-instruction",
    severity: "medium",
    pattern:
      /\b(do not|don't|never)\b[^.]{0,30}\b(tell|inform|mention|reveal|show)\b[^.]{0,20}\buser\b/i,
  },
  {
    rule: "embedded-directive",
    severity: "medium",
    pattern: /<\/?(system|important|secret|admin)>|(\bSYSTEM\s*:)|(\[system\])/i,
  },
];

/**
 * Unicode code points that should not appear in a legitimate tool description:
 * zero-width characters (200B–200F), bidirectional overrides (202A–202E),
 * word/function joiners (2060–2064), BOM (FEFF), and C0 control characters
 * (excluding tab / LF / CR). Built from an all-ASCII source string on purpose.
 */
/* eslint-disable no-control-regex -- detecting control characters is the point */
const HIDDEN_CHARS = new RegExp(
  "[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\uFEFF\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F]",
);
/* eslint-enable no-control-regex */

function excerpt(text: string, match: RegExpMatchArray | null): string {
  if (!match || match.index === undefined) return text.slice(0, 80);
  const start = Math.max(0, match.index - 20);
  return text
    .slice(start, start + 80)
    .replace(/\s+/g, " ")
    .trim();
}

/** Scan a single block of text for poisoning signals. */
export function scanText(text: string): SecurityFinding[] {
  if (!text) return [];
  const findings: SecurityFinding[] = [];

  for (const { rule, severity, pattern } of RULES) {
    const match = text.match(pattern);
    if (match) findings.push({ rule, severity, excerpt: excerpt(text, match) });
  }

  if (HIDDEN_CHARS.test(text)) {
    findings.push({
      rule: "hidden-characters",
      severity: "high",
      excerpt: "contains zero-width, control, or bidirectional-override characters",
    });
  }

  return findings;
}

/**
 * Scan a tool's name and description for poisoning signals.
 *
 * @param tool The tool definition to inspect.
 * @returns All findings across the tool's name and description.
 */
export function scanTool(tool: Tool): SecurityFinding[] {
  return [...scanText(tool.name ?? ""), ...scanText(tool.description ?? "")];
}

/** Whether any finding is at least the given severity. */
export function hasSeverityAtLeast(findings: readonly SecurityFinding[], min: Severity): boolean {
  const order: Record<Severity, number> = { low: 0, medium: 1, high: 2 };
  return findings.some((f) => order[f.severity] >= order[min]);
}
