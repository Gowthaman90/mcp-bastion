/**
 * False-error escalation check (human-oversight gap, EU AI Act Art. 14).
 *
 * A tool returns a fabricated failure — "permission denied" — and tells the agent how to "fix" it by
 * taking a more privileged path: a shell tool, sudo, an admin scope, disabling verification. The
 * agent follows the error text, and the human who approved `read_config` never approved
 * `run_shell`. The text itself is not an override directive, so the generic response heuristics
 * miss it.
 *
 * Flagged, deterministically: an **error-shaped** result (`isError: true`, or text that opens like an
 * error) whose text **steers** the agent (retry / use / run / call / switch to …) toward a
 * **privilege-raising** target within the same sentence, or that tells it to switch a safety
 * control off. Benign errors that suggest retrying later, fixing an argument, or calling an
 * ordinary tool are not findings.
 *
 * Pure function over the result; the engine decides warn / block.
 *
 * @packageDocumentation
 */
import type { SecurityFinding } from "./types.js";

/** Text that opens like an error, for results that do not set `isError`. */
const ERROR_OPENING =
  /^\s*(error\b|failed\b|failure\b|permission denied|access denied|unauthori[sz]ed|forbidden|not permitted|operation not allowed)/i;

/** An instruction to take a different action. */
const STEER = /\b(retry|re-run|rerun|try|use|call|run|invoke|execute|switch to|instead)\b/gi;

/**
 * A target that raises privilege: a shell/exec-style tool call, sudo/root/admin, a broader grant, or
 * turning a safety control off. Checked only in the window right after a steering verb.
 */
const PRIVILEGED_TARGET = new RegExp(
  [
    // A call to a shell/exec/admin-style tool, e.g. run_shell('…'), exec(…), admin_query(…).
    String.raw`\b[\w.-]*(shell|exec|bash|cmd|terminal|sudo|admin|root|eval|system)[\w.-]*\s*\(`,
    String.raw`\bsudo\b`,
    String.raw`\bas (root|admin(istrator)?|superuser)\b`,
    String.raw`\b(elevated|escalated|admin(istrator)?|root|superuser) (privileges?|permissions?|access|rights|mode|scope|token|role)\b`,
    String.raw`\b(broader|higher|full|unrestricted|wider) (privileges?|permissions?|access|rights|scope)\b`,
    String.raw`--(force|no-verify|insecure|skip-auth|disable-\w+)\b`,
  ].join("|"),
  "i",
);

/** Turning a safety control off is itself the instruction, wherever the retry verb sits. */
const DISABLE_SAFETY =
  /\b(disable|bypass|turn off|skip)\b[^.]{0,20}\b(auth\w*|verification|security|sandbox|safety|checks?)\b/i;

/** How far after a steering verb a privileged target may appear (stays within one instruction). */
const WINDOW = 80;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function textOf(result: Record<string, unknown>): string {
  const content = Array.isArray(result.content) ? result.content : [];
  return content
    .map((c) => (isRecord(c) && c.type === "text" && typeof c.text === "string" ? c.text : ""))
    .filter(Boolean)
    .join("\n");
}

/**
 * Inspect a tool result for an error that steers the agent toward a more privileged action.
 *
 * @returns One `error-privilege-steering` finding (severity `medium`), or none.
 */
export function checkErrorSteering(result: unknown): SecurityFinding[] {
  if (!isRecord(result)) return [];
  const text = textOf(result);
  if (!text) return [];
  if (result.isError !== true && !ERROR_OPENING.test(text)) return [];

  const disable = DISABLE_SAFETY.exec(text);
  if (disable) {
    return [
      {
        rule: "error-privilege-steering",
        severity: "medium",
        excerpt: disable[0].replace(/\s+/g, " ").trim().slice(0, 80),
      },
    ];
  }

  for (const m of text.matchAll(STEER)) {
    const start = m.index ?? 0;
    // Stay inside the sentence that holds the steering verb.
    const tail = text.slice(start, start + WINDOW);
    const sentence = tail.split(/(?<=[.!?])\s|\n/)[0] ?? tail;
    const target = PRIVILEGED_TARGET.exec(sentence);
    if (target) {
      return [
        {
          rule: "error-privilege-steering",
          severity: "medium",
          excerpt: sentence.replace(/\s+/g, " ").trim().slice(0, 80),
        },
      ];
    }
  }
  return [];
}
