/**
 * Inline data-loss-prevention (DLP) redaction of secret *values* in tool results.
 *
 * Response scanning (see `poisoning.ts`) *detects* a credential leaking back through a tool result;
 * this goes one step further and *removes* it — replacing the secret value with `[REDACTED]` so the
 * agent (and any downstream log) never sees it. It targets well-known credential shapes (cloud keys,
 * provider tokens, private-key blocks, and `NAME=secret` environment assignments), which keeps false
 * redactions low: ordinary prose and identifiers are left untouched.
 *
 * This is a mitigation, not a proof — a novel or heavily-obfuscated secret encoding can still slip
 * through. It complements, and does not replace, blocking a clearly-malicious response.
 *
 * @packageDocumentation
 */

const REDACTED = "[REDACTED]";

/** Patterns whose entire match is a secret value to replace wholesale. */
const SECRET_PATTERNS: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
  /\bASIA[0-9A-Z]{16}\b/g, // AWS temporary access key id
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, // GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_)
  /\bsk-[A-Za-z0-9]{20,}\b/g, // OpenAI-style secret keys
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, // PEM private keys
];

/** `NAME=secret` / `NAME: secret` where the name looks credential-bearing — redact the value only. */
const ENV_ASSIGNMENT =
  /\b([A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Za-z0-9_]*)(\s*[=:]\s*)(\S+)/gi;

/**
 * Redact credential-shaped secret values in `text`. Returns the scrubbed text and how many secrets
 * were removed (0 means the text was left byte-identical).
 */
export function redactSecrets(text: string): { text: string; redactions: number } {
  if (!text) return { text, redactions: 0 };
  let redactions = 0;
  let out = text;

  for (const re of SECRET_PATTERNS) {
    out = out.replace(re, () => {
      redactions++;
      return REDACTED;
    });
  }
  out = out.replace(ENV_ASSIGNMENT, (_m, name: string, sep: string) => {
    redactions++;
    return `${name}${sep}${REDACTED}`;
  });

  return { text: out, redactions };
}
