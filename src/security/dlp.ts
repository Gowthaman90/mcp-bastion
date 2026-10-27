/**
 * Inline data-loss-prevention (DLP) redaction of secret *values* in tool results.
 *
 * Response scanning (see `poisoning.ts`) *detects* a credential leaking back through a tool result;
 * this goes one step further and *removes* it — replacing the secret value with `[REDACTED]` so the
 * agent (and any downstream log) never sees it. It targets well-known credential shapes (cloud keys,
 * provider tokens, JWTs, bearer credentials, passwords in URLs, private-key blocks, and `NAME=secret`
 * assignments), which keeps false redactions low: ordinary prose, identifiers, booleans and short
 * numbers are left untouched. Measured on `test/redaction-corpus.test.ts`.
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
  /\bgithub_pat_[A-Za-z0-9_]{22,}/g, // GitHub fine-grained personal access tokens
  /\bsk-[A-Za-z0-9_-]{20,}/g, // OpenAI/Anthropic-style secret keys (sk-proj-, sk-ant-, sk-svcacct-, ...)
  /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g, // Stripe secret and restricted keys
  /\bAIza[0-9A-Za-z_-]{35}\b/g, // Google API keys
  /\bnpm_[A-Za-z0-9]{36}\b/g, // npm access tokens
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+/g, // Slack webhook URLs
  /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, // JWTs (header.payload.signature)
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, // PEM private keys
];

/** Patterns where only one group is the secret: `[prefix, secret, suffix]` around it is kept. */
const SECRET_PARTS: RegExp[] = [
  /\b(Bearer\s+)([A-Za-z0-9._~+/-]{16,}=*)()/g, // HTTP bearer credentials
  /\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)([^\s@/]+)(@)/gi, // password in a URL (scheme://user:PASSWORD@host)
];

/**
 * `NAME=secret` / `NAME: secret` where the name contains a credential word (anywhere, including at
 * the start) — redact the value only.
 */
const ENV_ASSIGNMENT =
  /\b([A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Za-z0-9_]*)(\s*[=:]\s*)(\S+)/gi;

/** Values that are never secrets: booleans, null-ish words and short plain numbers (`max_tokens: 1500`). */
const NOT_A_SECRET = /^(?:true|false|null|none|undefined|\d{1,7})[,;]?$/i;

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
  for (const re of SECRET_PARTS) {
    out = out.replace(re, (_m, pre: string, _secret: string, post: string) => {
      redactions++;
      return `${pre}${REDACTED}${post}`;
    });
  }
  out = out.replace(ENV_ASSIGNMENT, (m, name: string, sep: string, value: string) => {
    if (value === REDACTED || value.startsWith(REDACTED) || NOT_A_SECRET.test(value)) return m;
    redactions++;
    return `${name}${sep}${REDACTED}`;
  });

  return { text: out, redactions };
}
