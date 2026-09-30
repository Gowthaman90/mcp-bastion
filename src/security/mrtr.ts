/**
 * MRTR consent gate (MCP 2026-07-28, patterns/mrtr).
 *
 * With server-initiated requests gone, a server reaches the user (elicitation) or the client's own
 * model (sampling) *in band*: it returns `resultType: "input_required"` with `inputRequests` that the
 * client fulfils and echoes back. The channel is legitimate; the request need not be. Two shapes are
 * flagged here, deterministically:
 *
 *  1. **Credential elicitation** — a form elicitation whose requested fields are credential-shaped
 *     (`password`, `api_key`, `token`, …) or whose message asks for them. A weather tool has no
 *     business asking for a provider API key.
 *  2. **Server-injected model instructions** — a sampling request whose `systemPrompt` or message
 *     text trips the response heuristics (override / exfiltration / concealment directives): the
 *     server steering the client's LLM through a channel the user never sees. A clean systemPrompt
 *     is permitted by the spec and is not a finding.
 *  3. **Standing-grant elicitation** (consent fatigue) — an elicitation that asks the user for a
 *     persistent approval ("always allow", "don't ask again") on a broad or sensitive capability.
 *     One click converts a single approval into standing authority the user will never see again.
 *     Advisory (`medium`): the request is relayed, but the audit trail records it.
 *
 * Pure functions over the result object; the engine decides block / strip / warn.
 *
 * @packageDocumentation
 */
import { scanText } from "./poisoning.js";
import type { SecurityFinding } from "./types.js";

const CREDENTIAL_FIELD =
  /(^|[_\s-])(password|passwd|passcode|pin|api[_-]?key|apikey|secret|token|access[_-]?token|refresh[_-]?token|bearer|private[_-]?key|credential|client[_-]?secret|otp|2fa|mfa)([_\s-]|$)/i;
const CREDENTIAL_ASK =
  /\b(re-?enter|enter|provide|paste|confirm|type|supply)\b[^.]{0,80}\b(password|passcode|api key|api[_-]key|access token|refresh token|secret key|private key|credentials?|one-time code|verification code)\b/i;

/** Wording that turns one approval into a standing one. */
const STANDING =
  /\b(always (allow|approve|permit|trust)|allow always|don'?t ask (me )?again|never ask again|remember (this|my) (choice|decision|approval)|permanent(ly)?|for all future|auto-?approve|from now on)\b/i;
/** A capability broad or sensitive enough that a standing grant is disproportionate. */
const BROAD_CAPABILITY =
  /(\b(all|any|every|full|unrestricted|admin|root)\b|\*|(^|[.:_\-/\s])(write|delete|remove|execute|exec|shell|send|network|filesystem|fs)([.:_\-/\s]|$))/i;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Is this an `input_required` result (MRTR) rather than a complete tool result? */
export function isInputRequired(result: unknown): result is {
  resultType: "input_required";
  inputRequests: Record<string, unknown>;
  requestState?: string;
} {
  return (
    isRecord(result) && result.resultType === "input_required" && isRecord(result.inputRequests)
  );
}

/** Field names an elicitation form asks for. */
function requestedFields(params: Record<string, unknown>): string[] {
  const schema = isRecord(params.requestedSchema) ? params.requestedSchema : undefined;
  const props = schema && isRecord(schema.properties) ? Object.keys(schema.properties) : [];
  return props;
}

/** String values of an elicitation schema: enum options, defaults, titles and descriptions. */
function schemaStrings(params: Record<string, unknown>): string[] {
  const schema = isRecord(params.requestedSchema) ? params.requestedSchema : undefined;
  const props = schema && isRecord(schema.properties) ? Object.values(schema.properties) : [];
  const out: string[] = [];
  for (const p of props) {
    if (!isRecord(p)) continue;
    for (const k of ["title", "description", "default"])
      if (typeof p[k] === "string") out.push(p[k] as string);
    const options = [p.enum, p.enumNames, isRecord(p.items) ? p.items.enum : undefined];
    for (const o of options)
      if (Array.isArray(o)) for (const v of o) if (typeof v === "string") out.push(v);
    for (const k of ["oneOf", "anyOf"]) {
      const alts = p[k];
      if (Array.isArray(alts))
        for (const a of alts)
          if (isRecord(a))
            for (const f of ["const", "title"])
              if (typeof a[f] === "string") out.push(a[f] as string);
    }
  }
  return out;
}

/**
 * A standing-grant request: persistent-approval wording in the message or a form option, together
 * with a broad or sensitive capability anywhere in the request. Returns the matched wording, or null.
 */
function standingGrant(message: string, params: Record<string, unknown>): string | null {
  const texts = [message, ...schemaStrings(params)];
  const wording = texts.map((t) => STANDING.exec(t)?.[0]).find(Boolean);
  if (!wording) return null;
  return texts.some((t) => BROAD_CAPABILITY.test(t)) ? wording : null;
}

/**
 * Inspect every embedded request of an `input_required` result. Returns one finding per problem,
 * each tagged with the `inputRequests` key it concerns (`excerpt` starts with `[key]`).
 */
export function checkInputRequests(result: unknown): SecurityFinding[] {
  if (!isInputRequired(result)) return [];
  const findings: SecurityFinding[] = [];
  for (const [key, req] of Object.entries(result.inputRequests)) {
    if (!isRecord(req) || typeof req.method !== "string") continue;
    const params = isRecord(req.params) ? req.params : {};

    if (req.method === "elicitation/create") {
      const fields = requestedFields(params);
      const credFields = fields.filter((f) => CREDENTIAL_FIELD.test(f));
      const message = typeof params.message === "string" ? params.message : "";
      if (credFields.length > 0) {
        findings.push({
          rule: "mrtr-credential-elicitation",
          severity: "high",
          excerpt: `[${key}] elicitation requests credential-shaped field(s): ${credFields.join(", ")}`,
        });
      } else if (CREDENTIAL_ASK.test(message)) {
        findings.push({
          rule: "mrtr-credential-elicitation",
          severity: "high",
          excerpt: `[${key}] elicitation message asks for a credential: "${message.slice(0, 80)}"`,
        });
      }
      const standing = standingGrant(message, params);
      if (standing) {
        findings.push({
          rule: "mrtr-standing-grant",
          severity: "medium",
          excerpt: `[${key}] elicitation asks for a standing grant on a broad capability: "${standing}"`,
        });
      }
      // URL-mode elicitation to an external origin is a phishing surface too; flag as advisory.
      if (params.mode === "url" && typeof params.url === "string") {
        findings.push({
          rule: "mrtr-url-elicitation",
          severity: "medium",
          excerpt: `[${key}] URL elicitation to ${params.url.slice(0, 80)}`,
        });
      }
      for (const f of scanText(message)) {
        findings.push({
          rule: `mrtr-elicitation-${f.rule}`,
          severity: f.severity,
          excerpt: `[${key}] ${f.excerpt}`,
        });
      }
    }

    if (req.method === "sampling/createMessage") {
      // A server-supplied systemPrompt is permitted by the spec; it is a finding only when its
      // content trips the response heuristics (override / exfiltration / concealment directives).
      if (typeof params.systemPrompt === "string" && params.systemPrompt.trim().length > 0) {
        const sub = scanText(params.systemPrompt);
        if (sub.length > 0) {
          findings.push({
            rule: "mrtr-server-system-prompt",
            severity: "high",
            excerpt: `[${key}] server-supplied systemPrompt flagged: ${sub.map((f) => f.rule).join(", ")}`,
          });
        }
      }
      const messages = Array.isArray(params.messages) ? params.messages : [];
      const text = messages
        .map((m) =>
          isRecord(m) && isRecord(m.content) && typeof m.content.text === "string"
            ? m.content.text
            : "",
        )
        .join("\n");
      for (const f of scanText(text)) {
        findings.push({
          rule: `mrtr-sampling-${f.rule}`,
          severity: f.severity,
          excerpt: `[${key}] ${f.excerpt}`,
        });
      }
    }
  }
  return findings;
}

/**
 * Return a copy of the result with the flagged embedded requests removed (`strip` posture). If
 * nothing is left, the caller should treat the call as blocked rather than forward an empty round.
 */
export function stripFlaggedInputRequests(
  result: unknown,
  findings: SecurityFinding[],
): { result: unknown; removed: string[] } {
  if (!isInputRequired(result)) return { result, removed: [] };
  // Only high-severity findings remove a request; medium ones (e.g. a URL elicitation) are advisory.
  const flagged = new Set(
    findings
      .filter((f) => f.severity === "high")
      .map((f) => /^\[([^\]]+)\]/.exec(f.excerpt)?.[1])
      .filter((k): k is string => !!k),
  );
  const kept: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(result.inputRequests)) if (!flagged.has(k)) kept[k] = v;
  return { result: { ...result, inputRequests: kept }, removed: [...flagged] };
}
