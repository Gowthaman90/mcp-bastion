/**
 * Keyless delegation checks: the claims policy a gateway can apply to agent-to-sub-agent delegate
 * tokens without holding any secret.
 *
 * A caller (say, a master agent acting for a signed-in user) sends one short-lived JWT per sub-agent
 * through Bastion, each in its own header. Bastion sees the whole request, so it can check what no
 * single sub-agent can: that every token in the request names the same user. Per token it checks
 * the audience (the token was issued for this upstream, not a sibling and not Bastion itself), the
 * validity window, and who is acting (RFC 8693 `act`).
 *
 * `structural` mode decodes the token strictly and checks its claims; it does **not** verify the
 * signature, so it authenticates nothing. The upstream remains the verifier.
 *
 * Everything here is pure and deterministic: {@link checkDelegation} takes the policy, the carried
 * headers and the clock, and returns findings. Findings name a rule, never a token or claim value.
 *
 * @packageDocumentation
 */
import { createHmac } from "node:crypto";

import type { Severity } from "./types.js";

/** Rule ids, all deterministic. */
export type DelegationRule =
  | "delegation-malformed"
  | "delegation-audience-mismatch"
  | "delegation-passthrough"
  | "delegation-subject-mixing"
  | "delegation-expired"
  | "delegation-not-yet-valid"
  | "delegation-lifetime-excess"
  | "delegation-actor-not-allowed"
  | "delegation-actor-required"
  | "delegation-chain-depth"
  | "delegation-chain-cycle";

/** Rules about prior actors: informational per RFC 8693 §4.1, so governed by `onDelegationChain`. */
export const DELEGATION_CHAIN_RULES: ReadonlySet<DelegationRule> = new Set([
  "delegation-chain-depth",
  "delegation-chain-cycle",
]);

/** One delegation finding. `detail` is fixed text plus policy values; never a token or claim value. */
export interface DelegationFinding {
  rule: DelegationRule;
  severity: Severity;
  detail: string;
}

/** Policy for one upstream, with the incoming header already resolved from `forwardHeaders`. */
export interface DelegationUpstreamPolicy {
  /** Incoming (downstream) header name that carries this upstream's delegate token. */
  incomingHeader: string;
  /** The audience this upstream's tokens must carry. */
  audience: string;
  /** Longest accepted `exp − iat`, in seconds. */
  maxLifetimeSeconds?: number;
  /** Tolerance on `exp` and `nbf`, in seconds. Default 0. */
  clockSkewSeconds?: number;
  /** Allowed current actors (`act.sub`, else `act.client_id`). Unset = any. */
  allowedActors?: readonly string[];
  /** Require an `act` claim. */
  requireActor?: boolean;
  /** Longest accepted actor chain (current + prior actors). Unset = no limit. */
  maxChainDepth?: number;
}

/** The request-wide policy {@link checkDelegation} applies. */
export interface DelegationPolicy {
  /** Upstream name → its policy. Only these upstreams' tokens are checked. */
  upstreams: Readonly<Record<string, DelegationUpstreamPolicy>>;
  /** Audiences that identify the gateway itself (a token for one of these is passthrough). */
  gatewayAudiences?: readonly string[];
  /** All tokens in one request must share one (`iss`, `sub`). Default `true`. */
  oneUserPerRequest?: boolean;
}

/** What Bastion learned from one decodable token, for the audit record. Internal: holds `sub`. */
export interface DelegationTokenInfo {
  issuer: string | null;
  subject: string | null;
  tokenId: string | null;
  /** `exp` as a NumericDate, when it is one. */
  expiresAt: number | null;
  /** Current actor first, then prior actors (outermost to innermost). */
  actors: string[];
}

/** The result of {@link checkDelegation}. */
export interface DelegationResult {
  /** Upstream name → findings on that upstream's own token (absent token = no entry). */
  perUpstream: Record<string, DelegationFinding[]>;
  /** Findings across the request's tokens (subject mixing). */
  request: DelegationFinding[];
  /** Upstream name → claims of its token, when the token decoded. Never logged as is. */
  tokens: Record<string, DelegationTokenInfo>;
}

/** Header lookups accept a plain record or the request context's map; names are lower-case. */
export type CarriedHeaders = Readonly<Record<string, string>> | ReadonlyMap<string, string>;

const HIGH: Severity = "high";
const MEDIUM: Severity = "medium";

/** Bound on actor-chain traversal; a longer chain is reported as too deep, never walked further. */
const MAX_CHAIN_WALK = 32;

function headerValue(headers: CarriedHeaders, name: string): string | undefined {
  const key = name.toLowerCase();
  if (headers instanceof Map) return headers.get(key);
  const record = headers as Readonly<Record<string, string>>;
  return Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;
}

// --------------------------------------------------------------------------------------------
// Strict JWS compact decoding
// --------------------------------------------------------------------------------------------

/** Decoded JWS compact serialization (signature not verified). */
export interface DecodedJws {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

const B64URL = /^[A-Za-z0-9_-]+$/;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

/**
 * Decode one base64url segment strictly: alphabet `[A-Za-z0-9_-]`, no padding, and canonical (it
 * re-encodes to exactly the same text, so unused trailing bits must be zero).
 */
function decodeSegment(segment: string): Uint8Array | undefined {
  if (!B64URL.test(segment) || segment.length % 4 === 1) return undefined;
  const bytes = Buffer.from(segment, "base64url");
  if (bytes.toString("base64url") !== segment) return undefined;
  return bytes;
}

/**
 * Whether a JSON text (already accepted by `JSON.parse`) repeats a member name inside any object,
 * comparing names after escape decoding (`"a"` and `"a"` are the same name). JSON.parse keeps
 * the last duplicate while other parsers keep the first, so a duplicate is a parser-differential
 * hazard and the token is refused.
 */
export function hasDuplicateKeys(json: string): boolean {
  type Frame = { object: boolean; keys: Set<string>; expectKey: boolean };
  const stack: Frame[] = [];
  for (let i = 0; i < json.length; i++) {
    const c = json[i];
    if (c === '"') {
      let j = i + 1;
      while (json[j] !== '"') j += json[j] === "\\" ? 2 : 1;
      const top = stack.at(-1);
      if (top?.object && top.expectKey) {
        const name = JSON.parse(json.slice(i, j + 1)) as string;
        if (top.keys.has(name)) return true;
        top.keys.add(name);
        top.expectKey = false;
      }
      i = j;
    } else if (c === "{") {
      stack.push({ object: true, keys: new Set(), expectKey: true });
    } else if (c === "[") {
      stack.push({ object: false, keys: new Set(), expectKey: false });
    } else if (c === "}" || c === "]") {
      stack.pop();
    } else if (c === ",") {
      const top = stack.at(-1);
      if (top?.object) top.expectKey = true;
    }
  }
  return false;
}

function parseJsonObject(bytes: Uint8Array): Record<string, unknown> | undefined {
  let text: string;
  try {
    text = UTF8.decode(bytes);
  } catch {
    return undefined;
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  if (hasDuplicateKeys(text)) return undefined;
  return value as Record<string, unknown>;
}

/**
 * Decode a JWS compact serialization strictly, without verifying the signature. An optional
 * `Bearer ` scheme (one space) is accepted, so the token may travel in an `Authorization` header.
 * Returns `undefined` for anything that is not exactly three canonical base64url segments whose
 * first two decode to JSON objects with unique member names, with a string `alg` header.
 */
export function decodeJwsCompact(value: string): DecodedJws | undefined {
  const token = /^bearer /i.test(value) ? value.slice(7) : value;
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  const [h, p, s] = parts;
  if (s !== "" && !decodeSegment(s)) return undefined;
  const hb = decodeSegment(h);
  const pb = decodeSegment(p);
  if (!hb || !pb) return undefined;
  const header = parseJsonObject(hb);
  const payload = parseJsonObject(pb);
  if (!header || !payload || typeof header.alg !== "string") return undefined;
  return { header, payload };
}

// --------------------------------------------------------------------------------------------
// Claim checks
// --------------------------------------------------------------------------------------------

function finding(rule: DelegationRule, detail: string): DelegationFinding {
  return { rule, severity: DELEGATION_CHAIN_RULES.has(rule) ? MEDIUM : HIGH, detail };
}

const isNumericDate = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

/**
 * Walk the RFC 8693 `act` chain: the outermost `act` is the current actor, nested ones are prior
 * actors. An actor is named by `sub`, else `client_id`. `undefined` = the chain is malformed.
 */
function actorChain(act: unknown): { actors: string[]; truncated: boolean } | undefined {
  const actors: string[] = [];
  let node = act;
  while (node !== undefined) {
    if (node === null || typeof node !== "object" || Array.isArray(node)) return undefined;
    const claims = node as Record<string, unknown>;
    const id = claims.sub ?? claims.client_id;
    if (typeof id !== "string" || id === "") return undefined;
    actors.push(id);
    if (actors.length > MAX_CHAIN_WALK) return { actors, truncated: true };
    node = claims.act;
  }
  return { actors, truncated: false };
}

/** Checks on one upstream's token; also returns its claims for the subject check and the audit record. */
function checkToken(
  value: string,
  policy: DelegationUpstreamPolicy,
  gatewayAudiences: readonly string[],
  now: number,
): { findings: DelegationFinding[]; info?: DelegationTokenInfo } {
  const jws = decodeJwsCompact(value);
  if (!jws) {
    return {
      findings: [finding("delegation-malformed", "not a strict JWS compact serialization")],
    };
  }
  const c = jws.payload;
  const malformed = (what: string) => ({
    findings: [finding("delegation-malformed", `invalid ${what} claim`)],
  });

  // Claim types first: a token with a wrongly typed registered claim is not a valid JWT.
  if (c.iss !== undefined && typeof c.iss !== "string") return malformed("iss");
  if (c.sub !== undefined && typeof c.sub !== "string") return malformed("sub");
  if (c.jti !== undefined && typeof c.jti !== "string") return malformed("jti");
  for (const claim of ["exp", "nbf", "iat"] as const) {
    if (c[claim] !== undefined && !isNumericDate(c[claim])) return malformed(claim);
  }
  let audiences: string[];
  if (c.aud === undefined) audiences = [];
  else if (typeof c.aud === "string") audiences = [c.aud];
  else if (Array.isArray(c.aud) && c.aud.every((a) => typeof a === "string")) {
    audiences = c.aud as string[];
  } else return malformed("aud");
  const chain = c.act === undefined ? { actors: [], truncated: false } : actorChain(c.act);
  if (!chain) return malformed("act");

  const findings: DelegationFinding[] = [];
  const info: DelegationTokenInfo = {
    issuer: (c.iss as string | undefined) ?? null,
    subject: (c.sub as string | undefined) ?? null,
    tokenId: (c.jti as string | undefined) ?? null,
    expiresAt: (c.exp as number | undefined) ?? null,
    actors: chain.actors,
  };

  // Audience: passthrough (for the gateway itself, or for nobody) first, else lateral misroute.
  if (audiences.length === 0) {
    findings.push(finding("delegation-passthrough", "token carries no audience"));
  } else if (audiences.some((a) => gatewayAudiences.includes(a))) {
    findings.push(finding("delegation-passthrough", "token was issued for the gateway itself"));
  } else if (!audiences.includes(policy.audience)) {
    findings.push(
      finding("delegation-audience-mismatch", `token audience is not "${policy.audience}"`),
    );
  }

  // Validity window.
  const skew = policy.clockSkewSeconds ?? 0;
  const exp = c.exp as number | undefined;
  const nbf = c.nbf as number | undefined;
  const iat = c.iat as number | undefined;
  if (exp === undefined) {
    findings.push(finding("delegation-lifetime-excess", "token has no expiry (exp)"));
  } else {
    if (now > exp + skew) findings.push(finding("delegation-expired", "token has expired"));
    const max = policy.maxLifetimeSeconds;
    // Without `iat`, the time left is a lower bound on the lifetime.
    const lifetime = iat !== undefined ? exp - iat : exp - now - skew;
    if (max !== undefined && lifetime > max) {
      findings.push(finding("delegation-lifetime-excess", `token lifetime exceeds ${max} seconds`));
    }
  }
  if (nbf !== undefined && nbf > now + skew) {
    findings.push(finding("delegation-not-yet-valid", "token is not valid yet (nbf)"));
  }

  // Actor: only the current actor drives policy (RFC 8693 §4.1).
  const current = chain.actors[0];
  if (current === undefined) {
    if (policy.requireActor) {
      findings.push(finding("delegation-actor-required", "token names no acting agent (act)"));
    }
  } else if (policy.allowedActors && !policy.allowedActors.includes(current)) {
    findings.push(finding("delegation-actor-not-allowed", "current actor is not allowed"));
  }

  // Prior actors: informational, so detected (and by default only warned on).
  if (
    policy.maxChainDepth !== undefined &&
    (chain.truncated || chain.actors.length > policy.maxChainDepth)
  ) {
    findings.push(
      finding("delegation-chain-depth", `actor chain is deeper than ${policy.maxChainDepth}`),
    );
  }
  if (new Set(chain.actors).size !== chain.actors.length) {
    findings.push(finding("delegation-chain-cycle", "an actor appears twice in the chain"));
  }

  return { findings, info };
}

/**
 * Check every delegate token a request carries against the policy.
 *
 * @param policy  Per-upstream policy plus request-wide settings.
 * @param headers The request's carried headers (incoming name, lower-case → value).
 * @param now     The clock, in seconds since the epoch (a JWT NumericDate).
 * @returns Findings per upstream (only for upstreams whose token is present), findings across the
 *          request (subject mixing over (`iss`, `sub`)), and the decoded claims for the audit record.
 */
export function checkDelegation(
  policy: DelegationPolicy,
  headers: CarriedHeaders,
  now: number,
): DelegationResult {
  const result: DelegationResult = { perUpstream: {}, request: [], tokens: {} };
  const gatewayAudiences = policy.gatewayAudiences ?? [];
  const subjects = new Set<string>();

  for (const [server, upstream] of Object.entries(policy.upstreams)) {
    const value = headerValue(headers, upstream.incomingHeader);
    if (value === undefined || value === "") continue;
    const { findings, info } = checkToken(value, upstream, gatewayAudiences, now);
    result.perUpstream[server] = findings;
    if (info) {
      result.tokens[server] = info;
      subjects.add(JSON.stringify([info.issuer, info.subject]));
    }
  }

  if ((policy.oneUserPerRequest ?? true) && subjects.size > 1) {
    result.request.push(
      finding("delegation-subject-mixing", "delegate tokens in this request name different users"),
    );
  }
  return result;
}

/**
 * Pseudonymous subject for the audit record: `"hmac:"` + the first 16 hex characters of
 * HMAC-SHA256(key, `iss|sub`). An operator holding the key can recompute it to find one user's
 * records; nobody else can reverse it.
 */
export function subjectPseudonym(
  key: string | Uint8Array,
  issuer: string,
  subject: string,
): string {
  return (
    "hmac:" + createHmac("sha256", key).update(`${issuer}|${subject}`).digest("hex").slice(0, 16)
  );
}
