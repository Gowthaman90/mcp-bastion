/**
 * requestState custody (MCP 2026-07-28, patterns/mrtr).
 *
 * In the stateless protocol a multi-round-trip tool call carries its continuation as an opaque
 * `requestState` string that the *client* echoes back. The spec makes servers responsible for its
 * integrity (MUST protect it with HMAC/AEAD where it influences authorization; SHOULD bind it to the
 * authenticated principal, a short TTL and the originating request). A gateway is the one hop that
 * can enforce this for every upstream at once: Bastion never forwards an upstream's raw state to the
 * model. It **seals** the upstream state inside its own HMAC-SHA256 envelope, bound to the calling
 * principal, the upstream server, the tool, and an expiry; on the retry it verifies the envelope,
 * checks the bindings, and only then unwraps the original upstream state for forwarding.
 *
 * Envelope format: `bst1.<base64url payload>.<base64url hmac>` where payload =
 * `{ up, srv, tool, sub, exp, nonce }`. Pure functions; no I/O.
 *
 * @packageDocumentation
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import type { SecurityFinding } from "./types.js";

/** What a sealed envelope binds. */
export interface RequestStateBinding {
  /** Upstream server name the continuation belongs to. */
  server: string;
  /** Tool the continuation belongs to. */
  tool: string;
  /** Calling principal (bearer-token subject, or `"stdio"` for a local client). */
  principal: string;
}

export interface SealOptions extends RequestStateBinding {
  key: Uint8Array | string;
  /** Lifetime of the envelope. Default 300 s. */
  ttlSeconds?: number;
  /** Injectable clock (ms since epoch) for tests. */
  now?: () => number;
}

export interface OpenOptions extends RequestStateBinding {
  key: Uint8Array | string;
  now?: () => number;
}

/** Result of opening an envelope: either the upstream state, or the findings that rejected it. */
export type OpenResult =
  | { ok: true; upstreamState: string; payload: SealedPayload }
  | { ok: false; findings: SecurityFinding[] };

export interface SealedPayload {
  up: string;
  srv: string;
  tool: string;
  sub: string;
  exp: number;
  nonce: string;
}

const PREFIX = "bst1";
export const DEFAULT_REQUEST_STATE_TTL_SECONDS = 300;

const b64u = (b: Buffer | string): string =>
  Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s: string): Buffer => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
const mac = (key: Uint8Array | string, data: string): Buffer =>
  createHmac("sha256", key).update(data).digest();

/** Generate a fresh 32-byte key (used when none is configured; per-process). */
export function generateRequestStateKey(): Buffer {
  return randomBytes(32);
}

/** Seal an upstream `requestState` into a Bastion envelope bound to principal/server/tool/expiry. */
export function sealRequestState(upstreamState: string, opts: SealOptions): string {
  const now = opts.now?.() ?? Date.now();
  const payload: SealedPayload = {
    up: upstreamState,
    srv: opts.server,
    tool: opts.tool,
    sub: opts.principal,
    exp: Math.floor(now / 1000) + (opts.ttlSeconds ?? DEFAULT_REQUEST_STATE_TTL_SECONDS),
    nonce: b64u(randomBytes(8)),
  };
  const body = b64u(JSON.stringify(payload));
  return `${PREFIX}.${body}.${b64u(mac(opts.key, `${PREFIX}.${body}`))}`;
}

/** Is this string one of Bastion's envelopes (as opposed to a raw upstream state)? */
export function isSealedRequestState(state: unknown): state is string {
  return typeof state === "string" && state.startsWith(`${PREFIX}.`) && state.split(".").length === 3;
}

/**
 * Verify and open an envelope. Every failure is a finding, never an exception, so callers can log
 * and block uniformly. Rules: integrity (HMAC), expiry, principal binding, server/tool binding.
 */
export function openRequestState(state: unknown, opts: OpenOptions): OpenResult {
  const reject = (rule: string, excerpt: string, severity: "high" | "medium" = "high"): OpenResult => ({
    ok: false,
    findings: [{ rule, severity, excerpt }],
  });
  if (typeof state !== "string" || state.length === 0) {
    return reject("requeststate-missing", "retry carried no requestState");
  }
  if (!isSealedRequestState(state)) {
    // A raw (non-Bastion) state on the retry means the client bypassed custody, or the state was
    // minted before Bastion sat in the path. Either way it is unverifiable here.
    return reject("requeststate-unsealed", "requestState is not a Bastion-sealed envelope; refusing to forward unverifiable state");
  }
  const [, body, sig] = state.split(".");
  const expected = mac(opts.key, `${PREFIX}.${body}`);
  const given = unb64u(sig);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    return reject("requeststate-forged", "requestState HMAC does not verify (tampered or wrong key)");
  }
  let payload: SealedPayload;
  try {
    payload = JSON.parse(unb64u(body).toString("utf8")) as SealedPayload;
  } catch {
    return reject("requeststate-forged", "requestState payload is not valid JSON");
  }
  const now = opts.now?.() ?? Date.now();
  if (typeof payload.exp !== "number" || payload.exp * 1000 < now) {
    return reject("requeststate-expired", "requestState envelope has expired (replay after TTL)");
  }
  if (payload.sub !== opts.principal) {
    return reject("requeststate-cross-principal", `requestState was issued to a different principal (replay by "${opts.principal}")`);
  }
  if (payload.srv !== opts.server || payload.tool !== opts.tool) {
    return reject("requeststate-cross-request", `requestState was issued for ${payload.srv}/${payload.tool}, presented to ${opts.server}/${opts.tool}`);
  }
  return { ok: true, upstreamState: payload.up, payload };
}
