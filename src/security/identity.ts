/**
 * Server-identity checks — the server-layer analogue of tool-definition pinning.
 *
 * Two defenses against a server impersonating a trusted one:
 *
 *   - **Verification** (`checkServerIdentity`) — a server that *claims* an identity (name/org) but
 *     presents no verified binding (a signed / well-known-URI proof) is flagged. Advisory by default,
 *     since most servers do not yet publish identity proofs.
 *   - **Trust-on-first-use pinning** (`hashServerIdentity`) — the impersonation-relevant identity
 *     (endpoint, claimed name, TLS fingerprint) is fingerprinted on first connect; if it changes on a
 *     later connect, that is a strong hijack/impersonation signal. Deliberately **excludes** the
 *     server's advertised version and protocol so a benign redeploy does not trip the check.
 *
 * @packageDocumentation
 */
import { createHash } from "node:crypto";

import type { SecurityFinding } from "./types.js";

/** A server's advertised identity, as observed at connect time. */
export interface ServerIdentity {
  /** Upstream endpoint URL (or transport locator). */
  endpoint?: string;
  /** The identity/org name the server claims (e.g. `acme/payments`). */
  name?: string;
  /** TLS certificate fingerprint, when the transport exposes one. */
  tlsFingerprint?: string;
  /** Advertised server version — excluded from the pin (benign redeploys change it). */
  serverVersion?: string;
  /** Advertised protocol version — excluded from the pin. */
  protocolVersion?: string;
  /** A binding that proves the claimed identity (signed / well-known-URI). */
  identityProof?: { wellKnown?: string; verified?: boolean } | null;
}

/**
 * Flag a claimed server identity that lacks a verified binding. Returns findings (empty when the
 * identity carries a verified proof, or when no identity is claimed).
 */
export function checkServerIdentity(id: ServerIdentity): SecurityFinding[] {
  if (!id || typeof id !== "object") return [];
  const verified = id.identityProof != null && id.identityProof.verified === true;
  if (id.name && !verified) {
    return [
      {
        rule: "unverified-server-identity",
        severity: "high",
        excerpt:
          `server claims identity "${id.name}"` +
          (id.endpoint ? ` at ${id.endpoint}` : "") +
          " without a verified binding (no signed / well-known proof)",
      },
    ];
  }
  return [];
}

/**
 * Stable fingerprint of the impersonation-relevant identity (endpoint, name, TLS fingerprint).
 * Version/protocol are intentionally excluded so a benign redeploy keeps the same fingerprint.
 */
export function hashServerIdentity(id: ServerIdentity): string {
  const subset = [id.endpoint ?? "", id.name ?? "", id.tlsFingerprint ?? ""];
  return createHash("sha256").update(JSON.stringify(subset)).digest("hex");
}
