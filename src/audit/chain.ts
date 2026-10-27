/**
 * Optional integrity hash-chaining. Each event's hash covers its own content plus
 * the previous event's hash, so a naive edit within the log is detectable.
 *
 * With an integrity `key` the chain is an **HMAC-SHA256** chain: a party who can
 * rewrite the log but does not hold the key cannot recompute a valid chain (real
 * forgery resistance). **Unkeyed** it is a plain SHA-256 chain that only detects
 * accidental/naive corruption — a motivated rewriter can recompute it. In neither
 * mode does verification by itself detect truncation of the most-recent events: signed checkpoints
 * held by a second sink do that (see `checkpoint.ts` and `mcp-bastion audit verify`).
 *
 * Chain v2 (`chainVersion: 2`, used when sinks record arguments differently): the hash covers the
 * event WITHOUT its `args` view, plus `argsDigest`, so every sink verifies the same chain.
 *
 * @packageDocumentation
 */
import { createHash, createHmac } from "node:crypto";

import type { AuditEvent, AuditRecord } from "./types.js";

/**
 * Deterministically serialize a value with object keys sorted. Keys whose value
 * is `undefined` are skipped, so an in-memory event and the same event after a
 * JSON round-trip (which drops `undefined` fields) hash identically.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((k) => record[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalize(record[k])}`)
    .join(",")}}`;
}

/**
 * Compute an event's chain hash from its content and the previous hash.
 * The event's own `hash` field is excluded from the digest.
 *
 * @param prevHash Hash of the previous event (empty string for the first event).
 * @param event    The event, without its `hash` field set.
 */
export function chainHash(prevHash: string, event: object, key?: string): string {
  const h = key ? createHmac("sha256", key) : createHash("sha256");
  return h
    .update(prevHash)
    .update("\n")
    .update(canonicalize(chainBody(event)))
    .digest("hex");
}

/** What the chain hash covers: the record without `hash`, and without `args` under chain v2. */
export function chainBody(record: object): object {
  const { hash: _hash, ...rest } = record as Record<string, unknown>;
  if (rest.chainVersion === 2) delete rest.args;
  return rest;
}

/** Keyed digest of a call's full arguments for chain v2 (HMAC-SHA256, hex). */
export function argsDigest(args: unknown, key: string): string {
  return createHmac("sha256", key)
    .update(canonicalize(args ?? {}))
    .digest("hex");
}

/**
 * Verify a chain of events. Returns the index of the first broken link, or `-1`
 * if the chain is intact. Useful for offline audit-log verification and tests.
 *
 * @param events Events in sequence order.
 */
export function verifyChain(events: readonly (AuditEvent | AuditRecord)[], key?: string): number {
  let prev = "";
  for (let i = 0; i < events.length; i++) {
    const record = events[i] as AuditRecord;
    if ("recordType" in record && record.recordType === "checkpoint") continue; // not chained
    const hash = (record as { hash?: string }).hash;
    const expected = chainHash(prev, record, key);
    if (hash !== expected) return i;
    prev = hash;
  }
  return -1;
}
