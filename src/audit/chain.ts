/**
 * Optional tamper-evidence via hash-chaining. Each event's hash covers its own
 * content plus the previous event's hash, so any retroactive edit or deletion
 * breaks the chain and is detectable.
 *
 * @packageDocumentation
 */
import { createHash } from "node:crypto";

import type { AuditEvent } from "./types.js";

/**
 * Deterministically serialize a value with object keys sorted. Keys whose value
 * is `undefined` are skipped, so an in-memory event and the same event after a
 * JSON round-trip (which drops `undefined` fields) hash identically.
 */
function canonicalize(value: unknown): string {
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
export function chainHash(prevHash: string, event: Omit<AuditEvent, "hash">): string {
  return createHash("sha256")
    .update(prevHash)
    .update("\n")
    .update(canonicalize(event))
    .digest("hex");
}

/**
 * Verify a chain of events. Returns the index of the first broken link, or `-1`
 * if the chain is intact. Useful for offline audit-log verification and tests.
 *
 * @param events Events in sequence order.
 */
export function verifyChain(events: readonly AuditEvent[]): number {
  let prev = "";
  for (let i = 0; i < events.length; i++) {
    const { hash, ...rest } = events[i];
    const expected = chainHash(prev, rest);
    if (hash !== expected) return i;
    prev = hash;
  }
  return -1;
}
