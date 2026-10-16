/**
 * Request-scoped context for gateway-mode header forwarding.
 *
 * When Bastion serves a downstream HTTP request, the incoming headers that some upstream is
 * configured to forward are held in an {@link AsyncLocalStorage} for exactly the lifetime of that
 * request. Every upstream HTTP request issued on its behalf (connect, `tools/list`, `tools/call`,
 * `ping`) reads them at send time. Because the store follows the async call chain, two concurrent
 * downstream requests never see each other's values, even when they share one upstream connection.
 *
 * @packageDocumentation
 */
import { AsyncLocalStorage } from "node:async_hooks";

import type { DelegationVerdict } from "./delegation-gate.js";

/** What one downstream request carries for forwarding. */
export interface RequestContext {
  /** Incoming header name (lower-case) → value. Only headers some upstream forwards are kept. */
  readonly headers: ReadonlyMap<string, string>;
  /**
   * The request's delegation verdict, computed once on first need and reused by every check in the
   * same request (`tools/call`, `tools/list`, the fetch backstop).
   */
  delegation?: DelegationVerdict;
  /** The verdict while it is being computed (signature mode verifies asynchronously). */
  delegationPending?: Promise<DelegationVerdict>;
}

const storage = new AsyncLocalStorage<RequestContext>();

/**
 * Run `fn` with `headers` bound as the current downstream request's headers.
 *
 * @param headers Incoming header name → value. Names are lower-cased; empty values are dropped.
 */
export function runWithRequestHeaders<T>(headers: Record<string, string>, fn: () => T): T {
  const map = new Map<string, string>();
  for (const [name, value] of Object.entries(headers)) {
    if (value !== "") map.set(name.toLowerCase(), value);
  }
  return storage.run({ headers: map }, fn);
}

/** The current downstream request's context, or `undefined` outside any request. */
export function currentRequestContext(): RequestContext | undefined {
  return storage.getStore();
}

/**
 * Run `fn` outside any request context, so background work (scheduled reconnects, change
 * notifications) never carries the identity of whichever request happened to start it.
 */
export function runOutsideRequest<T>(fn: () => T): T {
  return storage.exit(fn);
}
