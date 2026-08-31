/**
 * Cache-policy enforcement for cacheable list results (protocol revision 2026-07-28).
 *
 * The 2026-07-28 revision lets a server attach caching hints to `resultType: "complete"` results of
 * `server/discover`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list` and
 * `resources/read`: `ttlMs` (a freshness hint in milliseconds) and `cacheScope` (`"public"` or
 * `"private"`). Three properties of that design need a policy layer above the protocol:
 *
 *  1. **No upper bound on `ttlMs`.** The spec requires only `ttlMs >= 0`. An arbitrarily long
 *     freshness window is therefore spec-legal, and a poisoned tool list can be pinned in caches for
 *     as long as the server asks. Clamping is a policy decision only an intermediary can make.
 *  2. **`"public"` crosses authorization contexts.** The spec's own security note: a public-scoped
 *     result "may be shared between callers even if the Result is coming from an authenticated
 *     endpoint", and implementors "MUST NOT rely on `cacheScope` alone to prevent unauthorized
 *     access". A public scope on an authenticated, authorization-varying list is a leak.
 *  3. **A stale cache suppresses rug-pull detection.** A `notifications/tools/list_changed`
 *     invalidates a still-fresh cached response. Serving the cached list past that signal hides the
 *     definition change that Bastion's own hash pinning exists to catch — the cache becomes a bypass
 *     for a defence, not merely a staleness problem.
 *
 * {@link checkCachePolicy} reports; {@link clampCacheHints} enforces, returning hardened hints that
 * are never weaker than what the server asked for. Both are pure, so they unit-test in isolation.
 *
 * Every rule fires only on an unambiguous violation. In particular the `"public"` rule requires the
 * caller to state that the request was authenticated, so unauthenticated traffic — where a public
 * scope is entirely correct — is never flagged.
 *
 * @packageDocumentation
 */
import type { SecurityFinding } from "./types.js";

/** Default ceiling on a server-asserted cache lifetime: one hour. */
export const DEFAULT_MAX_TTL_MS = 3_600_000;

/** Cache scopes defined by the specification. */
export type CacheScope = "public" | "private";

/** The caching hints a cacheable result may carry. */
export interface CacheHints {
  ttlMs?: number;
  cacheScope?: CacheScope | string;
}

/** What Bastion knows about the request that produced the result. */
export interface CachePolicyContext {
  /** Ceiling applied to `ttlMs`. Defaults to {@link DEFAULT_MAX_TTL_MS}. */
  maxTtlMs?: number;
  /** True when the request carried authorization. Required before a `"public"` scope can be judged. */
  authenticated?: boolean;
  /**
   * True when the result's contents depend on the caller's granted scopes. The spec permits a server
   * to vary a list by the authorization presented, which is exactly when `"public"` is wrong.
   */
  variesByAuthorization?: boolean;
  /** True when a `notifications/*_list_changed` has arrived and not yet been acted on. */
  invalidationPending?: boolean;
  /** `resultType` of the result, when known. Interim results carry no caching hints. */
  resultType?: string;
  /** True when the result came from an MRTR retry (one carrying `inputResponses` or `requestState`). */
  fromMrtrRetry?: boolean;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Pull `ttlMs` / `cacheScope` off a result object, ignoring anything of the wrong type. */
export function readCacheHints(result: unknown): CacheHints {
  if (!isRecord(result)) return {};
  const hints: CacheHints = {};
  if (typeof result.ttlMs === "number" && Number.isFinite(result.ttlMs)) hints.ttlMs = result.ttlMs;
  if (typeof result.cacheScope === "string") hints.cacheScope = result.cacheScope;
  return hints;
}

/**
 * Evaluate a result's caching hints against policy.
 *
 * @param result - The result object, or its hints directly.
 * @param ctx - What is known about the originating request.
 * @returns One finding per violation; an empty array when the hints are sound.
 */
export function checkCachePolicy(result: unknown, ctx: CachePolicyContext = {}): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const hints = readCacheHints(result);
  const maxTtlMs = ctx.maxTtlMs ?? DEFAULT_MAX_TTL_MS;

  // --- hints on a result that must not be cached at all ---
  const uncacheable = ctx.resultType === "input_required" || ctx.fromMrtrRetry === true;
  if (uncacheable && (hints.ttlMs !== undefined || hints.cacheScope !== undefined)) {
    findings.push({
      rule: "uncacheable-result-hints",
      severity: "high",
      excerpt:
        ctx.resultType === "input_required"
          ? "caching hints on an input_required result, which is not cacheable"
          : "caching hints on an MRTR retry result, which MUST NOT be cached",
    });
  }

  // --- ttlMs outside what the spec allows, or beyond what policy accepts ---
  if (hints.ttlMs !== undefined) {
    if (hints.ttlMs < 0) {
      findings.push({
        rule: "invalid-cache-ttl",
        severity: "medium",
        excerpt: `negative ttlMs ${hints.ttlMs}; servers MUST provide a value >= 0`,
      });
    } else if (hints.ttlMs > maxTtlMs) {
      findings.push({
        rule: "excessive-cache-ttl",
        severity: "medium",
        excerpt: `ttlMs ${hints.ttlMs} exceeds the ${maxTtlMs} ceiling; a poisoned list would stay pinned`,
      });
    }
  }

  // --- a public scope that will cross authorization contexts ---
  if (hints.cacheScope === "public" && ctx.authenticated === true) {
    findings.push({
      rule: "public-cache-scope",
      severity: ctx.variesByAuthorization === true ? "high" : "medium",
      excerpt:
        ctx.variesByAuthorization === true
          ? "cacheScope public on an authenticated result whose contents vary by authorization"
          : "cacheScope public on a result from an authenticated endpoint; it may be shared across callers",
    });
  }

  if (
    hints.cacheScope !== undefined &&
    hints.cacheScope !== "public" &&
    hints.cacheScope !== "private"
  ) {
    findings.push({
      rule: "invalid-cache-scope",
      severity: "medium",
      excerpt: `unrecognized cacheScope ${String(hints.cacheScope)}; expected public or private`,
    });
  }

  // --- serving past an invalidation signal, which is how a cache hides a rug pull ---
  if (ctx.invalidationPending === true) {
    findings.push({
      rule: "stale-cache-after-invalidation",
      severity: "high",
      excerpt:
        "list_changed invalidation outstanding; re-fetch and re-hash definitions before serving cached entries",
    });
  }

  return findings;
}

/** The outcome of hardening a result's caching hints. */
export interface ClampedCacheHints {
  ttlMs: number;
  cacheScope: CacheScope;
  /** True when policy altered what the server asked for. */
  changed: boolean;
}

/**
 * Harden a result's caching hints. The result is never more permissive than the server's request:
 * `ttlMs` is clamped into `[0, maxTtlMs]`, a pending invalidation forces `0`, an uncacheable result
 * forces `0`, and `"public"` is downgraded to `"private"` whenever the request was authenticated.
 *
 * @param result - The result object, or its hints directly.
 * @param ctx - What is known about the originating request.
 */
export function clampCacheHints(result: unknown, ctx: CachePolicyContext = {}): ClampedCacheHints {
  const hints = readCacheHints(result);
  const maxTtlMs = ctx.maxTtlMs ?? DEFAULT_MAX_TTL_MS;

  // Absent or negative ttlMs both mean "immediately stale" per the spec.
  const requestedTtl = hints.ttlMs === undefined || hints.ttlMs < 0 ? 0 : hints.ttlMs;
  const uncacheable =
    ctx.resultType === "input_required" ||
    ctx.fromMrtrRetry === true ||
    ctx.invalidationPending === true;
  const ttlMs = uncacheable ? 0 : Math.min(requestedTtl, maxTtlMs);

  const requestedScope: CacheScope = hints.cacheScope === "public" ? "public" : "private";
  const cacheScope: CacheScope =
    requestedScope === "public" && ctx.authenticated === true ? "private" : requestedScope;

  const changed = ttlMs !== hints.ttlMs || cacheScope !== hints.cacheScope;
  return { ttlMs, cacheScope, changed };
}
