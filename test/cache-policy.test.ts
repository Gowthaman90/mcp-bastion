import { describe, expect, it } from "vitest";

import {
  DEFAULT_MAX_TTL_MS,
  checkCachePolicy,
  clampCacheHints,
  readCacheHints,
} from "../src/security/index.js";

/** A conforming, modestly-cached public tool list — the benign baseline. */
function soundList() {
  return {
    resultType: "complete",
    tools: [{ name: "get_weather", description: "Returns the current weather for a given city." }],
    ttlMs: 300_000,
    cacheScope: "public",
  };
}

describe("cache policy (2026-07-28)", () => {
  describe("no false positives", () => {
    it("passes a sound unauthenticated public list", () => {
      expect(checkCachePolicy(soundList(), { resultType: "complete" })).toHaveLength(0);
    });

    it("passes a private list from an authenticated request", () => {
      const findings = checkCachePolicy(
        { ...soundList(), cacheScope: "private" },
        { authenticated: true, variesByAuthorization: true, resultType: "complete" },
      );
      expect(findings).toHaveLength(0);
    });

    it("passes a result carrying no caching hints at all", () => {
      expect(checkCachePolicy({ resultType: "complete", tools: [] })).toHaveLength(0);
    });

    it("ignores a non-object result", () => {
      expect(checkCachePolicy(null)).toHaveLength(0);
      expect(checkCachePolicy("nonsense")).toHaveLength(0);
    });

    it("accepts a zero TTL, which the spec defines as immediately stale", () => {
      expect(checkCachePolicy({ ...soundList(), ttlMs: 0 })).toHaveLength(0);
    });
  });

  describe("ttlMs", () => {
    it("flags a lifetime beyond the policy ceiling", () => {
      const findings = checkCachePolicy({ ...soundList(), ttlMs: 2_592_000_000 });
      expect(findings.map((f) => f.rule)).toContain("excessive-cache-ttl");
    });

    it("respects a caller-supplied ceiling", () => {
      const hints = { ...soundList(), ttlMs: 120_000 };
      expect(checkCachePolicy(hints, { maxTtlMs: 60_000 }).map((f) => f.rule)).toContain(
        "excessive-cache-ttl",
      );
      expect(checkCachePolicy(hints, { maxTtlMs: 600_000 })).toHaveLength(0);
    });

    it("flags a negative lifetime, which servers must never send", () => {
      const findings = checkCachePolicy({ ...soundList(), ttlMs: -1 });
      expect(findings.map((f) => f.rule)).toContain("invalid-cache-ttl");
    });
  });

  describe("cacheScope", () => {
    it("flags a public scope on an authenticated, authorization-varying list as high", () => {
      const findings = checkCachePolicy(soundList(), {
        authenticated: true,
        variesByAuthorization: true,
      });
      const f = findings.find((x) => x.rule === "public-cache-scope");
      expect(f).toBeDefined();
      expect(f?.severity).toBe("high");
    });

    it("flags a public scope on an authenticated result as medium when it does not vary", () => {
      const findings = checkCachePolicy(soundList(), { authenticated: true });
      expect(findings.find((x) => x.rule === "public-cache-scope")?.severity).toBe("medium");
    });

    it("does not judge a public scope when the request was not authenticated", () => {
      expect(checkCachePolicy(soundList(), { authenticated: false })).toHaveLength(0);
      expect(checkCachePolicy(soundList(), {})).toHaveLength(0);
    });

    it("flags an unrecognized scope value", () => {
      const findings = checkCachePolicy({ ...soundList(), cacheScope: "shared" });
      expect(findings.map((f) => f.rule)).toContain("invalid-cache-scope");
    });
  });

  describe("uncacheable results", () => {
    it("flags caching hints on an input_required result", () => {
      const findings = checkCachePolicy(
        { resultType: "input_required", ttlMs: 300_000 },
        { resultType: "input_required" },
      );
      expect(findings.map((f) => f.rule)).toContain("uncacheable-result-hints");
    });

    it("flags caching hints on an MRTR retry result", () => {
      const findings = checkCachePolicy(soundList(), { fromMrtrRetry: true });
      expect(findings.map((f) => f.rule)).toContain("uncacheable-result-hints");
    });
  });

  describe("invalidation suppresses rug-pull detection", () => {
    it("flags serving a cached list while a list_changed invalidation is outstanding", () => {
      const findings = checkCachePolicy(soundList(), { invalidationPending: true });
      const f = findings.find((x) => x.rule === "stale-cache-after-invalidation");
      expect(f).toBeDefined();
      expect(f?.severity).toBe("high");
    });

    it("does not fire when no invalidation is outstanding", () => {
      expect(
        checkCachePolicy(soundList(), { invalidationPending: false }).map((f) => f.rule),
      ).not.toContain("stale-cache-after-invalidation");
    });
  });
});

describe("clampCacheHints", () => {
  it("clamps an excessive lifetime to the ceiling", () => {
    const out = clampCacheHints({ ...soundList(), ttlMs: 2_592_000_000 });
    expect(out.ttlMs).toBe(DEFAULT_MAX_TTL_MS);
    expect(out.changed).toBe(true);
  });

  it("leaves a sound lifetime and scope untouched", () => {
    const out = clampCacheHints(soundList());
    expect(out).toEqual({ ttlMs: 300_000, cacheScope: "public", changed: false });
  });

  it("downgrades public to private on an authenticated request", () => {
    const out = clampCacheHints(soundList(), { authenticated: true });
    expect(out.cacheScope).toBe("private");
    expect(out.changed).toBe(true);
  });

  it("forces a zero lifetime when an invalidation is outstanding", () => {
    expect(clampCacheHints(soundList(), { invalidationPending: true }).ttlMs).toBe(0);
  });

  it("forces a zero lifetime for results that must not be cached", () => {
    expect(clampCacheHints(soundList(), { resultType: "input_required" }).ttlMs).toBe(0);
    expect(clampCacheHints(soundList(), { fromMrtrRetry: true }).ttlMs).toBe(0);
  });

  it("treats absent and negative lifetimes as immediately stale", () => {
    expect(clampCacheHints({ resultType: "complete" }).ttlMs).toBe(0);
    expect(clampCacheHints({ ...soundList(), ttlMs: -5 }).ttlMs).toBe(0);
  });

  it("never returns a scope more permissive than the server asked for", () => {
    const out = clampCacheHints(
      { ...soundList(), cacheScope: "private" },
      { authenticated: false },
    );
    expect(out.cacheScope).toBe("private");
  });
});

describe("readCacheHints", () => {
  it("reads well-typed hints and ignores wrongly-typed ones", () => {
    expect(readCacheHints(soundList())).toEqual({ ttlMs: 300_000, cacheScope: "public" });
    expect(readCacheHints({ ttlMs: "300000", cacheScope: 5 })).toEqual({});
    expect(readCacheHints({ ttlMs: Number.NaN })).toEqual({});
  });
});
