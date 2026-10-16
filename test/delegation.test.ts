/**
 * Keyless delegation checks, structural mode: one positive and one matched negative case per rule,
 * strict JWS decoding, configuration, and the pre-registered dev fixtures of mcp-defense-bench.
 */
import { describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { BastionConfigSchema, SecurityConfigSchema } from "../src/config/index.js";
import type { JSONWebKeySet } from "jose";

import {
  checkDelegation,
  checkDelegationAsync,
  decodeJwsCompact,
  delegationKeySet,
  DELEGATION_CHAIN_RULES,
  hasDuplicateKeys,
  subjectPseudonym,
  type DelegationPolicy,
  type DelegationUpstreamPolicy,
} from "../src/security/index.js";

const NOW = 1_791_936_000; // 2026-10-14T00:00:00Z
const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
const SIG = Buffer.from("signature-not-checked").toString("base64url");

/** An HS256-shaped compact JWS; the signature is never checked in structural mode. */
function jwt(payload: Record<string, unknown>, header: Record<string, unknown> = {}): string {
  return `${b64({ typ: "JWT", alg: "HS256", ...header })}.${b64(payload)}.${SIG}`;
}

/** Claims of a compliant token for `aud`, overridable per test. */
function claims(aud: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: "https://idp.example",
    sub: "user:priya",
    aud,
    iat: NOW - 30,
    exp: NOW + 90,
    jti: "t-1",
    act: { sub: "master-quote-agent" },
    ...extra,
  };
}

const PFQA = "https://pfqa.example/mcp";
const PSQA = "https://psqa.example/mcp";
const GATEWAY = "https://bastion.example/mcp";

function policy(over: Partial<DelegationUpstreamPolicy> = {}, top: Partial<DelegationPolicy> = {}) {
  const base = {
    maxLifetimeSeconds: 300,
    clockSkewSeconds: 30,
    allowedActors: ["master-quote-agent"],
    maxChainDepth: 2,
  };
  return {
    upstreams: {
      pfqa: { incomingHeader: "x-delegate-pfqa", audience: PFQA, ...base, ...over },
      psqa: { incomingHeader: "x-delegate-psqa", audience: PSQA, ...base, ...over },
    },
    gatewayAudiences: [GATEWAY],
    ...top,
  } satisfies DelegationPolicy;
}

/** Rule ids found on pfqa's token (plus request-wide ones) for one pfqa token. */
function rulesFor(token: string, over: Partial<DelegationUpstreamPolicy> = {}): string[] {
  const r = checkDelegation(policy(over), { "x-delegate-pfqa": token }, NOW);
  return [...(r.perUpstream.pfqa ?? []), ...r.request].map((f) => f.rule);
}

describe("checkDelegation: one positive and one matched negative per rule", () => {
  it("compliant token: no findings", () => {
    expect(rulesFor(jwt(claims(PFQA)))).toEqual([]);
  });

  it("delegation-malformed", () => {
    const good = jwt(claims(PFQA));
    expect(rulesFor(good)).not.toContain("delegation-malformed");
    const [h, p, s] = good.split(".");
    const bad = [
      "not-a-jwt",
      `${h}.${p}`,
      `${h}.${p}.${s}.extra`,
      `${h}=.${p}.${s}`, // padding
      `${h}.${p.replace(/-/g, "+").replace(/_/g, "/")}x.${s}`, // standard alphabet
      `${h}.${b64([1, 2])}.${s}`, // payload not an object
      `${h}.${Buffer.from("{not json").toString("base64url")}.${s}`,
      `${b64({ typ: "JWT" })}.${p}.${s}`, // no alg
      `${h}.${Buffer.from('{"sub":"a","sub":"b"}').toString("base64url")}.${s}`, // duplicate
      `${h}.${Buffer.from([0xff, 0xfe, 0x7b]).toString("base64url")}.${s}`, // not UTF-8
      jwt(claims(PFQA, { exp: "tomorrow" })),
      jwt(claims(PFQA, { aud: [PFQA, 7] })),
      jwt(claims(PFQA, { act: "master-quote-agent" })),
      jwt(claims(PFQA, { act: { sub: "a", act: { client_id: 3 } } })),
    ];
    for (const token of bad) expect(rulesFor(token), token).toEqual(["delegation-malformed"]);
  });

  it("delegation-audience-mismatch (lateral: a sibling's token)", () => {
    expect(rulesFor(jwt(claims(PSQA)))).toEqual(["delegation-audience-mismatch"]);
    expect(rulesFor(jwt(claims(PFQA)))).toEqual([]);
    expect(rulesFor(jwt(claims([PSQA, PFQA] as unknown as string)))).toEqual([]);
    expect(rulesFor(jwt(claims(PFQA.toUpperCase())))).toEqual(["delegation-audience-mismatch"]);
  });

  it("delegation-passthrough (no audience, or the gateway's own)", () => {
    const { aud: _drop, ...noAud } = claims(PFQA);
    expect(rulesFor(jwt(noAud))).toEqual(["delegation-passthrough"]);
    expect(rulesFor(jwt(claims([] as unknown as string)))).toEqual(["delegation-passthrough"]);
    expect(rulesFor(jwt(claims(GATEWAY)))).toEqual(["delegation-passthrough"]);
    expect(rulesFor(jwt(claims([PFQA, GATEWAY] as unknown as string)))).toEqual([
      "delegation-passthrough",
    ]);
    expect(rulesFor(jwt(claims(PFQA)))).toEqual([]);
  });

  it("delegation-subject-mixing (across the request's tokens)", () => {
    const run = (b: Record<string, unknown>, top: Partial<DelegationPolicy> = {}) =>
      checkDelegation(
        policy({}, top),
        { "x-delegate-pfqa": jwt(claims(PFQA)), "x-delegate-psqa": jwt(claims(PSQA, b)) },
        NOW,
      );
    const mixed = run({ sub: "user:raj" });
    expect(mixed.request.map((f) => f.rule)).toEqual(["delegation-subject-mixing"]);
    expect(mixed.perUpstream.pfqa).toEqual([]); // each token is fine on its own
    expect(run({ iss: "https://partner-idp.example" }).request).toHaveLength(1); // same sub, other iss
    expect(run({}).request).toEqual([]);
    expect(run({ sub: "user:raj" }, { oneUserPerRequest: false }).request).toEqual([]);
  });

  it("delegation-expired (with clock skew)", () => {
    expect(rulesFor(jwt(claims(PFQA, { iat: NOW - 200, exp: NOW - 31 })))).toEqual([
      "delegation-expired",
    ]);
    expect(rulesFor(jwt(claims(PFQA, { iat: NOW - 200, exp: NOW - 30 })))).toEqual([]);
  });

  it("delegation-not-yet-valid (with clock skew)", () => {
    expect(rulesFor(jwt(claims(PFQA, { nbf: NOW + 31 })))).toEqual(["delegation-not-yet-valid"]);
    expect(rulesFor(jwt(claims(PFQA, { nbf: NOW + 30 })))).toEqual([]);
  });

  it("delegation-lifetime-excess (exp − iat over the limit, or no exp)", () => {
    expect(rulesFor(jwt(claims(PFQA, { iat: NOW - 10, exp: NOW + 291 })))).toEqual([
      "delegation-lifetime-excess",
    ]);
    expect(rulesFor(jwt(claims(PFQA, { iat: NOW - 10, exp: NOW + 290 })))).toEqual([]);
    const { exp: _drop, ...noExp } = claims(PFQA);
    expect(rulesFor(jwt(noExp))).toEqual(["delegation-lifetime-excess"]);
    // Without iat, the time left bounds the lifetime from below.
    const { iat: _i, ...noIat } = claims(PFQA);
    expect(rulesFor(jwt({ ...noIat, exp: NOW + 30 * 86_400 }))).toEqual([
      "delegation-lifetime-excess",
    ]);
    expect(rulesFor(jwt({ ...noIat, exp: NOW + 120 }))).toEqual([]);
  });

  it("delegation-actor-not-allowed (current actor: act.sub, else act.client_id)", () => {
    expect(rulesFor(jwt(claims(PFQA, { act: { sub: "bulk-export-agent" } })))).toEqual([
      "delegation-actor-not-allowed",
    ]);
    expect(rulesFor(jwt(claims(PFQA, { act: { client_id: "bulk-export-agent" } })))).toEqual([
      "delegation-actor-not-allowed",
    ]);
    expect(rulesFor(jwt(claims(PFQA, { act: { client_id: "master-quote-agent" } })))).toEqual([]);
    // Only the current actor drives policy: an unlisted *prior* actor is fine.
    expect(
      rulesFor(
        jwt(claims(PFQA, { act: { sub: "master-quote-agent", act: { sub: "front-end" } } })),
      ),
    ).toEqual([]);
  });

  it("delegation-actor-required", () => {
    const { act: _drop, ...direct } = claims(PFQA);
    expect(rulesFor(jwt(direct), { requireActor: true })).toEqual(["delegation-actor-required"]);
    expect(rulesFor(jwt(claims(PFQA)), { requireActor: true })).toEqual([]);
    expect(rulesFor(jwt(direct))).toEqual([]); // not required by default
  });

  it("delegation-chain-depth (medium)", () => {
    const deep = { sub: "master-quote-agent", act: { sub: "planner", act: { sub: "helper" } } };
    const ok = { sub: "master-quote-agent", act: { sub: "planner" } };
    const r = checkDelegation(
      policy(),
      { "x-delegate-pfqa": jwt(claims(PFQA, { act: deep })) },
      NOW,
    );
    expect(r.perUpstream.pfqa).toEqual([
      expect.objectContaining({ rule: "delegation-chain-depth", severity: "medium" }),
    ]);
    expect(rulesFor(jwt(claims(PFQA, { act: ok })))).toEqual([]);
    expect(rulesFor(jwt(claims(PFQA, { act: deep })), { maxChainDepth: undefined })).toEqual([]);
  });

  it("delegation-chain-cycle (medium)", () => {
    const cyclic = { sub: "master-quote-agent", act: { sub: "master-quote-agent" } };
    const r = checkDelegation(
      policy(),
      { "x-delegate-pfqa": jwt(claims(PFQA, { act: cyclic })) },
      NOW,
    );
    expect(r.perUpstream.pfqa).toEqual([
      expect.objectContaining({ rule: "delegation-chain-cycle", severity: "medium" }),
    ]);
    expect(
      rulesFor(jwt(claims(PFQA, { act: { sub: "master-quote-agent", act: { sub: "planner" } } }))),
    ).toEqual([]);
    expect([...DELEGATION_CHAIN_RULES].sort()).toEqual([
      "delegation-chain-cycle",
      "delegation-chain-depth",
    ]);
  });
});

describe("checkDelegation: request handling and privacy", () => {
  it("checks only carried tokens and returns claims for the audit record", () => {
    const r = checkDelegation(policy(), new Map([["x-delegate-pfqa", jwt(claims(PFQA))]]), NOW);
    expect(Object.keys(r.perUpstream)).toEqual(["pfqa"]);
    expect(r.tokens.pfqa).toEqual({
      issuer: "https://idp.example",
      subject: "user:priya",
      tokenId: "t-1",
      expiresAt: NOW + 90,
      actors: ["master-quote-agent"],
      verified: "structural",
    });
  });

  it("finding details never contain a token or a claim value", () => {
    const token = jwt(
      claims(PSQA, {
        sub: "user:secret-sub",
        iat: NOW - 999,
        exp: NOW - 500,
        act: { sub: "x-bot" },
      }),
    );
    const other = jwt(claims(PSQA, { sub: "user:other-sub" }));
    const r = checkDelegation(
      policy(),
      { "x-delegate-pfqa": token, "x-delegate-psqa": other },
      NOW,
    );
    const text = JSON.stringify([r.perUpstream, r.request]);
    expect(r.perUpstream.pfqa.length).toBeGreaterThan(2);
    for (const secret of [token, other, "user:secret-sub", "user:other-sub", "x-bot", PSQA]) {
      expect(text).not.toContain(secret);
    }
  });

  it("accepts a Bearer scheme prefix and an empty signature segment, nothing looser", () => {
    const token = jwt(claims(PFQA));
    expect(decodeJwsCompact(`Bearer ${token}`)?.payload.sub).toBe("user:priya");
    expect(decodeJwsCompact(`Bearer  ${token}`)).toBeUndefined();
    const [h, p] = token.split(".");
    expect(decodeJwsCompact(`${h}.${p}.`)).toBeDefined();
    expect(decodeJwsCompact(`${h}.${p}.@@`)).toBeUndefined();
    // Non-canonical base64url (non-zero unused bits) is refused.
    const last = p.at(-1)!;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if (p.length % 4 !== 0) {
      const tweaked = p.slice(0, -1) + alphabet[(alphabet.indexOf(last) + 1) % 64];
      expect(decodeJwsCompact(`${h}.${tweaked}.${SIG}`)).toBeUndefined();
    }
  });

  it("hasDuplicateKeys compares names after escape decoding, per object", () => {
    expect(hasDuplicateKeys('{"sub":"a","s\\u0075b":"b"}')).toBe(true);
    expect(hasDuplicateKeys('{"act":{"sub":"a"},"sub":"b"}')).toBe(false);
    expect(hasDuplicateKeys('{"a":[{"x":1},{"x":2}],"b":"\\"a\\":"}')).toBe(false);
    expect(hasDuplicateKeys('{"a":{"x":1,"x":2}}')).toBe(true);
  });

  it("subjectPseudonym is hmac: + 16 hex of HMAC-SHA256(key, iss|sub)", () => {
    const p = subjectPseudonym("k".repeat(32), "https://idp.example", "user:priya");
    expect(p).toMatch(/^hmac:[0-9a-f]{16}$/);
    expect(subjectPseudonym("k".repeat(32), "https://idp.example", "user:priya")).toBe(p);
    expect(subjectPseudonym("j".repeat(32), "https://idp.example", "user:priya")).not.toBe(p);
  });
});

describe("delegation configuration", () => {
  const http = (delegation: unknown, extra: Record<string, unknown> = {}) => ({
    transport: "http",
    url: "http://localhost:8011/mcp",
    forwardHeaders: { "x-cso-identity": "x-cso-delegate-pfqa" },
    delegation,
    ...extra,
  });
  const parse = (servers: Record<string, unknown>, top: Record<string, unknown> = {}) =>
    BastionConfigSchema.safeParse({ listen: { mode: "http" }, servers, ...top });
  const messages = (r: ReturnType<typeof parse>) =>
    r.success ? [] : r.error.issues.map((i) => i.message);

  it("applies defaults", () => {
    const r = parse({ pfqa: http({ audience: "pfqa" }) });
    expect(r.success).toBe(true);
    const cfg = r.data!;
    const server = cfg.servers.pfqa;
    expect(server.transport === "http" && server.delegation).toEqual({
      audience: "pfqa",
      verify: "structural",
      maxLifetimeSeconds: 3600,
      clockSkewSeconds: 30,
      requireActor: false,
    });
    expect(cfg.delegation).toEqual({
      gatewayAudiences: [],
      oneUserPerRequest: true,
      recordSubject: "hash",
    });
  });

  it("requires an audience", () => {
    expect(parse({ pfqa: http({}) }).success).toBe(false);
  });

  it("requires forwardHeaders", () => {
    const r = parse({ pfqa: http({ audience: "pfqa" }, { forwardHeaders: undefined }) });
    expect(messages(r).join()).toMatch(/delegation needs forwardHeaders/);
  });

  it("requires header to be a forwardHeaders key, and to be named when there are several", () => {
    expect(messages(parse({ pfqa: http({ audience: "pfqa", header: "x-other" }) })).join()).toMatch(
      /must be a forwardHeaders key/,
    );
    expect(parse({ pfqa: http({ audience: "pfqa", header: "X-CSO-Identity" }) }).success).toBe(
      true,
    );
    const two = { "x-cso-identity": "x-a", "x-trace": "x-b" };
    expect(
      messages(parse({ pfqa: http({ audience: "pfqa" }, { forwardHeaders: two }) })).join(),
    ).toMatch(/delegation.header is required/);
  });

  it('verify: "signature" needs issuer, algorithms and one key source', () => {
    const r = parse({ pfqa: http({ audience: "pfqa", verify: "signature" }) });
    expect(messages(r)).toEqual([
      'verify "signature" needs issuer',
      'verify "signature" needs a non-empty algorithms list',
      'verify "signature" needs exactly one key source: jwksUrl or jwks',
    ]);
  });

  it("rejects duplicate audiences across upstreams and an audience that is the gateway's", () => {
    const psqa = http(
      { audience: "pfqa" },
      { forwardHeaders: { "x-cso-identity": "x-cso-delegate-psqa" } },
    );
    expect(messages(parse({ pfqa: http({ audience: "pfqa" }), psqa })).join()).toMatch(
      /already used by "pfqa"/,
    );
    expect(
      messages(
        parse(
          { pfqa: http({ audience: "mcp-bastion" }) },
          { delegation: { gatewayAudiences: ["mcp-bastion"] } },
        ),
      ).join(),
    ).toMatch(/cannot also identify Bastion/);
  });

  it("rejects unknown keys (a typo must not silently drop a check) and stdio upstreams", () => {
    expect(parse({ pfqa: http({ audience: "pfqa", maxChainDeph: 2 }) }).success).toBe(false);
    expect(parse({ local: { command: "node", delegation: { audience: "pfqa" } } }).success).toBe(
      false,
    );
  });

  it("onDelegation / onDelegationChain default from the enforcement profile", () => {
    const at = (enforcementProfile: string) => SecurityConfigSchema.parse({ enforcementProfile });
    expect(at("observe")).toMatchObject({ onDelegation: "warn", onDelegationChain: "warn" });
    expect(at("balanced")).toMatchObject({ onDelegation: "block", onDelegationChain: "warn" });
    expect(at("strict")).toMatchObject({ onDelegation: "block", onDelegationChain: "block" });
    expect(SecurityConfigSchema.parse({ onDelegationChain: "block" }).onDelegationChain).toBe(
      "block",
    );
  });
});

// ---------------------------------------------------------------------------------------------
// mcp-defense-bench pre-registered DEV fixtures (staging/delegation/dev only; the held-out set is
// never read here). Signature-forgery fixtures run in signature mode with their inline public JWKS.
// ---------------------------------------------------------------------------------------------

interface DelegatedRequest {
  now: number;
  gateway: { audiences: string[] };
  upstreams: Record<string, { audience: string; incomingHeader: string }>;
  trust:
    | { mode: "structural" }
    | { mode: "signature"; jwks: JSONWebKeySet; issuer: string; algorithms: string[] };
  policy: {
    maxLifetimeSeconds?: number;
    clockSkewSeconds?: number;
    allowedActors?: string[];
    maxChainDepth?: number;
  };
  request: { method: string; target: string; headers: Record<string, string> };
}
interface DevFixture {
  id: string;
  fixture: DelegatedRequest;
  expected: { detect: boolean; enforce: boolean };
  benignControl: DelegatedRequest;
}

const DEV_DIR = join(
  fileURLToPath(new URL("..", import.meta.url)),
  "..",
  "mcp-defense-bench",
  "staging",
  "delegation",
  "dev",
);

function loadDevFixtures(): DevFixture[] {
  const out: DevFixture[] = [];
  for (const vector of readdirSync(DEV_DIR)) {
    for (const file of readdirSync(join(DEV_DIR, vector))) {
      if (file.endsWith(".json")) {
        out.push(JSON.parse(readFileSync(join(DEV_DIR, vector, file), "utf8")) as DevFixture);
      }
    }
  }
  return out;
}

/**
 * Findings on the target upstream plus request-wide ones, as Bastion would apply them. This is the
 * whole mapping a bench adapter needs: fixture upstreams + trust + policy → a DelegationPolicy.
 */
async function evaluate(fx: DelegatedRequest) {
  const trust = fx.trust;
  const signature =
    trust.mode === "signature"
      ? {
          issuer: trust.issuer,
          algorithms: trust.algorithms,
          keys: delegationKeySet({ jwks: trust.jwks }),
        }
      : undefined;
  const upstreams: Record<string, DelegationUpstreamPolicy> = {};
  for (const [name, u] of Object.entries(fx.upstreams)) {
    upstreams[name] = {
      incomingHeader: u.incomingHeader,
      audience: u.audience,
      ...fx.policy,
      ...(signature ? { signature } : {}),
    };
  }
  const headers = Object.fromEntries(
    Object.entries(fx.request.headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
  const r = await checkDelegationAsync(
    { upstreams, gatewayAudiences: fx.gateway.audiences, oneUserPerRequest: true },
    headers,
    fx.now,
  );
  return [...(r.perUpstream[fx.request.target] ?? []), ...r.request];
}

describe.skipIf(!existsSync(DEV_DIR))("mcp-defense-bench delegation dev fixtures", () => {
  const fixtures = existsSync(DEV_DIR) ? loadDevFixtures() : [];
  const signed = fixtures.filter((f) => f.fixture.trust.mode === "signature");

  it("has the pre-registered dev fixtures (12 structural, 3 signature)", () => {
    expect(fixtures.length - signed.length).toBeGreaterThanOrEqual(12);
    expect(signed.length).toBeGreaterThanOrEqual(3);
  });

  for (const f of fixtures) {
    it(`${f.id}: flags the attack, passes its benign control`, async () => {
      const findings = await evaluate(f.fixture);
      expect(findings.length, "attack detected").toBeGreaterThan(0);
      // Balanced profile: chain rules warn, everything else blocks.
      const blocks = findings.some((x) => !DELEGATION_CHAIN_RULES.has(x.rule));
      expect(blocks, "enforce matches expectation").toBe(f.expected.enforce);
      if (f.fixture.trust.mode === "signature") {
        const signatureRules = [
          "delegation-signature-invalid",
          "delegation-alg-disallowed",
          "delegation-issuer-mismatch",
          "delegation-key-unknown",
        ];
        expect(
          findings.some((x) => signatureRules.includes(x.rule)),
          "signature rule",
        ).toBe(true);
      }
      expect(await evaluate(f.benignControl), "benign control").toEqual([]);
    });
  }
});
