/**
 * Keyless delegation checks, signature mode: tokens verified against the issuer's public keys
 * (generated here, served from a local JWKS endpoint and also passed inline). Covers the forgery
 * attacks, the operational cases (unknown kid, JWKS outage) and the configuration.
 */
import { afterEach, describe, expect, it } from "vitest";
import { createHmac, randomUUID } from "node:crypto";
import { createServer, type Server as HttpServer } from "node:http";
import { exportJWK, exportSPKI, generateKeyPair, SignJWT, type JWK } from "jose";

import { BastionConfigSchema } from "../src/config/index.js";
import {
  checkDelegation,
  checkDelegationAsync,
  delegationKeySet,
  type DelegationKeySource,
  type DelegationPolicy,
} from "../src/security/index.js";

const NOW = Math.floor(Date.now() / 1000);
const ISSUER = "https://idp.example";
const AUD = "https://pfqa.example/mcp";
const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

type Pair = Awaited<ReturnType<typeof generateKeyPair>>;
interface SigningKey {
  alg: "ES256" | "EdDSA";
  kid: string;
  pair: Pair;
  jwk: JWK;
}

async function signingKey(alg: "ES256" | "EdDSA", kid: string): Promise<SigningKey> {
  const pair = await generateKeyPair(alg, { extractable: true });
  const jwk = { ...(await exportJWK(pair.publicKey)), kid, alg, use: "sig" };
  return { alg, kid, pair, jwk };
}

const claims = (extra: Record<string, unknown> = {}) => ({
  iss: ISSUER,
  sub: "user:priya",
  aud: AUD,
  iat: NOW - 10,
  exp: NOW + 110,
  jti: randomUUID(),
  act: { sub: "master-quote-agent" },
  ...extra,
});

async function sign(
  key: SigningKey,
  extra: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
): Promise<string> {
  return new SignJWT(claims(extra))
    .setProtectedHeader({ alg: key.alg, kid: key.kid, typ: "JWT", ...header })
    .sign(key.pair.privateKey);
}

const keys: { es: SigningKey; ed: SigningKey; attacker: SigningKey } = {} as never;
const ready = (async () => {
  keys.es = await signingKey("ES256", "trusted-es");
  keys.ed = await signingKey("EdDSA", "trusted-ed");
  keys.attacker = await signingKey("ES256", "trusted-es"); // same kid, different key
})();

/** A JWKS endpoint that counts hits and can be changed, failed or hung. */
async function jwksServer(initial: () => JWK[]) {
  let mode: "ok" | "500" | "hang" = "ok";
  let current = initial;
  const hits: number[] = [];
  const server: HttpServer = createServer((_req, res) => {
    hits.push(Date.now());
    if (mode === "hang") return; // never answers
    if (mode === "500") return void res.writeHead(500).end("down");
    res
      .writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ keys: current() }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  cleanups.push(
    () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  );
  return {
    url: `http://127.0.0.1:${(server.address() as { port: number }).port}/jwks.json`,
    hits,
    setKeys: (k: () => JWK[]) => (current = k),
    setMode: (m: typeof mode) => (mode = m),
  };
}

const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => undefined);
});

function policy(source: DelegationKeySource, algorithms = ["ES256", "EdDSA"]): DelegationPolicy {
  return {
    upstreams: {
      pfqa: {
        incomingHeader: "x-delegate-pfqa",
        audience: AUD,
        maxLifetimeSeconds: 300,
        clockSkewSeconds: 30,
        allowedActors: ["master-quote-agent"],
        signature: { issuer: ISSUER, algorithms, keys: delegationKeySet(source) },
      },
    },
    gatewayAudiences: ["https://bastion.example/mcp"],
  };
}

async function run(p: DelegationPolicy, token: string) {
  const r = await checkDelegationAsync(p, { "x-delegate-pfqa": token }, NOW);
  return { rules: (r.perUpstream.pfqa ?? []).map((f) => f.rule), result: r };
}

const inline = () => ({ jwks: { keys: [keys.es.jwk, keys.ed.jwk] } });

describe("signature mode: valid tokens", () => {
  it("verifies ES256 and EdDSA tokens with an inline key set", async () => {
    await ready;
    for (const key of [keys.es, keys.ed]) {
      const { rules, result } = await run(policy(inline()), await sign(key));
      expect(rules, key.alg).toEqual([]);
      expect(result.tokens.pfqa.verified).toBe("signature");
    }
  });

  it("verifies against a remote JWKS, fetched once and cached", async () => {
    await ready;
    const jwks = await jwksServer(() => [keys.es.jwk, keys.ed.jwk]);
    const p = policy({ jwksUrl: jwks.url });
    for (let i = 0; i < 3; i++) {
      expect((await run(p, await sign(i % 2 ? keys.ed : keys.es))).rules).toEqual([]);
    }
    expect(jwks.hits).toHaveLength(1);
  });

  it("keeps structural rules and names in signature mode", async () => {
    await ready;
    const p = policy(inline());
    expect((await run(p, await sign(keys.es, { aud: "https://psqa.example/mcp" }))).rules).toEqual([
      "delegation-audience-mismatch",
    ]);
    expect(
      (await run(p, await sign(keys.es, { aud: "https://bastion.example/mcp" }))).rules,
    ).toEqual(["delegation-passthrough"]);
    expect((await run(p, await sign(keys.es, { exp: NOW - 100, iat: NOW - 200 }))).rules).toEqual([
      "delegation-expired",
    ]);
    // Subject mixing still spans the request.
    const both = {
      ...p,
      upstreams: {
        ...p.upstreams,
        psqa: { ...p.upstreams.pfqa, incomingHeader: "x-delegate-psqa", audience: "psqa" },
      },
    };
    const r = await checkDelegationAsync(
      both,
      {
        "x-delegate-pfqa": await sign(keys.es),
        "x-delegate-psqa": await sign(keys.es, { aud: "psqa", sub: "user:raj" }),
      },
      NOW,
    );
    expect(r.request.map((f) => f.rule)).toEqual(["delegation-subject-mixing"]);
  });
});

describe("signature mode: forgeries", () => {
  it("alg none, in any casing, is disallowed before any key lookup", async () => {
    await ready;
    const jwks = await jwksServer(() => [keys.es.jwk]);
    const p = policy({ jwksUrl: jwks.url });
    for (const alg of ["none", "None", "NONE", "nOnE"]) {
      const token = `${b64({ alg, typ: "JWT" })}.${b64(claims())}.`;
      const { rules, result } = await run(p, token);
      expect(rules, alg).toEqual(["delegation-alg-disallowed"]);
      expect(result.tokens.pfqa.verified).toBe("failed");
    }
    expect(jwks.hits).toHaveLength(0);
  });

  it("HS256 signed with the public key as the HMAC secret is disallowed", async () => {
    await ready;
    const header = b64({ alg: "HS256", typ: "JWT", kid: keys.es.kid });
    const body = b64(claims());
    for (const secret of [await exportSPKI(keys.es.pair.publicKey), JSON.stringify(keys.es.jwk)]) {
      const sig = createHmac("sha256", secret).update(`${header}.${body}`).digest("base64url");
      expect((await run(policy(inline()), `${header}.${body}.${sig}`)).rules).toEqual([
        "delegation-alg-disallowed",
      ]);
    }
  });

  it("an algorithm outside the allow-list (case-sensitive) is disallowed", async () => {
    await ready;
    expect((await run(policy(inline(), ["ES256"]), await sign(keys.ed))).rules).toEqual([
      "delegation-alg-disallowed",
    ]);
    const [, body, sig] = (await sign(keys.es)).split(".");
    const lower = `${b64({ alg: "es256", kid: keys.es.kid })}.${body}.${sig}`;
    expect((await run(policy(inline()), lower)).rules).toEqual(["delegation-alg-disallowed"]);
  });

  it("an attacker key presenting the trusted kid fails verification", async () => {
    await ready;
    expect((await run(policy(inline()), await sign(keys.attacker))).rules).toEqual([
      "delegation-signature-invalid",
    ]);
  });

  it("jku, x5u and embedded jwk headers are never followed", async () => {
    await ready;
    const evil = await jwksServer(() => [keys.attacker.jwk]);
    const trusted = await jwksServer(() => [keys.es.jwk]);
    const p = policy({ jwksUrl: trusted.url });
    for (const header of [
      { jku: evil.url },
      { x5u: evil.url },
      { jwk: keys.attacker.jwk },
      { jku: evil.url, kid: "attacker-only" },
    ]) {
      const { rules } = await run(p, await sign(keys.attacker, {}, header));
      expect(
        rules.some((r) => r === "delegation-signature-invalid" || r === "delegation-key-unknown"),
      ).toBe(true);
    }
    expect(evil.hits).toHaveLength(0);
  });

  it("a wrong issuer is reported even with a valid signature", async () => {
    await ready;
    const { rules, result } = await run(
      policy(inline()),
      await sign(keys.es, { iss: "https://evil-idp.example" }),
    );
    expect(rules).toEqual(["delegation-issuer-mismatch"]);
    expect(result.tokens.pfqa.verified).toBe("signature");
  });

  it("a payload changed after signing fails verification", async () => {
    await ready;
    const [h, , s] = (await sign(keys.es)).split(".");
    const tampered = `${h}.${b64(claims({ sub: "user:admin" }))}.${s}`;
    expect((await run(policy(inline()), tampered)).rules).toEqual(["delegation-signature-invalid"]);
  });

  it("a critical header extension (unencoded payload) is refused", async () => {
    await ready;
    const [, body, sig] = (await sign(keys.es)).split(".");
    const crafted = `${b64({ alg: "ES256", kid: keys.es.kid, crit: ["b64"], b64: false })}.${body}.${sig}`;
    expect((await run(policy(inline()), crafted)).rules).toEqual(["delegation-signature-invalid"]);
  });
});

describe("signature mode: operations", () => {
  it("an unknown kid triggers at most one refetch per cooldown", async () => {
    await ready;
    const jwks = await jwksServer(() => [keys.es.jwk]);
    const p = policy({ jwksUrl: jwks.url, cooldownMs: 400 });
    expect((await run(p, await sign(keys.es))).rules).toEqual([]);
    expect(jwks.hits).toHaveLength(1);

    // The issuer rotates in a new key; tokens with its kid arrive inside the cooldown.
    const rotated = await signingKey("ES256", "rotated-es");
    jwks.setKeys(() => [keys.es.jwk, rotated.jwk]);
    for (let i = 0; i < 5; i++) {
      expect((await run(p, await sign(rotated))).rules).toEqual(["delegation-key-unknown"]);
    }
    expect(jwks.hits).toHaveLength(1);

    // After the cooldown, exactly one refetch picks the new key up.
    await new Promise((r) => setTimeout(r, 450));
    expect((await run(p, await sign(rotated))).rules).toEqual([]);
    expect((await run(p, await sign(rotated))).rules).toEqual([]);
    expect(jwks.hits).toHaveLength(2);
  });

  it("a JWKS outage fails closed, without a fetch storm, and the error names no token", async () => {
    await ready;
    const jwks = await jwksServer(() => [keys.es.jwk]);
    jwks.setMode("500");
    const p = policy({ jwksUrl: jwks.url, cooldownMs: 400 });
    const token = await sign(keys.es);
    for (let i = 0; i < 4; i++) {
      const { rules, result } = await run(p, token);
      expect(rules).toEqual(["delegation-key-unknown"]);
      expect(result.errors?.pfqa).toMatch(/key set unavailable/);
      expect(result.errors?.pfqa).not.toContain(token);
    }
    expect(jwks.hits).toHaveLength(1); // failed fast inside the cooldown

    jwks.setMode("ok");
    await new Promise((r) => setTimeout(r, 450));
    expect((await run(p, token)).rules).toEqual([]);
  });

  it("a JWKS endpoint that never answers fails closed after the timeout", async () => {
    await ready;
    const jwks = await jwksServer(() => [keys.es.jwk]);
    jwks.setMode("hang");
    const p = policy({ jwksUrl: jwks.url, timeoutMs: 200 });
    const started = Date.now();
    const { rules, result } = await run(p, await sign(keys.es));
    expect(rules).toEqual(["delegation-key-unknown"]);
    expect(result.errors?.pfqa).toMatch(/key set unavailable/);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it("the synchronous checker refuses a signature-mode policy instead of skipping verification", async () => {
    await ready;
    expect(() => checkDelegation(policy(inline()), {}, NOW)).toThrow(/checkDelegationAsync/);
  });
});

describe("signature mode configuration", () => {
  const server = (delegation: Record<string, unknown>) => ({
    transport: "http",
    url: "http://localhost:8011/mcp",
    forwardHeaders: { "x-cso-identity": "x-cso-delegate-pfqa" },
    delegation: { audience: "pfqa", verify: "signature", issuer: ISSUER, ...delegation },
  });
  const parse = (delegation: Record<string, unknown>) =>
    BastionConfigSchema.safeParse({
      listen: { mode: "http" },
      servers: { pfqa: server(delegation) },
    });
  const messages = (r: ReturnType<typeof parse>) =>
    r.success ? "" : r.error.issues.map((i) => i.message).join(" | ");

  it("accepts a remote HTTPS key set, a loopback HTTP one, or an inline public set", async () => {
    await ready;
    for (const source of [
      { jwksUrl: "https://idp.example/.well-known/jwks.json" },
      { jwksUrl: "http://127.0.0.1:9000/jwks.json" },
      { jwks: { keys: [keys.es.jwk] } },
    ]) {
      const r = parse({ algorithms: ["ES256"], ...source });
      expect(r.success, messages(r)).toBe(true);
    }
  });

  it("rejects plaintext HTTP to a remote JWKS host", () => {
    expect(messages(parse({ algorithms: ["ES256"], jwksUrl: "http://idp.example/jwks" }))).toMatch(
      /must use HTTPS/,
    );
  });

  it("rejects HMAC and none in any casing, and unknown algorithms", () => {
    for (const alg of ["HS256", "hs384", "Hs512", "none", "NONE", "None"]) {
      expect(messages(parse({ algorithms: [alg], jwksUrl: "https://i.example/j" })), alg).toMatch(
        /never accepted/,
      );
    }
    expect(messages(parse({ algorithms: ["es256"], jwksUrl: "https://i.example/j" }))).toMatch(
      /unsupported algorithm/,
    );
    expect(messages(parse({ algorithms: [], jwksUrl: "https://i.example/j" }))).not.toBe("");
  });

  it("requires exactly one key source", async () => {
    await ready;
    expect(
      messages(
        parse({
          algorithms: ["ES256"],
          jwksUrl: "https://i.example/j",
          jwks: { keys: [keys.es.jwk] },
        }),
      ),
    ).toMatch(/exactly one key source/);
  });

  it("rejects a key set carrying private or secret key material", async () => {
    await ready;
    const priv = await exportJWK(keys.es.pair.privateKey);
    expect(messages(parse({ algorithms: ["ES256"], jwks: { keys: [priv] } }))).toMatch(
      /private or secret member\(s\) d/,
    );
    expect(
      messages(parse({ algorithms: ["ES256"], jwks: { keys: [{ kty: "oct", k: "c2VjcmV0" }] } })),
    ).toMatch(/member\(s\) k/);
  });

  it("rejects signature-only keys in structural mode", () => {
    const r = BastionConfigSchema.safeParse({
      listen: { mode: "http" },
      servers: {
        pfqa: { ...server({}), delegation: { audience: "pfqa", issuer: ISSUER } },
      },
    });
    expect(messages(r)).toMatch(/"issuer" is only valid with verify: "signature"/);
  });
});
