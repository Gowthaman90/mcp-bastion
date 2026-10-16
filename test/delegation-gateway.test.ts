/**
 * Keyless delegation checks end to end, on the identity-forwarding fixture: two sub-agents behind
 * one Bastion, each receiving its own delegate JWT. A request that mixes two users never reaches an
 * upstream, is audited with a hashed subject, and leaves no token or raw subject anywhere.
 */
import { afterEach, describe, expect, it } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server as HttpServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { BastionConfigSchema } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";
import { startHttpServer, type HttpListener } from "../src/proxy/index.js";
import { subjectPseudonym } from "../src/security/index.js";
// @ts-expect-error -- untyped .mjs test helper
import { startIdentityHttpServer } from "./helpers/identity-http-server.mjs";

interface UpstreamFixture {
  url: string;
  requests: { httpMethod: string; method?: string; identity?: string }[];
  close(): Promise<void>;
}

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const ISSUER = "https://spire.example/identity";
const SUBJECT_KEY = "subject-key-for-tests-0123456789";
const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

/** A delegate token (HS256-shaped; Bastion never verifies the signature in structural mode). */
function delegate(aud: string, sub: string, extra: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: ISSUER,
    sub,
    aud,
    iat: now - 5,
    exp: now + 115,
    jti: randomUUID(),
    act: { sub: "master-quote-agent" },
    ...extra,
  };
  return `${b64({ typ: "JWT", alg: "HS256" })}.${b64(payload)}.${b64(randomUUID())}`;
}

function textOf(res: unknown): string {
  const content = (res as { content?: Array<{ type?: string; text?: string }> }).content ?? [];
  return content.map((c) => (c.type === "text" ? (c.text ?? "") : "")).join("");
}

/** Bastion config for two sub-agents, each with its own delegate header and audience. */
function rawConfig(pfqaUrl: string, psqaUrl: string, extra: Record<string, unknown> = {}) {
  const server = (url: string, name: string) => ({
    transport: "http",
    url,
    protocol: "legacy",
    connect: "onDemand",
    forwardHeaders: { "x-cso-identity": `x-cso-delegate-${name}` },
    delegation: {
      audience: name,
      maxLifetimeSeconds: 120,
      allowedActors: ["master-quote-agent"],
      maxChainDepth: 2,
    },
  });
  return {
    servers: { pfqa: server(pfqaUrl, "pfqa"), psqa: server(psqaUrl, "psqa") },
    listen: { mode: "http" },
    delegation: { gatewayAudiences: ["mcp-bastion"], subjectKey: SUBJECT_KEY },
    ...extra,
  };
}

const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => undefined);
});

async function client(url: string, headers: Record<string, string>): Promise<Client> {
  const c = new Client({ name: "master-engine", version: "0.0.0" }, { capabilities: {} });
  await c.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers } }));
  cleanups.push(() => c.close());
  return c;
}

async function startGateway(): Promise<{
  pfqa: UpstreamFixture;
  psqa: UpstreamFixture;
  mgr: UpstreamManager;
  listener: HttpListener;
}> {
  const pfqa = (await startIdentityHttpServer()) as UpstreamFixture;
  const psqa = (await startIdentityHttpServer()) as UpstreamFixture;
  cleanups.push(
    () => pfqa.close(),
    () => psqa.close(),
  );
  const mgr = new UpstreamManager(
    BastionConfigSchema.parse({
      ...rawConfig(pfqa.url, psqa.url),
      reconnect: { auto: false },
      healthCheck: { enabled: false },
    }),
  );
  cleanups.push(() => mgr.closeAll());
  const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
  cleanups.push(() => listener.close());
  return { pfqa, psqa, mgr, listener };
}

describe("delegation checks in the gateway", () => {
  it("serves a request whose tokens all name one user", async () => {
    const { pfqa, mgr, listener } = await startGateway();
    const token = delegate("pfqa", "user:priya");
    const c = await client(listener.url, {
      "x-cso-delegate-pfqa": token,
      "x-cso-delegate-psqa": delegate("psqa", "user:priya"),
    });
    const res = await c.callTool({ name: "pfqa__whoami", arguments: {} });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(textOf(res)).toBe(`identity=${token} n=`);
    expect(pfqa.requests.some((q) => q.identity === token)).toBe(true);
    expect(mgr.status().find((s) => s.name === "pfqa")?.delegation).toEqual({
      mode: "structural",
      audience: "pfqa",
      lastViolation: null,
    });
  });

  it("blocks a request mixing two users before any upstream request (call and list)", async () => {
    const { pfqa, psqa, mgr, listener } = await startGateway();
    const c = await client(listener.url, {
      "x-cso-delegate-pfqa": delegate("pfqa", "user:priya"),
      "x-cso-delegate-psqa": delegate("psqa", "user:raj"),
    });
    const res = await c.callTool({ name: "pfqa__whoami", arguments: {} });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toBe(
      'Blocked by mcp-bastion: the delegation token for "pfqa" failed delegation-subject-mixing, ' +
        'so "pfqa__whoami" was not forwarded.',
    );
    const names = (await c.listTools()).tools.map((t) => t.name);
    expect(names.filter((n) => !n.startsWith("bastion__"))).toEqual([]);
    expect(pfqa.requests).toHaveLength(0);
    expect(psqa.requests).toHaveLength(0);
    const status = mgr.status().find((s) => s.name === "pfqa")!;
    expect(status.state).toBe("idle");
    expect(status.delegation?.lastViolation?.rule).toBe("delegation-subject-mixing");
    expect(Object.keys(status.delegation!.lastViolation!)).toEqual(["rule", "at"]);
  });

  it("does not list a shared, already-connected upstream to a blocked request", async () => {
    const { pfqa, listener } = await startGateway();
    const good = await client(listener.url, { "x-cso-delegate-pfqa": delegate("pfqa", "u:a") });
    expect((await good.listTools()).tools.map((t) => t.name)).toContain("pfqa__whoami");
    const before = pfqa.requests.length;
    const wrongAudience = await client(listener.url, {
      "x-cso-delegate-pfqa": delegate("psqa", "u:a"),
    });
    expect((await wrongAudience.listTools()).tools.map((t) => t.name)).not.toContain(
      "pfqa__whoami",
    );
    const res = await wrongAudience.callTool({ name: "pfqa__whoami", arguments: {} });
    expect(textOf(res)).toMatch(/failed delegation-audience-mismatch/);
    expect(pfqa.requests.length).toBe(before);
  });

  it("the fetch backstop refuses a blocked token on a reconnect made inside the request", async () => {
    const { pfqa, listener } = await startGateway();
    const c = await client(listener.url, {
      "x-cso-delegate-pfqa": delegate("mcp-bastion", "user:priya"), // passthrough
    });
    const res = await c.callTool({ name: "bastion__reconnect", arguments: { server: "pfqa" } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/delegation-passthrough/);
    expect(pfqa.requests).toHaveLength(0);
  });

  it("chain depth is warn-only by default: the call goes ahead and status notes the rule", async () => {
    const { pfqa, mgr, listener } = await startGateway();
    const act = { sub: "master-quote-agent", act: { sub: "planner", act: { sub: "helper" } } };
    const token = delegate("pfqa", "user:priya", { act });
    const c = await client(listener.url, { "x-cso-delegate-pfqa": token });
    const res = await c.callTool({ name: "pfqa__whoami", arguments: {} });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(pfqa.requests.some((q) => q.identity === token)).toBe(true);
    const status = mgr.status().find((s) => s.name === "pfqa")!;
    expect(status.delegation?.lastViolation?.rule).toBe("delegation-chain-depth");
  });
});

describe("delegation checks end to end (CLI)", () => {
  it("audits a blocked mixed-user request with a hashed subject and records no token or raw sub", async () => {
    const pfqa = (await startIdentityHttpServer()) as UpstreamFixture;
    const psqa = (await startIdentityHttpServer()) as UpstreamFixture;
    cleanups.push(
      () => pfqa.close(),
      () => psqa.close(),
    );

    const webhookBodies: string[] = [];
    const hook: HttpServer = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        webhookBodies.push(Buffer.concat(chunks).toString("utf8"));
        res.writeHead(204).end();
      });
    });
    await new Promise<void>((r) => hook.listen(0, "127.0.0.1", r));
    cleanups.push(() => new Promise((r) => hook.close(r)));
    const hookPort = (hook.address() as { port: number }).port;

    const dir = await mkdtemp(join(tmpdir(), "bastion-deleg-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const auditPath = join(dir, "audit.jsonl");
    const configPath = join(dir, "bastion.config.json");
    await writeFile(
      configPath,
      JSON.stringify(
        rawConfig(pfqa.url, psqa.url, {
          audit: {
            enabled: true,
            includeArgs: "full",
            tamperEvident: true,
            sinks: [
              { type: "console" },
              { type: "file", path: auditPath },
              { type: "webhook", url: `http://127.0.0.1:${hookPort}/audit`, batchSize: 1 },
            ],
          },
        }),
      ),
    );

    const child: ChildProcess = spawn(
      process.execPath,
      ["--import", "tsx", "src/cli.ts", "--config", configPath, "--http", "0"],
      { cwd: repoRoot, env: { ...process.env, BASTION_LOG_LEVEL: "trace" } },
    );
    let stderr = "";
    child.stderr!.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
    const exited = new Promise<void>((r) => child.on("exit", () => r()));
    cleanups.push(async () => {
      if (child.exitCode === null) child.kill("SIGKILL");
    });
    const url = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no start-up line:\n${stderr}`)), 15_000);
      const check = () => {
        for (const line of stderr.split("\n")) {
          if (!line.includes('"mcp-bastion started"')) continue;
          clearTimeout(timer);
          resolve((JSON.parse(line) as { url: string }).url);
          return;
        }
        child.stderr!.once("data", check);
      };
      check();
    });

    const priya = `user:priya-${randomUUID()}`;
    const raj = `user:raj-${randomUUID()}`;
    const tokens = {
      goodPfqa: delegate("pfqa", priya),
      goodPsqa: delegate("psqa", priya),
      mixedPfqa: delegate("pfqa", priya),
      mixedPsqa: delegate("psqa", raj),
    };
    const good = await client(url, {
      "x-cso-delegate-pfqa": tokens.goodPfqa,
      "x-cso-delegate-psqa": tokens.goodPsqa,
    });
    const mixed = await client(url, {
      "x-cso-delegate-pfqa": tokens.mixedPfqa,
      "x-cso-delegate-psqa": tokens.mixedPsqa,
    });

    const blocked = await mixed.callTool({ name: "pfqa__whoami", arguments: { n: 1 } });
    expect(textOf(blocked)).toMatch(/failed delegation-subject-mixing/);
    expect(pfqa.requests).toHaveLength(0);
    expect(psqa.requests).toHaveLength(0);

    const ok = await good.callTool({ name: "pfqa__whoami", arguments: { n: 2 } });
    expect(textOf(ok)).toBe(`identity=${tokens.goodPfqa} n=2`);
    const statusText = textOf(await mixed.callTool({ name: "bastion__status", arguments: {} }));
    expect(statusText).toMatch(/"rule":\s*"delegation-subject-mixing"/);
    expect(statusText).toMatch(/"mode":\s*"structural"/);
    await good.close();
    await mixed.close();

    child.kill("SIGTERM"); // graceful: flushes and closes the audit sinks
    await exited;

    const events = (await readFile(auditPath, "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const hashed = subjectPseudonym(SUBJECT_KEY, ISSUER, priya);
    const blockedEvent = events.find((e) => e.decision === "blocked_delegation");
    expect(blockedEvent).toMatchObject({
      server: "pfqa",
      tool: "whoami",
      namespacedName: "pfqa__whoami",
      outcome: "blocked",
      forwardedHeaders: ["x-cso-identity"],
      delegation: {
        subject: hashed,
        issuer: ISSUER,
        audience: "pfqa",
        actors: ["master-quote-agent"],
        chainDepth: 1,
        verified: "structural",
        findings: [{ rule: "delegation-subject-mixing", severity: "high" }],
      },
    });
    expect(blockedEvent!.hash).toEqual(expect.any(String)); // in the tamper-evident chain
    const allowedEvent = events.find((e) => e.decision === "allowed");
    expect(allowedEvent).toMatchObject({ delegation: { subject: hashed, findings: [] } });

    const audit = await readFile(auditPath, "utf8");
    for (const [sink, output] of [
      ["stderr logs + console sink", stderr],
      ["file sink", audit],
      ["webhook sink", webhookBodies.join("\n")],
      ["bastion__status", statusText],
    ] as const) {
      for (const secret of [...Object.values(tokens), priya, raj]) {
        expect(output, sink).not.toContain(secret);
      }
    }
  });
});

describe("signature mode in the gateway", () => {
  async function setup() {
    const trusted = await generateKeyPair("ES256", { extractable: true });
    const attacker = await generateKeyPair("ES256", { extractable: true });
    const jwk: JWK = { ...(await exportJWK(trusted.publicKey)), kid: "spire-1", alg: "ES256" };
    let down = false;
    const jwksHits: number[] = [];
    const jwksServer: HttpServer = createServer((_req, res) => {
      jwksHits.push(Date.now());
      if (down) return void res.writeHead(503).end();
      res
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ keys: [jwk] }));
    });
    await new Promise<void>((r) => jwksServer.listen(0, "127.0.0.1", r));
    cleanups.push(() => new Promise((r) => jwksServer.close(r)));
    const jwksUrl = `http://127.0.0.1:${(jwksServer.address() as { port: number }).port}/jwks`;

    const pfqa = (await startIdentityHttpServer()) as UpstreamFixture;
    cleanups.push(() => pfqa.close());
    const dir = await mkdtemp(join(tmpdir(), "bastion-sig-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const auditPath = join(dir, "audit.jsonl");
    const mgr = new UpstreamManager(
      BastionConfigSchema.parse({
        servers: {
          pfqa: {
            transport: "http",
            url: pfqa.url,
            protocol: "legacy",
            connect: "onDemand",
            forwardHeaders: { "x-cso-identity": "x-cso-delegate-pfqa" },
            delegation: {
              audience: "pfqa",
              verify: "signature",
              issuer: ISSUER,
              algorithms: ["ES256"],
              jwksUrl,
              maxLifetimeSeconds: 120,
            },
          },
        },
        listen: { mode: "http" },
        delegation: { gatewayAudiences: ["mcp-bastion"], subjectKey: SUBJECT_KEY },
        audit: { enabled: true, sinks: [{ type: "file", path: auditPath }] },
        reconnect: { auto: false },
        healthCheck: { enabled: false },
      }),
    );
    let closed = false;
    const closeMgr = async () => {
      if (!closed) await mgr.closeAll();
      closed = true;
    };
    cleanups.push(closeMgr);
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
    cleanups.push(() => listener.close());

    const now = Math.floor(Date.now() / 1000);
    const sign = (key: CryptoKey, sub = "user:priya") =>
      new SignJWT({ sub, act: { sub: "master-quote-agent" } })
        .setProtectedHeader({ alg: "ES256", kid: "spire-1", typ: "JWT" })
        .setIssuer(ISSUER)
        .setAudience("pfqa")
        .setIssuedAt(now - 5)
        .setExpirationTime(now + 100)
        .sign(key);
    const audit = async () => {
      await closeMgr();
      return (await readFile(auditPath, "utf8"))
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l) as { decision: string; delegation?: Record<string, unknown> });
    };
    return {
      pfqa,
      mgr,
      listener,
      jwksHits,
      setDown: (d: boolean) => (down = d),
      sign,
      trusted,
      attacker,
      audit,
    };
  }

  it("passes a validly signed token through and blocks a forged one before any upstream request", async () => {
    const g = await setup();
    const forged = await g.sign(g.attacker.privateKey);
    const bad = await client(g.listener.url, { "x-cso-delegate-pfqa": forged });
    const blocked = await bad.callTool({ name: "pfqa__whoami", arguments: {} });
    expect(textOf(blocked)).toBe(
      'Blocked by mcp-bastion: the delegation token for "pfqa" failed ' +
        'delegation-signature-invalid, so "pfqa__whoami" was not forwarded.',
    );
    expect((await bad.listTools()).tools.map((t) => t.name)).not.toContain("pfqa__whoami");
    expect(g.pfqa.requests).toHaveLength(0);

    const token = await g.sign(g.trusted.privateKey);
    const good = await client(g.listener.url, { "x-cso-delegate-pfqa": token });
    const ok = await good.callTool({ name: "pfqa__whoami", arguments: {} });
    expect(ok.isError, textOf(ok)).toBeFalsy();
    expect(textOf(ok)).toBe(`identity=${token} n=`);
    expect(g.jwksHits).toHaveLength(1); // fetched once, cached across requests
    expect(g.mgr.status()[0].delegation).toMatchObject({
      mode: "signature",
      audience: "pfqa",
      lastViolation: { rule: "delegation-signature-invalid" },
    });

    const events = await g.audit();
    expect(events.find((e) => e.decision === "blocked_delegation")?.delegation).toMatchObject({
      verified: "failed",
      findings: [{ rule: "delegation-signature-invalid", severity: "high" }],
    });
    expect(events.find((e) => e.decision === "allowed")?.delegation).toMatchObject({
      verified: "signature",
      subject: subjectPseudonym(SUBJECT_KEY, ISSUER, "user:priya"),
      findings: [],
    });
    const text = JSON.stringify(events);
    expect(text).not.toContain(token);
    expect(text).not.toContain(forged);
  });

  it("fails closed when the key set is unreachable, and says so in status", async () => {
    const g = await setup();
    g.setDown(true);
    const token = await g.sign(g.trusted.privateKey);
    const c = await client(g.listener.url, { "x-cso-delegate-pfqa": token });
    const res = await c.callTool({ name: "pfqa__whoami", arguments: {} });
    expect(textOf(res)).toMatch(/failed delegation-key-unknown/);
    expect(g.pfqa.requests).toHaveLength(0);
    const status = g.mgr.status()[0];
    expect(status.lastError).toMatch(/delegation key set unavailable/);
    expect(status.lastError).not.toContain(token);
  });
});
