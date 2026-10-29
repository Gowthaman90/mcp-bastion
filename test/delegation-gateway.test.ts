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
    act: { sub: "orchestrator-agent" },
    ...extra,
  };
  return `${b64({ typ: "JWT", alg: "HS256" })}.${b64(payload)}.${b64(randomUUID())}`;
}

function textOf(res: unknown): string {
  const content = (res as { content?: Array<{ type?: string; text?: string }> }).content ?? [];
  return content.map((c) => (c.type === "text" ? (c.text ?? "") : "")).join("");
}

/** Bastion config for two sub-agents, each with its own delegate header and audience. */
function rawConfig(filesUrl: string, ticketsUrl: string, extra: Record<string, unknown> = {}) {
  const server = (url: string, name: string) => ({
    transport: "http",
    url,
    protocol: "legacy",
    connect: "onDemand",
    forwardHeaders: { "x-user-identity": `x-delegate-${name}` },
    delegation: {
      audience: name,
      maxLifetimeSeconds: 120,
      allowedActors: ["orchestrator-agent"],
      maxChainDepth: 2,
    },
  });
  return {
    servers: { files: server(filesUrl, "files"), tickets: server(ticketsUrl, "tickets") },
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
  const c = new Client({ name: "orchestrator", version: "0.0.0" }, { capabilities: {} });
  await c.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers } }));
  cleanups.push(() => c.close());
  return c;
}

async function startGateway(extra: Record<string, unknown> = {}): Promise<{
  files: UpstreamFixture;
  tickets: UpstreamFixture;
  mgr: UpstreamManager;
  listener: HttpListener;
}> {
  const files = (await startIdentityHttpServer()) as UpstreamFixture;
  const tickets = (await startIdentityHttpServer()) as UpstreamFixture;
  cleanups.push(
    () => files.close(),
    () => tickets.close(),
  );
  const raw = rawConfig(files.url, tickets.url, extra) as { security?: Record<string, unknown> };
  const mgr = new UpstreamManager(
    BastionConfigSchema.parse({
      ...raw,
      // The fixture echoes the forwarded token in its result; keep it readable (DLP would redact a JWT).
      security: { redactResponseSecrets: false, ...(raw.security ?? {}) },
      reconnect: { auto: false },
      healthCheck: { enabled: false },
    }),
  );
  cleanups.push(() => mgr.closeAll());
  const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
  cleanups.push(() => listener.close());
  return { files, tickets, mgr, listener };
}

describe("delegation checks in the gateway", () => {
  it("serves a request whose tokens all name one user", async () => {
    const { files, mgr, listener } = await startGateway();
    const token = delegate("files", "user:priya");
    const c = await client(listener.url, {
      "x-delegate-files": token,
      "x-delegate-tickets": delegate("tickets", "user:priya"),
    });
    const res = await c.callTool({ name: "files__whoami", arguments: {} });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(textOf(res)).toBe(`identity=${token} n=`);
    expect(files.requests.some((q) => q.identity === token)).toBe(true);
    expect(mgr.status().find((s) => s.name === "files")?.delegation).toEqual({
      mode: "structural",
      audience: "files",
      lastViolation: null,
    });
  });

  it("blocks a request mixing two users before any upstream request (call and list)", async () => {
    const { files, tickets, mgr, listener } = await startGateway();
    const c = await client(listener.url, {
      "x-delegate-files": delegate("files", "user:priya"),
      "x-delegate-tickets": delegate("tickets", "user:raj"),
    });
    const res = await c.callTool({ name: "files__whoami", arguments: {} });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toBe(
      'Blocked by mcp-bastion: the delegation token for "files" failed delegation-subject-mixing, ' +
        'so "files__whoami" was not forwarded.',
    );
    const names = (await c.listTools()).tools.map((t) => t.name);
    expect(names.filter((n) => !n.startsWith("bastion__"))).toEqual([]);
    expect(files.requests).toHaveLength(0);
    expect(tickets.requests).toHaveLength(0);
    const status = mgr.status().find((s) => s.name === "files")!;
    expect(status.state).toBe("idle");
    expect(status.delegation?.lastViolation?.rule).toBe("delegation-subject-mixing");
    expect(Object.keys(status.delegation!.lastViolation!)).toEqual(["rule", "at"]);
  });

  it("does not list a shared, already-connected upstream to a blocked request", async () => {
    const { files, listener } = await startGateway();
    const good = await client(listener.url, { "x-delegate-files": delegate("files", "u:a") });
    expect((await good.listTools()).tools.map((t) => t.name)).toContain("files__whoami");
    const before = files.requests.length;
    const wrongAudience = await client(listener.url, {
      "x-delegate-files": delegate("tickets", "u:a"),
    });
    expect((await wrongAudience.listTools()).tools.map((t) => t.name)).not.toContain(
      "files__whoami",
    );
    const res = await wrongAudience.callTool({ name: "files__whoami", arguments: {} });
    expect(textOf(res)).toMatch(/failed delegation-audience-mismatch/);
    expect(files.requests.length).toBe(before);
  });

  it("the fetch backstop refuses a blocked token on a reconnect made inside the request", async () => {
    const { files, listener } = await startGateway();
    const c = await client(listener.url, {
      "x-delegate-files": delegate("mcp-bastion", "user:priya"), // passthrough
    });
    const res = await c.callTool({ name: "bastion__reconnect", arguments: { server: "files" } });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/delegation-passthrough/);
    expect(files.requests).toHaveLength(0);
  });

  it("chain depth is warn-only by default: the call goes ahead and status notes the rule", async () => {
    const { files, mgr, listener } = await startGateway();
    const act = { sub: "orchestrator-agent", act: { sub: "planner", act: { sub: "helper" } } };
    const token = delegate("files", "user:priya", { act });
    const c = await client(listener.url, { "x-delegate-files": token });
    const res = await c.callTool({ name: "files__whoami", arguments: {} });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(files.requests.some((q) => q.identity === token)).toBe(true);
    const status = mgr.status().find((s) => s.name === "files")!;
    expect(status.delegation?.lastViolation?.rule).toBe("delegation-chain-depth");
  });
});

describe("delegation checks in shadow mode ('observe')", () => {
  it("lets a mixed-user request through and audits it as wouldBlock: blocked_delegation", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bastion-deleg-shadow-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const auditPath = join(dir, "audit.jsonl");
    const { files, mgr, listener } = await startGateway({
      security: { enforcementProfile: "observe" },
      audit: { enabled: true, sinks: [{ type: "file", path: auditPath }] },
    });

    // Chain depth only: 'balanced' warns on it too, so no wouldBlock.
    const act = { sub: "orchestrator-agent", act: { sub: "planner", act: { sub: "helper" } } };
    const deep = await client(listener.url, {
      "x-delegate-files": delegate("files", "user:priya", { act }),
    });
    expect((await deep.callTool({ name: "files__whoami", arguments: {} })).isError).toBeFalsy();

    // Two users in one request: 'balanced' would block this before any upstream contact.
    const mixed = await client(listener.url, {
      "x-delegate-files": delegate("files", "user:priya"),
      "x-delegate-tickets": delegate("tickets", "user:raj"),
    });
    const res = await mixed.callTool({ name: "files__whoami", arguments: {} });
    expect(res.isError, textOf(res)).toBeFalsy();
    expect(files.requests.length).toBeGreaterThan(0);

    await mgr.closeAll();
    const events = (await readFile(auditPath, "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as { decision: string; wouldBlock?: string });
    expect(events.map((e) => e.decision)).toEqual(["allowed", "allowed"]);
    expect(events[0]).not.toHaveProperty("wouldBlock");
    expect(events[1].wouldBlock).toBe("blocked_delegation");
  });
});

describe("delegation checks end to end (CLI)", () => {
  it("audits a blocked mixed-user request with a hashed subject and records no token or raw sub", async () => {
    const files = (await startIdentityHttpServer()) as UpstreamFixture;
    const tickets = (await startIdentityHttpServer()) as UpstreamFixture;
    cleanups.push(
      () => files.close(),
      () => tickets.close(),
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
        rawConfig(files.url, tickets.url, {
          security: { redactResponseSecrets: false }, // the fixture echoes the token in its result
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
      goodFiles: delegate("files", priya),
      goodTickets: delegate("tickets", priya),
      mixedFiles: delegate("files", priya),
      mixedTickets: delegate("tickets", raj),
    };
    const good = await client(url, {
      "x-delegate-files": tokens.goodFiles,
      "x-delegate-tickets": tokens.goodTickets,
    });
    const mixed = await client(url, {
      "x-delegate-files": tokens.mixedFiles,
      "x-delegate-tickets": tokens.mixedTickets,
    });

    const blocked = await mixed.callTool({ name: "files__whoami", arguments: { n: 1 } });
    expect(textOf(blocked)).toMatch(/failed delegation-subject-mixing/);
    expect(files.requests).toHaveLength(0);
    expect(tickets.requests).toHaveLength(0);

    const ok = await good.callTool({ name: "files__whoami", arguments: { n: 2 } });
    expect(textOf(ok)).toBe(`identity=${tokens.goodFiles} n=2`);
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
      server: "files",
      tool: "whoami",
      namespacedName: "files__whoami",
      outcome: "blocked",
      forwardedHeaders: ["x-user-identity"],
      delegation: {
        subject: hashed,
        issuer: ISSUER,
        audience: "files",
        actors: ["orchestrator-agent"],
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

    const files = (await startIdentityHttpServer()) as UpstreamFixture;
    cleanups.push(() => files.close());
    const dir = await mkdtemp(join(tmpdir(), "bastion-sig-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const auditPath = join(dir, "audit.jsonl");
    const mgr = new UpstreamManager(
      BastionConfigSchema.parse({
        servers: {
          files: {
            transport: "http",
            url: files.url,
            protocol: "legacy",
            connect: "onDemand",
            forwardHeaders: { "x-user-identity": "x-delegate-files" },
            delegation: {
              audience: "files",
              verify: "signature",
              issuer: ISSUER,
              algorithms: ["ES256"],
              jwksUrl,
              maxLifetimeSeconds: 120,
            },
          },
        },
        listen: { mode: "http" },
        security: { redactResponseSecrets: false }, // the fixture echoes the token in its result
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
      new SignJWT({ sub, act: { sub: "orchestrator-agent" } })
        .setProtectedHeader({ alg: "ES256", kid: "spire-1", typ: "JWT" })
        .setIssuer(ISSUER)
        .setAudience("files")
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
      files,
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
    const bad = await client(g.listener.url, { "x-delegate-files": forged });
    const blocked = await bad.callTool({ name: "files__whoami", arguments: {} });
    expect(textOf(blocked)).toBe(
      'Blocked by mcp-bastion: the delegation token for "files" failed ' +
        'delegation-signature-invalid, so "files__whoami" was not forwarded.',
    );
    expect((await bad.listTools()).tools.map((t) => t.name)).not.toContain("files__whoami");
    expect(g.files.requests).toHaveLength(0);

    const token = await g.sign(g.trusted.privateKey);
    const good = await client(g.listener.url, { "x-delegate-files": token });
    const ok = await good.callTool({ name: "files__whoami", arguments: {} });
    expect(ok.isError, textOf(ok)).toBeFalsy();
    expect(textOf(ok)).toBe(`identity=${token} n=`);
    expect(g.jwksHits).toHaveLength(1); // fetched once, cached across requests
    expect(g.mgr.status()[0].delegation).toMatchObject({
      mode: "signature",
      audience: "files",
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
    const c = await client(g.listener.url, { "x-delegate-files": token });
    const res = await c.callTool({ name: "files__whoami", arguments: {} });
    expect(textOf(res)).toMatch(/failed delegation-key-unknown/);
    expect(g.files.requests).toHaveLength(0);
    const status = g.mgr.status()[0];
    expect(status.lastError).toMatch(/delegation key set unavailable/);
    expect(status.lastError).not.toContain(token);
  });
});
