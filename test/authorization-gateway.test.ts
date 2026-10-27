/**
 * Runtime authorization end to end: named bearer clients, delegation identities (signature and
 * structural mode), refusal before any upstream contact, `tools/list` filtering, control tools,
 * MRTR re-authorization, shadow mode, audit and status.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { BastionConfigSchema, type BastionConfig } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";
import { principalOf, resolveListenClients, startHttpServer } from "../src/proxy/index.js";
import { findingKind, isSealedRequestState } from "../src/security/index.js";
// @ts-expect-error -- untyped .mjs test helper
import { startToolsHttpServer } from "./helpers/tools-http-server.mjs";

interface ToolsUpstream {
  url: string;
  requests: { httpMethod: string; method?: string }[];
  calls: { name: string; arguments: unknown }[];
  close(): Promise<void>;
}

const ISSUER = "https://idp.example";
const TOKENS = { ops: "ops-token-0123456789abcdef", intern: "intern-token-0123456789abcd" };
const ENV = { BASTION_TOKEN_OPS: TOKENS.ops, BASTION_TOKEN_INTERN: TOKENS.intern };
const FILE_TOOLS = [
  { name: "read_file", inputSchema: { type: "object", properties: { path: { type: "string" } } } },
  {
    name: "delete_file",
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  },
];

const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => undefined);
});

const textOf = (res: unknown): string =>
  ((res as { content?: Array<{ type?: string; text?: string }> }).content ?? [])
    .map((c) => (c.type === "text" ? (c.text ?? "") : ""))
    .join("");

async function client(url: string, headers: Record<string, string>): Promise<Client> {
  const c = new Client({ name: "authz-test", version: "0.0.0" }, { capabilities: {} });
  await c.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers } }));
  cleanups.push(() => c.close());
  return c;
}

/** One `files` HTTP upstream (on demand) behind a Bastion with named clients and an audit file. */
async function gateway(opts: {
  authorization: Record<string, unknown>;
  security?: Record<string, unknown>;
  files?: Record<string, unknown>;
  listen?: Record<string, unknown>;
  delegation?: Record<string, unknown>;
}) {
  const files = (await startToolsHttpServer({ tools: FILE_TOOLS })) as ToolsUpstream;
  cleanups.push(() => files.close());
  const dir = await mkdtemp(join(tmpdir(), "bastion-authz-gw-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  const auditPath = join(dir, "audit.jsonl");
  const config = BastionConfigSchema.parse({
    servers: {
      files: {
        transport: "http",
        url: files.url,
        protocol: "legacy",
        connect: "onDemand",
        ...opts.files,
      },
    },
    listen: {
      mode: "http",
      authToken: "legacy-shared-token-0123456789",
      clients: {
        ops: { tokenEnv: "BASTION_TOKEN_OPS" },
        intern: { tokenEnv: "BASTION_TOKEN_INTERN" },
      },
      ...opts.listen,
    },
    authorization: { enabled: true, ...opts.authorization },
    security: opts.security ?? {},
    audit: { enabled: true, tamperEvident: true, sinks: [{ type: "file", path: auditPath }] },
    ...(opts.delegation ? { delegation: opts.delegation } : {}),
    reconnect: { auto: false },
    healthCheck: { enabled: false },
  });
  const mgr = new UpstreamManager(config);
  let closed = false;
  const closeMgr = async () => {
    if (!closed) await mgr.closeAll();
    closed = true;
  };
  cleanups.push(closeMgr);
  const listener = await startHttpServer(mgr, {
    host: "127.0.0.1",
    port: 0,
    path: "/mcp",
    authToken: config.listen.authToken,
    clients: resolveListenClients(config.listen, ENV),
  });
  cleanups.push(() => listener.close());
  const audit = async () => {
    await closeMgr();
    return (await readFile(auditPath, "utf8"))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  };
  return { files, mgr, listener, audit };
}

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

describe("named clients over HTTP (listen.clients)", () => {
  const policy = {
    rules: [
      { id: "ops-files", effect: "allow", principal: { client: "ops" }, tools: ["files__*"] },
      { id: "no-deletes", effect: "deny", principal: "*", tools: ["files__delete_file"] },
      {
        id: "intern-reads",
        effect: "allow",
        principal: { client: "intern" },
        tools: ["files__read_file"],
        args: { path: { pathWithin: "/data/public" } },
      },
      {
        id: "legacy-status",
        effect: "allow",
        principal: { client: "default" },
        tools: ["bastion__status"],
      },
    ],
  };

  it("tells clients apart by token, and refuses a wrong or missing token with 401", async () => {
    const g = await gateway({ authorization: policy });
    for (const auth of [undefined, "Bearer nope", `Bearer ${TOKENS.ops}x`, `Basic ${TOKENS.ops}`]) {
      const res = await fetch(g.listener.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          ...(auth ? { authorization: auth } : {}),
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      });
      expect(res.status).toBe(401);
    }

    const ops = await client(g.listener.url, bearer(TOKENS.ops));
    const intern = await client(g.listener.url, bearer(TOKENS.intern));
    expect(
      textOf(await ops.callTool({ name: "files__read_file", arguments: { path: "/etc/hosts" } })),
    ).toBe("ran read_file");
    const traversal = await intern.callTool({
      name: "files__read_file",
      arguments: { path: "/data/public/../secrets/key" },
    });
    expect(traversal.isError).toBe(true);
    expect(textOf(traversal)).toBe(
      'Blocked by mcp-bastion: this caller is not authorized to call "files__read_file" (no matching grant).',
    );
    expect(
      textOf(
        await intern.callTool({
          name: "files__read_file",
          arguments: { path: "/data/public/a.txt" },
        }),
      ),
    ).toBe("ran read_file");
    const del = await ops.callTool({ name: "files__delete_file", arguments: { path: "/tmp/x" } });
    expect(textOf(del)).toBe(
      'Blocked by mcp-bastion: this caller is not authorized to call "files__delete_file" (rule no-deletes).',
    );
    expect(g.files.calls.map((c) => c.name)).toEqual(["read_file", "read_file"]);

    // The legacy authToken is the client `default`.
    const legacy = await client(g.listener.url, bearer("legacy-shared-token-0123456789"));
    expect(
      (await legacy.callTool({ name: "files__read_file", arguments: { path: "/a" } })).isError,
    ).toBe(true);
    expect((await legacy.callTool({ name: "bastion__status", arguments: {} })).isError).toBeFalsy();

    const events = await g.audit();
    const byClient = (c: string) =>
      events.filter((e) => (e.authorization as { client?: string } | undefined)?.client === c);
    expect(byClient("ops").map((e) => e.decision)).toEqual(["allowed", "blocked_authorization"]);
    expect(byClient("intern").map((e) => e.decision)).toEqual(["blocked_authorization", "allowed"]);
    expect(byClient("default").map((e) => e.decision)).toEqual(["blocked_authorization"]);
    const denied = byClient("ops")[1];
    expect(denied).toMatchObject({
      server: "files",
      tool: "delete_file",
      outcome: "blocked",
      authorization: {
        effect: "deny",
        rule: "no-deletes",
        byDefault: false,
        client: "ops",
        identities: ["client"],
        violations: ["client:denied"],
      },
      frameworks: {
        nistAiRmf: expect.arrayContaining(["MANAGE"]),
        owaspLlm: ["LLM06: Excessive Agency"],
      },
    });
    expect(denied.hash).toEqual(expect.any(String)); // in the tamper-evident chain
    const text = JSON.stringify(events);
    for (const token of Object.values(TOKENS)) expect(text).not.toContain(token);
  });

  it("names a client's principal client:<name> and keeps the legacy bearer hash", () => {
    expect(principalOf({ token: "t", clientId: "ops", scopes: [] })).toBe("client:ops");
    expect(principalOf({ token: "t", clientId: "default", scopes: [] })).toMatch(
      /^bearer:[0-9a-f]{16}$/,
    );
    expect(principalOf(undefined)).toBe("http-anonymous");
  });

  it("reads tokens from the environment and refuses missing or shared ones", () => {
    const listen = { clients: { ops: { tokenEnv: "T_OPS" }, intern: { tokenEnv: "T_INTERN" } } };
    expect(resolveListenClients(listen, { T_OPS: "a", T_INTERN: "b" })).toEqual([
      { name: "ops", token: "a" },
      { name: "intern", token: "b" },
    ]);
    expect(() => resolveListenClients(listen, { T_OPS: "a" })).toThrow(/T_INTERN is not set/);
    expect(() => resolveListenClients(listen, { T_OPS: "a", T_INTERN: "" })).toThrow(
      /T_INTERN is not set/,
    );
    expect(() => resolveListenClients(listen, { T_OPS: "a", T_INTERN: "a" })).toThrow(
      /same as ops/,
    );
    expect(() =>
      resolveListenClients({ ...listen, authToken: "a" }, { T_OPS: "a", T_INTERN: "b" }),
    ).toThrow(/same as default/);
  });

  it("lets named clients alone satisfy the non-loopback bind guard", async () => {
    const mgr = new UpstreamManager(BastionConfigSchema.parse({ servers: {} }));
    cleanups.push(() => mgr.closeAll());
    await expect(startHttpServer(mgr, { host: "0.0.0.0", port: 0, path: "/mcp" })).rejects.toThrow(
      /non-loopback/,
    );
    const listener = await startHttpServer(mgr, {
      host: "0.0.0.0",
      port: 0,
      path: "/mcp",
      clients: [{ name: "ops", token: TOKENS.ops }],
    });
    await listener.close();
  });

  it("hides tools a client could never call, and keeps argument-constrained ones", async () => {
    const g = await gateway({ authorization: policy });
    const names = async (token: string) =>
      (await (await client(g.listener.url, bearer(token))).listTools()).tools.map((t) => t.name);
    expect(await names(TOKENS.ops)).toEqual(["files__read_file"]);
    expect(await names(TOKENS.intern)).toEqual(["files__read_file"]);
    expect(await names("legacy-shared-token-0123456789")).toEqual(["bastion__status"]);
  });
});

describe("refusal before any upstream contact", () => {
  it("never connects an on-demand upstream for a refused call, nor forwards its headers", async () => {
    const g = await gateway({
      authorization: {
        rules: [{ effect: "allow", principal: { client: "ops" }, tools: ["files__read_file"] }],
      },
      files: { forwardHeaders: { "x-user": "x-user" } },
    });
    const intern = await client(g.listener.url, { ...bearer(TOKENS.intern), "x-user": "alice" });
    const res = await intern.callTool({ name: "files__read_file", arguments: { path: "/a" } });
    expect(textOf(res)).toMatch(/not authorized to call "files__read_file"/);
    expect(g.files.requests).toHaveLength(0);
    const ops = await client(g.listener.url, { ...bearer(TOKENS.ops), "x-user": "alice" });
    expect(
      textOf(await ops.callTool({ name: "files__read_file", arguments: { path: "/a" } })),
    ).toBe("ran read_file");
    expect(g.files.requests.length).toBeGreaterThan(0);
    const events = await g.audit();
    expect(events.find((e) => e.decision === "blocked_authorization")).toMatchObject({
      forwardedHeaders: ["x-user"],
      authorization: { rule: null, byDefault: true, violations: ["client:no-grant"] },
    });
  });

  it("an identity asserted in arguments, headers or _meta grants nothing", async () => {
    const g = await gateway({
      authorization: {
        rules: [{ effect: "allow", principal: { client: "ops" }, tools: ["files__*"] }],
      },
    });
    const intern = await client(g.listener.url, {
      ...bearer(TOKENS.intern),
      "x-client": "ops",
      "x-forwarded-user": "ops",
    });
    const res = await intern.callTool({
      name: "files__read_file",
      arguments: { path: "/a", client: "ops", runAs: "ops" },
      _meta: { principal: "ops", client: "ops" },
    } as never);
    expect((res as { isError?: boolean }).isError).toBe(true);
    expect(g.files.calls).toHaveLength(0);
  });
});

describe("control tools", () => {
  it("are authorized under server bastion: hidden and refused without a grant", async () => {
    const g = await gateway({
      authorization: {
        rules: [
          { id: "ops-files", effect: "allow", principal: { client: "ops" }, tools: ["files__*"] },
          {
            id: "ops-status",
            effect: "allow",
            principal: { client: "ops" },
            tools: ["bastion__status"],
          },
        ],
      },
    });
    const intern = await client(g.listener.url, bearer(TOKENS.intern));
    expect((await intern.listTools()).tools).toEqual([]);
    const refused = await intern.callTool({
      name: "bastion__reconnect",
      arguments: { server: "files" },
    });
    expect(textOf(refused)).toBe(
      'Blocked by mcp-bastion: this caller is not authorized to call "bastion__reconnect" (no matching grant).',
    );
    expect(g.files.requests).toHaveLength(0);

    const ops = await client(g.listener.url, bearer(TOKENS.ops));
    expect((await ops.listTools()).tools.map((t) => t.name)).toEqual([
      "files__read_file",
      "files__delete_file",
      "bastion__status",
    ]);
    const status = JSON.parse(
      textOf(await ops.callTool({ name: "bastion__status", arguments: {} })),
    );
    expect(status.authorization).toEqual({
      enabled: true,
      default: "deny",
      rules: 2,
      action: "block",
      trustStructuralClaims: false,
      lastDenial: { rule: null, at: expect.any(String) },
    });
    expect(JSON.stringify(status)).not.toContain("ops-files"); // no policy content beyond counts

    const events = await g.audit();
    expect(events.find((e) => e.decision === "blocked_authorization")).toMatchObject({
      server: "bastion",
      tool: "reconnect",
      namespacedName: "bastion__reconnect",
      authorization: { client: "intern" },
    });
  });

  it("are unaffected while authorization is disabled", async () => {
    const g = await gateway({ authorization: { enabled: false } });
    const intern = await client(g.listener.url, bearer(TOKENS.intern));
    const names = (await intern.listTools()).tools.map((t) => t.name);
    expect(names).toContain("files__delete_file");
    expect(names).toContain("bastion__status");
    const status = JSON.parse(
      textOf(await intern.callTool({ name: "bastion__status", arguments: {} })),
    );
    expect(status).not.toHaveProperty("authorization");
  });
});

describe("shadow mode and enforcement settings", () => {
  const rules = [
    { id: "ops-files", effect: "allow", principal: { client: "ops" }, tools: ["files__*"] },
  ];

  it("observe lets a refused call through and records wouldBlock: blocked_authorization", async () => {
    const g = await gateway({
      authorization: { rules },
      security: { enforcementProfile: "observe" },
    });
    const intern = await client(g.listener.url, bearer(TOKENS.intern));
    expect(
      textOf(await intern.callTool({ name: "files__read_file", arguments: { path: "/a" } })),
    ).toBe("ran read_file");
    const ops = await client(g.listener.url, bearer(TOKENS.ops));
    await ops.callTool({ name: "files__read_file", arguments: { path: "/a" } });
    const events = await g.audit();
    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({
      decision: "allowed",
      outcome: "ok",
      wouldBlock: "blocked_authorization",
      authorization: { effect: "deny", client: "intern", violations: ["client:no-grant"] },
    });
    expect(events[1]).not.toHaveProperty("wouldBlock");
    expect(events[1]).toMatchObject({ authorization: { effect: "allow", rule: "ops-files" } });
  });

  it("an explicit onAuthorization overrides the profile", async () => {
    const g = await gateway({
      authorization: { rules },
      security: { enforcementProfile: "observe", onAuthorization: "block" },
    });
    const intern = await client(g.listener.url, bearer(TOKENS.intern));
    expect(
      (await intern.callTool({ name: "files__read_file", arguments: { path: "/a" } })).isError,
    ).toBe(true);
    expect(g.files.calls).toHaveLength(0);
  });

  it("resolves onAuthorization per profile", () => {
    const parse = (security: Record<string, unknown>) =>
      BastionConfigSchema.parse({ servers: {}, security }).security;
    expect(parse({}).onAuthorization).toBe("block");
    expect(parse({ enforcementProfile: "observe" }).onAuthorization).toBe("warn");
    expect(parse({ enforcementProfile: "strict" }).onAuthorization).toBe("block");
  });
});

describe("user and agent identities from delegate tokens", () => {
  async function keys() {
    const trusted = await generateKeyPair("ES256");
    const attacker = await generateKeyPair("ES256");
    const jwk = { ...(await exportJWK(trusted.publicKey)), kid: "k1", alg: "ES256", use: "sig" };
    return { trusted, attacker, jwk };
  }
  const token = (key: CryptoKey, claims: Record<string, unknown>, sub = "user:alice") => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT(claims)
      .setProtectedHeader({ alg: "ES256", kid: "k1", typ: "JWT" })
      .setIssuer(ISSUER)
      .setAudience("files")
      .setSubject(sub)
      .setIssuedAt(now - 5)
      .setExpirationTime(now + 100)
      .sign(key);
  };
  const delegatedRules = [
    { id: "host", effect: "allow", principal: { client: "ops" }, tools: ["*"] },
    { id: "alice-files", effect: "allow", principal: { user: "user:alice" }, tools: ["files__*"] },
    {
      id: "reader-agent",
      effect: "allow",
      principal: { agent: "reader-agent" },
      tools: ["files__read_file"],
    },
  ];

  it("signature mode: needs the user's and the current actor's grant; prior actors grant nothing", async () => {
    const k = await keys();
    const g = await gateway({
      authorization: { rules: delegatedRules },
      files: {
        forwardHeaders: { "x-delegate": "x-delegate-files" },
        delegation: {
          audience: "files",
          verify: "signature",
          issuer: ISSUER,
          algorithms: ["ES256"],
          jwks: { keys: [k.jwk] },
        },
      },
    });
    const as = async (claims: Record<string, unknown>, sub?: string) =>
      client(g.listener.url, {
        ...bearer(TOKENS.ops),
        "x-delegate-files": await token(k.trusted.privateKey, claims, sub),
      });

    const reader = await as({ act: { sub: "reader-agent" } });
    expect(textOf(await reader.callTool({ name: "files__read_file", arguments: {} }))).toBe(
      "ran read_file",
    );
    expect((await reader.callTool({ name: "files__delete_file", arguments: {} })).isError).toBe(
      true,
    );
    const fileTools = async (c: Client) =>
      (await c.listTools()).tools.map((t) => t.name).filter((n) => n.startsWith("files__"));
    expect(await fileTools(reader)).toEqual(["files__read_file"]);

    // reader-agent is only a PRIOR actor here; the current actor has no grant.
    const relayed = await as({ act: { sub: "relay-agent", act: { sub: "reader-agent" } } });
    expect((await relayed.callTool({ name: "files__read_file", arguments: {} })).isError).toBe(
      true,
    );

    // The agent's grant is not used for a user who lacks one.
    const bob = await as({ act: { sub: "reader-agent" } }, "user:bob");
    expect((await bob.callTool({ name: "files__read_file", arguments: {} })).isError).toBe(true);

    const events = await g.audit();
    const decisions = events.map((e) => [
      e.decision,
      (e.authorization as { violations: string[] }).violations,
    ]);
    expect(decisions).toEqual([
      ["allowed", []],
      ["blocked_authorization", ["agent:no-grant"]],
      ["blocked_authorization", ["agent:no-grant"]],
      ["blocked_authorization", ["user:no-grant"]],
    ]);
    expect(events[0]).toMatchObject({
      authorization: { identities: ["client", "user", "agent"], rule: "host" },
      delegation: { verified: "signature" },
    });
    expect(JSON.stringify(events)).not.toContain("user:alice"); // the subject is pseudonymised
  });

  it("an untrusted token refuses the call instead of dropping the identity", async () => {
    const k = await keys();
    const g = await gateway({
      authorization: { rules: [{ effect: "allow", principal: { client: "ops" }, tools: ["*"] }] },
      security: { onDelegation: "warn" }, // let the forged token past the delegation check
      files: {
        forwardHeaders: { "x-delegate": "x-delegate-files" },
        delegation: {
          audience: "files",
          verify: "signature",
          issuer: ISSUER,
          algorithms: ["ES256"],
          jwks: { keys: [k.jwk] },
        },
      },
    });
    const forged = await client(g.listener.url, {
      ...bearer(TOKENS.ops),
      "x-delegate-files": await token(k.attacker.privateKey, { act: { sub: "reader-agent" } }),
    });
    expect((await forged.callTool({ name: "files__read_file", arguments: {} })).isError).toBe(true);
    const listed = (await forged.listTools()).tools.map((t) => t.name);
    expect(listed.filter((n) => n.startsWith("files__"))).toEqual([]);
    expect(listed).toContain("bastion__status"); // control tools carry no delegation identity
    expect(g.files.calls).toHaveLength(0);
    const events = await g.audit();
    expect(events[0]).toMatchObject({
      decision: "blocked_authorization",
      authorization: { violations: ["user:no-grant", "agent:no-grant", "delegation:unverified"] },
    });
  });

  it("structural mode: user/agent rules are a config error unless trustStructuralClaims", () => {
    const servers = {
      files: {
        transport: "http",
        url: "http://127.0.0.1:1/mcp",
        forwardHeaders: { "x-delegate": "x-delegate-files" },
        delegation: { audience: "files" },
      },
      other: { transport: "http", url: "http://127.0.0.1:2/mcp" },
    };
    const parse = (authorization: Record<string, unknown>) =>
      BastionConfigSchema.safeParse({ servers, listen: { mode: "http" }, authorization });
    const userRule = { effect: "allow", principal: { user: "user:alice" }, tools: ["files__*"] };
    const bad = parse({ enabled: true, rules: [userRule] });
    expect(bad.success).toBe(false);
    expect(JSON.stringify(bad.error?.issues)).toMatch(/not signature-verified/);
    expect(parse({ enabled: true, rules: [{ ...userRule, tools: ["*"] }] }).success).toBe(false);
    expect(parse({ enabled: true, rules: [{ ...userRule, tools: ["fil*"] }] }).success).toBe(false);
    // Only the other upstream's tools: fine.
    expect(parse({ enabled: true, rules: [{ ...userRule, tools: ["other__*"] }] }).success).toBe(
      true,
    );
    // Client rules are fine on a structural upstream.
    expect(
      parse({
        enabled: true,
        rules: [{ effect: "allow", principal: { client: "stdio" }, tools: ["*"] }],
      }).success,
    ).toBe(true);
    expect(parse({ enabled: true, trustStructuralClaims: true, rules: [userRule] }).success).toBe(
      true,
    );
  });

  it("structural mode with trustStructuralClaims uses the claims", async () => {
    const k = await keys();
    const g = await gateway({
      authorization: { trustStructuralClaims: true, rules: delegatedRules },
      files: {
        forwardHeaders: { "x-delegate": "x-delegate-files" },
        delegation: { audience: "files" },
      },
    });
    const reader = await client(g.listener.url, {
      ...bearer(TOKENS.ops),
      "x-delegate-files": await token(k.attacker.privateKey, { act: { sub: "reader-agent" } }),
    });
    expect(textOf(await reader.callTool({ name: "files__read_file", arguments: {} }))).toBe(
      "ran read_file",
    );
    expect((await reader.callTool({ name: "files__delete_file", arguments: {} })).isError).toBe(
      true,
    );
  });
});

describe("MRTR retries are re-authorized", () => {
  const modernStdio = fileURLToPath(new URL("./fixtures/modern-server.mjs", import.meta.url));

  it("every round of an input_required exchange is checked again", async () => {
    const config: BastionConfig = BastionConfigSchema.parse({
      servers: { up: { command: process.execPath, args: [modernStdio] } },
      listen: {
        clients: { teller: { tokenEnv: "T_TELLER" }, intruder: { tokenEnv: "T_INTRUDER" } },
      },
      authorization: {
        enabled: true,
        rules: [
          {
            id: "small-transfers",
            effect: "allow",
            principal: { client: "teller" },
            tools: ["up__confirm_transfer"],
            args: { msg: { in: ["small"] } },
          },
        ],
      },
      reconnect: { auto: false },
      healthCheck: { enabled: false },
    });
    const mgr = new UpstreamManager(config);
    cleanups.push(() => mgr.closeAll());
    await mgr.connectAll();
    const round = (await mgr.callUpstreamTool(
      "up__confirm_transfer",
      { msg: "small" },
      { client: "teller" },
    )) as {
      requestState?: string;
      resultType?: string;
    };
    expect(isSealedRequestState(round.requestState)).toBe(true);
    const retry = {
      inputResponses: { confirm: { action: "accept", content: { ok: true, client: "teller" } } },
      requestState: round.requestState,
    };
    // Same sealed state, but an argument outside the grant on the retry.
    const widened = await mgr.callUpstreamTool(
      "up__confirm_transfer",
      { msg: "large" },
      { client: "teller", ...retry },
    );
    expect(textOf(widened)).toMatch(/not authorized to call "up__confirm_transfer"/);
    // Another client presenting the continuation (and naming the teller in its input responses).
    const other = await mgr.callUpstreamTool(
      "up__confirm_transfer",
      { msg: "small" },
      { client: "intruder", ...retry },
    );
    expect(textOf(other)).toMatch(/not authorized to call "up__confirm_transfer"/);
    // The honest retry completes.
    const done = await mgr.callUpstreamTool(
      "up__confirm_transfer",
      { msg: "small" },
      { client: "teller", ...retry },
    );
    expect(textOf(done)).toContain("transfer done");
  });
});

describe("authorization config", () => {
  const parse = (authorization: unknown, listen: Record<string, unknown> = {}) =>
    BastionConfigSchema.safeParse({
      servers: {},
      listen: { mode: "http", ...listen },
      authorization,
    });
  const allow = { effect: "allow", principal: "*", tools: ["a__b"] };

  it("is off by default and numbers rules without ids", () => {
    const c = BastionConfigSchema.parse({ servers: {} });
    expect(c.authorization).toEqual({
      enabled: false,
      default: "deny",
      trustStructuralClaims: false,
      rules: [],
    });
    const r = parse({ enabled: true, rules: [allow, { ...allow, id: "named" }, allow] });
    expect(r.success && r.data.authorization.rules.map((x) => x.id)).toEqual([
      "rule-1",
      "named",
      "rule-3",
    ]);
  });

  it.each([
    ["interior wildcard", { rules: [{ ...allow, tools: ["*__delete_*"] }] }],
    ["empty tools", { rules: [{ ...allow, tools: [] }] }],
    ["two principal kinds", { rules: [{ ...allow, principal: { client: "stdio", user: "u" } }] }],
    ["empty principal", { rules: [{ ...allow, principal: {} }] }],
    ["unknown principal kind", { rules: [{ ...allow, principal: { role: "admin" } }] }],
    ["unknown client", { rules: [{ ...allow, principal: { client: "ghost" } }] }],
    [
      "duplicate ids",
      {
        rules: [
          { ...allow, id: "x" },
          { ...allow, id: "x" },
        ],
      },
    ],
    ["empty constraint", { rules: [{ ...allow, args: { env: {} } }] }],
    ["unknown constraint", { rules: [{ ...allow, args: { env: { regex: ".*" } } }] }],
    ["relative pathWithin", { rules: [{ ...allow, args: { p: { pathWithin: "data" } } }] }],
    ["min above max", { rules: [{ ...allow, args: { n: { min: 5, max: 1 } } }] }],
    ["empty in", { rules: [{ ...allow, args: { env: { in: [] } } }] }],
    ["object equals", { rules: [{ ...allow, args: { env: { equals: { a: 1 } } } }] }],
    ["unknown key", { rules: [allow], mode: "strict" }],
  ])("rejects %s", (_label, authorization) => {
    expect(parse({ enabled: true, ...authorization }).success).toBe(false);
  });

  it("accepts named, default, stdio and anonymous clients", () => {
    const rule = (client: string) => ({ ...allow, principal: { client } });
    const listen = { authToken: "t", clients: { ops: { tokenEnv: "T_OPS" } } };
    for (const c of ["ops", "default", "stdio", "anonymous"]) {
      expect(parse({ enabled: true, rules: [rule(c)] }, listen).success).toBe(true);
    }
    expect(parse({ enabled: true, rules: [rule("default")] }).success).toBe(false); // no authToken
  });

  it("rejects reserved and malformed client names and env var names", () => {
    for (const clients of [
      { default: { tokenEnv: "T" } },
      { stdio: { tokenEnv: "T" } },
      { "bad name": { tokenEnv: "T" } },
      { ops: { tokenEnv: "not-an-env" } },
      { ops: { tokenEnv: "T", token: "inline" } },
    ]) {
      expect(parse({}, { clients }).success).toBe(false);
    }
  });

  it("reserves the server name bastion for control tools while authorization is enabled", () => {
    const servers = { bastion: { command: "node" } };
    expect(
      BastionConfigSchema.safeParse({ servers, authorization: { enabled: true } }).success,
    ).toBe(false);
    expect(BastionConfigSchema.safeParse({ servers }).success).toBe(true);
  });

  it("refuses to forward the incoming authorization header when named clients are set", () => {
    const r = BastionConfigSchema.safeParse({
      servers: {
        up: {
          transport: "http",
          url: "http://127.0.0.1:1/mcp",
          forwardHeaders: { authorization: "authorization" },
        },
      },
      listen: { mode: "http", clients: { ops: { tokenEnv: "T" } } },
    });
    expect(r.success).toBe(false);
  });
});

describe("finding kinds (H1)", () => {
  it.each([
    ["tool-definition-changed", "deterministic"],
    ["undeclared-parameter", "deterministic"],
    ["cross-server-exfil", "deterministic"],
    ["delegation-subject-mixing", "deterministic"],
    ["requeststate-forged", "deterministic"],
    ["header-body-mismatch", "deterministic"],
    ["instruction-override", "heuristic"],
    ["hidden-characters", "heuristic"],
    ["command-injection", "heuristic"],
    ["secret-redacted", "heuristic"],
    ["mrtr-credential-elicitation", "heuristic"],
    ["mrtr-elicitation-secret-access", "heuristic"],
    ["error-privilege-steering", "heuristic"],
    ["some-future-rule", "heuristic"],
  ])("%s is %s", (rule, kind) => {
    expect(findingKind(rule)).toBe(kind);
  });
});
