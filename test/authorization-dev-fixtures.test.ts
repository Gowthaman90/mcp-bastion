/**
 * Replays the 12 pre-registered `authorization` dev fixtures (mcp-defense-bench, tag
 * `authorization-prereg-2026-10-26`) through a real Bastion HTTP gateway.
 *
 * Mapping from the fixture to a deployment:
 * - each `<server>__*` tool group becomes one HTTP upstream (connected on demand, so "no upstream
 *   contact" is observable);
 * - `caller.client` is a `listen.clients` bearer token;
 * - `caller.user` / `caller.agent` / `caller.priorAgents` become an ES256-signed delegate token per
 *   upstream (`sub`, `act.sub`, nested `act`), verified in signature mode;
 * - `request.headers` are sent as HTTP headers and `request.meta` as `_meta`;
 * - the policy's rules are used as they are. Bastion always authenticates a transport client, so a
 *   fixture whose caller has no client is served through a host client `agent-host` granted every
 *   tool (`principal: {client: "agent-host"}, tools: ["*"]`): it adds a permit for the host and
 *   removes none, so the user and agent grants still decide.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { BastionConfigSchema } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";
import { resolveListenClients, startHttpServer } from "../src/proxy/index.js";
// @ts-expect-error -- untyped .mjs test helper
import { startToolsHttpServer } from "./helpers/tools-http-server.mjs";

interface FixtureCall {
  type: "authorized-call";
  separator: string;
  tools: { name: string; description?: string; inputSchema?: unknown }[];
  policy: { default: "deny" | "allow"; rules: Record<string, unknown>[] };
  caller: {
    authenticatedBy: string;
    client?: string;
    user?: string;
    agent?: string;
    priorAgents?: string[];
  };
  request: {
    method: "tools/call";
    name: string;
    arguments: Record<string, unknown>;
    headers?: Record<string, string>;
    meta?: Record<string, unknown>;
    retryOf?: string;
    inputResponses?: Record<string, unknown>;
  };
}
interface Fixture {
  vector: string;
  id: string;
  fixture: FixtureCall;
  benignControl: FixtureCall;
  intent: { violates: string[] };
}
interface ToolsUpstream {
  url: string;
  requests: { httpMethod: string; method?: string }[];
  calls: { name: string; arguments: unknown }[];
  close(): Promise<void>;
}

const FIXTURES = fileURLToPath(new URL("./fixtures/authorization-dev/", import.meta.url));
const ISSUER = "https://idp.forge.test";
const HOST = "agent-host";

async function loadFixtures(): Promise<{ file: string; data: Fixture }[]> {
  const out: { file: string; data: Fixture }[] = [];
  for (const vector of (await readdir(FIXTURES, { withFileTypes: true })).filter((d) =>
    d.isDirectory(),
  )) {
    for (const file of (await readdir(join(FIXTURES, vector.name)))
      .filter((f) => f.endsWith(".json"))
      .sort()) {
      const data = JSON.parse(await readFile(join(FIXTURES, vector.name, file), "utf8")) as Fixture;
      out.push({ file: `${vector.name}/${file}`, data });
    }
  }
  return out;
}
const fixtures = await loadFixtures();

const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => undefined);
});

function textOf(res: unknown): string {
  const content = (res as { content?: Array<{ type?: string; text?: string }> }).content ?? [];
  return content.map((c) => (c.type === "text" ? (c.text ?? "") : "")).join("");
}

/** The client name a fixture caller is served as. */
const clientOfCaller = (caller: FixtureCall["caller"]) => caller.client ?? HOST;
const envName = (client: string) =>
  `BASTION_TEST_TOKEN_${client.replace(/[^A-Za-z0-9]/g, "_").toUpperCase()}`;

/** Start one gateway for a fixture's tools and policy (shared by its attack and benign control). */
async function startGateway(f: FixtureCall, callers: FixtureCall["caller"][]) {
  const sep = f.separator;
  const byServer = new Map<string, FixtureCall["tools"]>();
  for (const tool of f.tools) {
    const i = tool.name.indexOf(sep);
    const server = tool.name.slice(0, i);
    byServer.set(server, [
      ...(byServer.get(server) ?? []),
      { ...tool, name: tool.name.slice(i + sep.length) },
    ]);
  }
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256", use: "sig" };

  const upstreams = new Map<string, ToolsUpstream>();
  const servers: Record<string, unknown> = {};
  for (const [server, tools] of byServer) {
    const up = (await startToolsHttpServer({ tools })) as ToolsUpstream;
    cleanups.push(() => up.close());
    upstreams.set(server, up);
    servers[server] = {
      transport: "http",
      url: up.url,
      protocol: "legacy",
      connect: "onDemand",
      forwardHeaders: { "x-delegate": `x-delegate-${server}` },
      onMissingForwardedHeader: "omit",
      delegation: {
        audience: server,
        verify: "signature",
        issuer: ISSUER,
        algorithms: ["ES256"],
        jwks: { keys: [jwk] },
      },
    };
  }

  const clientNames = new Set<string>(callers.map(clientOfCaller));
  for (const rule of f.policy.rules) {
    const p = rule.principal as Record<string, unknown> | string;
    if (typeof p === "object" && typeof p.client === "string") clientNames.add(p.client);
  }
  const rules: Record<string, unknown>[] = f.policy.rules.map((r, i) => ({
    id: `r${i + 1}`,
    ...r,
  }));
  if (callers.some((c) => c.client === undefined)) {
    rules.push({ id: "host-client", effect: "allow", principal: { client: HOST }, tools: ["*"] });
  }
  const env: Record<string, string> = {};
  for (const name of clientNames)
    env[envName(name)] = `token-for-${name}-${Math.random().toString(36).slice(2)}`;

  const dir = await mkdtemp(join(tmpdir(), "bastion-authz-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  const auditPath = join(dir, "audit.jsonl");
  const config = BastionConfigSchema.parse({
    servers,
    namespace: { separator: sep },
    listen: {
      mode: "http",
      clients: Object.fromEntries([...clientNames].map((n) => [n, { tokenEnv: envName(n) }])),
    },
    authorization: { enabled: true, default: f.policy.default, rules },
    audit: { enabled: true, sinks: [{ type: "file", path: auditPath }] },
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
    clients: resolveListenClients(config.listen, env),
  });
  cleanups.push(() => listener.close());

  /** Connect as a fixture caller: its bearer token, its signed delegate tokens, its headers. */
  async function connect(call: FixtureCall): Promise<Client> {
    const headers: Record<string, string> = { ...(call.request.headers ?? {}) };
    headers.authorization = `Bearer ${env[envName(clientOfCaller(call.caller))]}`;
    if (call.caller.user !== undefined || call.caller.agent !== undefined) {
      for (const server of byServer.keys()) {
        headers[`x-delegate-${server}`] = await delegateToken(privateKey, server, call.caller);
      }
    }
    const c = new Client({ name: "fixture-caller", version: "0.0.0" }, { capabilities: {} });
    await c.connect(
      new StreamableHTTPClientTransport(new URL(listener.url), { requestInit: { headers } }),
    );
    cleanups.push(() => c.close());
    return c;
  }

  const audit = async () => {
    await closeMgr();
    return (await readFile(auditPath, "utf8"))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  };
  return { upstreams, connect, audit };
}

async function delegateToken(
  key: CryptoKey,
  aud: string,
  caller: FixtureCall["caller"],
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  // Current actor outermost, prior actors nested inside it (RFC 8693 §4.1).
  let act: Record<string, unknown> | undefined;
  for (const prior of [...(caller.priorAgents ?? [])].reverse())
    act = { sub: prior, ...(act ? { act } : {}) };
  if (caller.agent !== undefined) act = { sub: caller.agent, ...(act ? { act } : {}) };
  const claims: Record<string, unknown> = act ? { act } : {};
  const jwt = new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", kid: "k1", typ: "JWT" })
    .setIssuer(ISSUER)
    .setAudience(aud)
    .setIssuedAt(now - 5)
    .setExpirationTime(now + 300);
  if (caller.user !== undefined) jwt.setSubject(caller.user);
  return jwt.sign(key);
}

function callParams(call: FixtureCall): Record<string, unknown> {
  const r = call.request;
  return {
    name: r.name,
    arguments: r.arguments,
    ...(r.meta ? { _meta: r.meta } : {}),
    ...(r.inputResponses ? { inputResponses: r.inputResponses } : {}),
  };
}

describe("authorization dev fixtures (mcp-defense-bench, pre-registered)", () => {
  it("loads all 12 dev fixtures", () => {
    expect(fixtures).toHaveLength(12);
    for (const { data } of fixtures) {
      expect(data.fixture.type).toBe("authorized-call");
      expect(data.benignControl.type).toBe("authorized-call");
    }
  });

  it.each(fixtures.map((f) => [f.file, f.data] as const))(
    "%s: attack refused before upstream contact, benign control allowed",
    async (_file, fx) => {
      const attack = fx.fixture;
      const benign = fx.benignControl;
      expect(benign.policy).toEqual(attack.policy);
      const g = await startGateway(attack, [attack.caller, benign.caller]);
      const target = attack.request.name.slice(0, attack.request.name.indexOf(attack.separator));
      const upstream = g.upstreams.get(target)!;

      // Attack: refused, and the target upstream is never contacted (not even an on-demand connect).
      const bad = await g.connect(attack);
      const refused = await bad.callTool(callParams(attack) as never);
      expect(refused.isError, textOf(refused)).toBe(true);
      expect(textOf(refused)).toMatch(
        new RegExp(
          `^Blocked by mcp-bastion: this caller is not authorized to call "${attack.request.name}" \\(`,
        ),
      );
      expect(upstream.requests).toHaveLength(0);
      for (const up of g.upstreams.values()) expect(up.calls).toHaveLength(0);
      if (fx.intent.violates.every((v) => v.endsWith(":no-grant") || v.endsWith(":denied"))) {
        const listed = (await bad.listTools()).tools.map((t) => t.name);
        expect(listed).not.toContain(attack.request.name);
      }

      // Benign control: allowed and forwarded with its arguments.
      const good = await g.connect(benign);
      const ok = await good.callTool(callParams(benign) as never);
      expect(ok.isError, textOf(ok)).toBeFalsy();
      const originalName = benign.request.name.slice(target.length + benign.separator.length);
      expect(textOf(ok)).toBe(`ran ${originalName}`);
      expect(upstream.calls).toEqual([{ name: originalName, arguments: benign.request.arguments }]);
      expect((await good.listTools()).tools.map((t) => t.name)).toContain(benign.request.name);

      // Audit: the refusal names exactly the pre-registered violations.
      const events = await g.audit();
      const blocked = events.filter((e) => e.decision === "blocked_authorization");
      expect(blocked).toHaveLength(1);
      expect(blocked[0]).toMatchObject({
        namespacedName: attack.request.name,
        outcome: "blocked",
        authorization: { effect: "deny", client: clientOfCaller(attack.caller) },
        frameworks: { owaspLlm: expect.arrayContaining(["LLM06: Excessive Agency"]) },
      });
      expect((blocked[0].authorization as { violations: string[] }).violations).toEqual(
        fx.intent.violates,
      );
      const allowed = events.filter((e) => e.decision === "allowed");
      expect(allowed).toHaveLength(1);
      expect(allowed[0]).toMatchObject({ authorization: { effect: "allow", violations: [] } });
    },
  );
});
