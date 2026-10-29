/**
 * Every `tools/call` that passed authorization and then failed leaves one audit event: a failed
 * on-demand connect (e.g. HTTP 401 for the caller's forwarded credentials), an upstream that is not
 * connected, and an MRTR retry whose `requestState` fails custody.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { parseJsonl, verifyAuditLog } from "../src/audit/index.js";
import { BastionConfigSchema } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";
import { logger } from "../src/observability/index.js";
import { resolveListenClients, startHttpServer } from "../src/proxy/index.js";
// @ts-expect-error -- untyped .mjs test helper
import { startIdentityHttpServer } from "./helpers/identity-http-server.mjs";

const TOKEN = "orchestrator-token-0123456789abcdef";
const ENV = { BASTION_TOKEN_ORCHESTRATOR: TOKEN };
const modernStdio = fileURLToPath(new URL("./fixtures/modern-server.mjs", import.meta.url));
const mockStdio = fileURLToPath(new URL("./fixtures/mock-server.mjs", import.meta.url));

const textOf = (res: unknown) =>
  ((res as { content?: Array<{ type?: string; text?: string }> }).content ?? [])
    .map((c) => (c.type === "text" ? (c.text ?? "") : ""))
    .join("");

const cleanups: (() => Promise<unknown>)[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => undefined);
  vi.restoreAllMocks();
});

async function auditDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "bastion-failed-call-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function readEvents(path: string): Promise<Record<string, unknown>[]> {
  const text = await readFile(path, "utf8").catch(() => "");
  return text
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>)
    .filter((e) => !("recordType" in e));
}

/** A gateway in front of an on-demand upstream that answers 401 to identities starting "invalid". */
async function gateway(extra: Record<string, unknown> = {}) {
  const upstream = await startIdentityHttpServer();
  cleanups.push(() => upstream.close());
  const dir = await auditDir();
  const log = join(dir, "audit.jsonl");
  const config = BastionConfigSchema.parse({
    servers: {
      files: {
        transport: "http",
        url: upstream.url,
        protocol: "legacy",
        forwardHeaders: { "x-user-identity": "x-delegate-files" },
        connect: "onDemand",
      },
    },
    listen: { mode: "http", clients: { orchestrator: { tokenEnv: "BASTION_TOKEN_ORCHESTRATOR" } } },
    reconnect: { auto: false },
    healthCheck: { enabled: false },
    audit: { enabled: true, tamperEvident: true, sinks: [{ type: "file", path: log }] },
    authorization: {
      enabled: true,
      rules: [
        {
          id: "orchestrator-files",
          effect: "allow",
          principal: { client: "orchestrator" },
          tools: ["files__*"],
        },
      ],
    },
    ...extra,
  });
  const mgr = new UpstreamManager(config);
  let closed = false;
  const closeMgr = async () => {
    if (closed) return;
    closed = true;
    await mgr.closeAll();
  };
  cleanups.push(closeMgr);
  await mgr.connectAll();
  const listener = await startHttpServer(mgr, {
    host: "127.0.0.1",
    port: 0,
    path: "/mcp",
    clients: resolveListenClients(config.listen, ENV),
  });
  cleanups.push(() => listener.close());
  const events = async () => {
    await closeMgr();
    return readEvents(log);
  };
  return { upstream, mgr, listener, log, events };
}

async function caller(url: string, identity: string): Promise<Client> {
  const c = new Client({ name: "orchestrator", version: "0.0.0" }, { capabilities: {} });
  await c.connect(
    new StreamableHTTPClientTransport(new URL(url), {
      requestInit: { headers: { authorization: `Bearer ${TOKEN}`, "x-delegate-files": identity } },
    }),
  );
  cleanups.push(() => c.close());
  return c;
}

describe("a call that fails while connecting an on-demand upstream is audited", () => {
  it("writes one event for a first-contact HTTP 401, with no credential in it", async () => {
    const g = await gateway();
    const bad = await caller(g.listener.url, "invalid-token-5f2a9c");
    const res = await bad.callTool({ name: "files__whoami", arguments: {} });
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/authentication failed/);
    expect(g.mgr.status()[0].state).toBe("idle");

    const events = await g.events();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      server: "files",
      tool: "whoami",
      namespacedName: "files__whoami",
      decision: "allowed",
      outcome: "error",
      forwardedHeaders: ["x-user-identity"],
      authorization: { effect: "allow", rule: "orchestrator-files", client: "orchestrator" },
    });
    expect(JSON.stringify(events)).not.toContain("invalid-token-5f2a9c");
    expect(JSON.stringify(events)).not.toContain(TOKEN);
  });

  it("records the same fields as the same 401 on a connected upstream", async () => {
    const g = await gateway();
    const bad = await caller(g.listener.url, "invalid-first");
    await bad.callTool({ name: "files__whoami", arguments: {} }); // first contact: connect fails
    const good = await caller(g.listener.url, "user-a-token");
    expect(textOf(await good.callTool({ name: "files__whoami", arguments: {} }))).toMatch(
      /identity=user-a-token/,
    );
    const bad2 = await caller(g.listener.url, "invalid-second");
    expect((await bad2.callTool({ name: "files__whoami", arguments: {} })).isError).toBe(true);

    const events = await g.events();
    expect(events.map((e) => e.outcome)).toEqual(["error", "ok", "error"]);
    // Definition-level fields exist only once the tool list is known (after a connect).
    const keys = (e: Record<string, unknown>) =>
      Object.keys(e)
        .filter((k) => !["definitionHash", "findings"].includes(k))
        .sort();
    expect(keys(events[0])).toEqual(keys(events[2]));
    expect(events[0].decision).toBe(events[2].decision);
  });

  it("carries wouldBlock under observe for a caller authorization would refuse", async () => {
    const g = await gateway({
      security: { enforcementProfile: "observe" },
      authorization: { enabled: true, rules: [] },
    });
    const bad = await caller(g.listener.url, "invalid-observe");
    expect((await bad.callTool({ name: "files__whoami", arguments: {} })).isError).toBe(true);
    const events = await g.events();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      decision: "allowed",
      outcome: "error",
      wouldBlock: "blocked_authorization",
      authorization: { effect: "deny", violations: ["client:no-grant"] },
    });
  });

  it("keeps the hash chain verifiable", async () => {
    const g = await gateway();
    const bad = await caller(g.listener.url, "invalid-chain");
    await bad.callTool({ name: "files__whoami", arguments: {} });
    const good = await caller(g.listener.url, "user-b-token");
    await good.callTool({ name: "files__whoami", arguments: {} });
    await g.events();
    const report = verifyAuditLog(parseJsonl(await readFile(g.log, "utf8")).records);
    expect(report.events).toBe(2);
    expect(report.status).toBe("intact");
  });
});

describe("other authorized calls that end without reaching the upstream are audited", () => {
  it("a call to an upstream that is not connected", async () => {
    const dir = await auditDir();
    const log = join(dir, "audit.jsonl");
    const mgr = new UpstreamManager(
      BastionConfigSchema.parse({
        servers: { mock: { command: process.execPath, args: [mockStdio] } },
        reconnect: { auto: false },
        healthCheck: { enabled: false },
        audit: { enabled: true, sinks: [{ type: "file", path: log }] },
      }),
    );
    cleanups.push(() => mgr.closeAll());
    await mgr.connectAll();
    const [tool] = mgr.listUpstreamTools();
    await mgr.upstreamsList()[0].close();
    const res = await mgr.callUpstreamTool(tool.name, {});
    expect(textOf(res)).toMatch(/currently disconnected/);
    await mgr.closeAll();
    const events = await readEvents(log);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      server: "mock",
      namespacedName: tool.name,
      decision: "allowed",
      outcome: "error",
    });
  });

  it("an MRTR retry whose requestState fails custody is recorded as blocked_request_state", async () => {
    const dir = await auditDir();
    const log = join(dir, "audit.jsonl");
    const mgr = new UpstreamManager(
      BastionConfigSchema.parse({
        servers: { up: { command: process.execPath, args: [modernStdio] } },
        reconnect: { auto: false },
        healthCheck: { enabled: false },
        audit: { enabled: true, sinks: [{ type: "file", path: log }] },
      }),
    );
    cleanups.push(() => mgr.closeAll());
    await mgr.connectAll();
    const res = await mgr.callUpstreamTool(
      "up__confirm_transfer",
      {},
      {
        inputResponses: { confirm: { action: "accept", content: { ok: true } } },
        requestState: "upstream-state-42",
      },
    );
    expect(textOf(res)).toMatch(/requeststate-unsealed/);
    await mgr.closeAll();
    const events = await readEvents(log);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      server: "up",
      tool: "confirm_transfer",
      decision: "blocked_request_state",
      outcome: "blocked",
    });
  });
});

describe("log level matches the cause of an upstream 401", () => {
  /** Messages logged at error and warn level while `run` runs. */
  async function logged(run: () => Promise<unknown>) {
    const error = vi.spyOn(logger, "error");
    const warn = vi.spyOn(logger, "warn");
    await run();
    const msgs = (spy: typeof error) =>
      spy.mock.calls.map((c) => (typeof c[0] === "string" ? c[0] : String(c[1] ?? "")));
    return { errors: msgs(error), warnings: msgs(warn) };
  }

  it("one caller's rejected credentials at first contact: one warning, no error, no disconnect", async () => {
    const g = await gateway();
    const bad = await caller(g.listener.url, "invalid-log-1");
    const { errors, warnings } = await logged(() =>
      bad.callTool({ name: "files__whoami", arguments: {} }),
    );
    expect(errors).toEqual([]);
    expect(warnings).toEqual(["upstream refused the caller's forwarded credentials"]);
    expect(g.mgr.status()[0].state).toBe("idle");
  });

  it("one caller's rejected credentials on a connected upstream: a warning, no error", async () => {
    const g = await gateway();
    const good = await caller(g.listener.url, "user-c-token");
    await good.callTool({ name: "files__whoami", arguments: {} });
    const bad = await caller(g.listener.url, "invalid-log-2");
    const { errors, warnings } = await logged(() =>
      bad.callTool({ name: "files__whoami", arguments: {} }),
    );
    expect(errors).toEqual([]);
    expect(warnings).toContain("upstream refused the caller's forwarded credentials");
    expect(g.mgr.status()[0].state).toBe("connected");
  });

  it("a 401 to static credentials fails every caller and stays an error", async () => {
    const upstream = await startIdentityHttpServer();
    cleanups.push(() => upstream.close());
    const mgr = new UpstreamManager(
      BastionConfigSchema.parse({
        servers: {
          files: {
            transport: "http",
            url: upstream.url,
            protocol: "legacy",
            headers: { "x-user-identity": "invalid-static-credential" },
          },
        },
        reconnect: { auto: false },
        healthCheck: { enabled: false },
      }),
    );
    cleanups.push(() => mgr.closeAll());
    const { errors, warnings } = await logged(() => mgr.connectAll());
    expect(errors).toContain("upstream connect failed");
    expect(warnings).not.toContain("upstream refused the caller's forwarded credentials");
    expect(warnings).not.toContain("upstream disconnected unexpectedly");
  });
});
