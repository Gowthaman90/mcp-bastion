import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { Client, StreamableHTTPClientTransport, isInputRequiredResult } from "@modelcontextprotocol/client";
import { Client as LegacyClient } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport as LegacyHttp } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { BastionConfigSchema, type BastionConfig } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";
import { startHttpServer } from "../src/proxy/index.js";
import { isSealedRequestState } from "../src/security/index.js";

const modernStdio = fileURLToPath(new URL("./fixtures/modern-server.mjs", import.meta.url));
const legacyStdio = fileURLToPath(new URL("./fixtures/mock-server.mjs", import.meta.url));

function cfg(security: Record<string, unknown> = {}): BastionConfig {
  return BastionConfigSchema.parse({
    servers: { up: { command: process.execPath, args: [modernStdio] }, old: { command: process.execPath, args: [legacyStdio] } },
    reconnect: { auto: false },
    healthCheck: { enabled: false },
    security,
  });
}
const textOf = (r: unknown) => (((r as { content?: Array<{ type?: string; text?: string }> }).content ?? []).map((c) => (c.type === "text" ? c.text ?? "" : "")).join(""));

async function modernClient(url: string, extra: Record<string, unknown> = {}) {
  const c = new Client(
    { name: "t", version: "0" },
    { versionNegotiation: { mode: "auto" }, inputRequired: { autoFulfill: false }, capabilities: { elicitation: { form: {} }, sampling: {} }, ...extra },
  );
  await c.connect(new StreamableHTTPClientTransport(new URL(url)));
  return c;
}
const allow = { allowInputRequired: true } as unknown as Parameters<Client["callTool"]>[1];

describe("v1.0 stateless era: dual-stack negotiation", () => {
  it("negotiates modern with a 2026-07-28 upstream and legacy with a 1.x upstream, from one manager", async () => {
    const mgr = new UpstreamManager(cfg());
    await mgr.connectAll();
    try {
      const eras = Object.fromEntries(mgr.upstreamsList().map((u) => [u.name, u.era]));
      expect(eras).toEqual({ up: "modern", old: "legacy" });
      expect(textOf(await mgr.callUpstreamTool("old__echo", { msg: "x" }))).toContain("x");
      expect(textOf(await mgr.callUpstreamTool("up__echo", { msg: "y" }))).toContain("y");
    } finally {
      await mgr.closeAll();
    }
  });
});

describe("v1.0 MRTR relay with requestState custody", () => {
  it("relays input_required with a sealed requestState, and completes on an honest retry", async () => {
    const mgr = new UpstreamManager(cfg());
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
    const c = await modernClient(listener.url);
    try {
      const round = await c.callTool({ name: "up__confirm_transfer", arguments: {} }, allow);
      expect(isInputRequiredResult(round)).toBe(true);
      const ir = round as { requestState?: string; inputRequests: Record<string, unknown> };
      expect(isSealedRequestState(ir.requestState)).toBe(true); // never the upstream's raw state
      expect(ir.requestState).not.toContain("upstream-state-42");
      const done = await c.callTool(
        { name: "up__confirm_transfer", arguments: {}, inputResponses: { confirm: { action: "accept", content: { ok: true } } }, requestState: ir.requestState } as never,
        allow,
      );
      expect(textOf(done)).toContain("transfer done");
      expect(textOf(done)).toContain("state=upstream-state-42"); // upstream got ITS state back
    } finally {
      await c.close();
      await listener.close();
      await mgr.closeAll();
    }
  });

  it("blocks a retry whose requestState was tampered with or is the raw upstream value", async () => {
    const mgr = new UpstreamManager(cfg());
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
    const c = await modernClient(listener.url);
    try {
      const round = (await c.callTool({ name: "up__confirm_transfer", arguments: {} }, allow)) as { requestState: string };
      const tampered = round.requestState.slice(0, -3) + "AAA";
      const r1 = await c.callTool({ name: "up__confirm_transfer", arguments: {}, inputResponses: { confirm: { action: "accept", content: { ok: true } } }, requestState: tampered } as never, allow);
      expect((r1 as { isError?: boolean }).isError).toBe(true);
      expect(textOf(r1)).toMatch(/requeststate-forged/);
      const r2 = await c.callTool({ name: "up__confirm_transfer", arguments: {}, inputResponses: { confirm: { action: "accept", content: { ok: true } } }, requestState: "upstream-state-42" } as never, allow);
      expect((r2 as { isError?: boolean }).isError).toBe(true);
      expect(textOf(r2)).toMatch(/requeststate-unsealed/);
    } finally {
      await c.close();
      await listener.close();
      await mgr.closeAll();
    }
  });

  it("blocks credential-phishing elicitation and server-injected systemPrompts under the balanced profile", async () => {
    const mgr = new UpstreamManager(cfg());
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
    const c = await modernClient(listener.url);
    try {
      const phish = await c.callTool({ name: "up__phish", arguments: {} }, allow);
      expect(isInputRequiredResult(phish)).toBe(false);
      expect(textOf(phish)).toMatch(/mrtr-credential-elicitation/);
      const steer = await c.callTool({ name: "up__steer", arguments: {} }, allow);
      expect(isInputRequiredResult(steer)).toBe(false);
      expect(textOf(steer)).toMatch(/mrtr-server-system-prompt/);
    } finally {
      await c.close();
      await listener.close();
      await mgr.closeAll();
    }
  });

  it("relays the same rounds untouched when onInputRequired is 'warn'", async () => {
    const mgr = new UpstreamManager(cfg({ onInputRequired: "warn" }));
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
    const c = await modernClient(listener.url);
    try {
      const phish = await c.callTool({ name: "up__phish", arguments: {} }, allow);
      // warn posture strips the flagged request rather than blocking; nothing benign remained here
      expect(textOf(phish)).toMatch(/flagged and stripped|mrtr/);
    } finally {
      await c.close();
      await listener.close();
      await mgr.closeAll();
    }
  });
});

describe("v1.0 transport downgrade prevention", () => {
  it("answers legacy GET/DELETE streams with 405 and never mints or echoes a session id", async () => {
    const mgr = new UpstreamManager(cfg());
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
    try {
      const get = await fetch(listener.url, { method: "GET", headers: { accept: "text/event-stream" } });
      expect(get.status).toBe(405);
      const del = await fetch(listener.url, { method: "DELETE", headers: { "mcp-session-id": "sess-abc" } });
      expect(del.status).toBe(405);
      const post = await fetch(listener.url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-session-id": "sess-abc", "last-event-id": "42" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "x", version: "0" } } }),
      });
      expect(post.status).toBe(200);
      expect(post.headers.get("mcp-session-id")).toBeNull();
    } finally {
      await listener.close();
      await mgr.closeAll();
    }
  });

  it("refuses pre-2026-07-28 clients entirely when listen.legacy is 'reject' (-32022)", async () => {
    const mgr = new UpstreamManager(cfg());
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp", legacy: "reject" });
    try {
      const old = new LegacyClient({ name: "old", version: "0" }, { capabilities: {} });
      await expect(old.connect(new LegacyHttp(new URL(listener.url)))).rejects.toThrow(/-32022|Unsupported protocol version/);
      const modern = await modernClient(listener.url);
      expect(modern.getProtocolEra()).toBe("modern");
      await modern.close();
    } finally {
      await listener.close();
      await mgr.closeAll();
    }
  });
});
