import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { BastionConfigSchema, type BastionConfig } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";
import { startHttpServer } from "../src/proxy/index.js";

const mockStdio = fileURLToPath(new URL("./fixtures/mock-server.mjs", import.meta.url));
const REV = "2026-07-28";

function cfg(servers: Record<string, unknown>, extra: Record<string, unknown> = {}): BastionConfig {
  return BastionConfigSchema.parse({
    servers,
    reconnect: { auto: false },
    healthCheck: { enabled: false },
    ...extra,
  });
}

const initBody = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "t", version: "0" },
    _meta: { "io.modelcontextprotocol/protocolVersion": REV },
  },
};

async function post(url: string, headers: Record<string, string>, body: unknown) {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(body),
  });
}

describe("2026-07-28 wiring: header/body coherence gate (HTTP listener)", () => {
  it("rejects a routing-header/body disagreement with 400 and JSON-RPC -32020", async () => {
    const mgr = new UpstreamManager(cfg({ mock: { command: process.execPath, args: [mockStdio] } }));
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
    try {
      const res = await post(
        listener.url,
        { "MCP-Protocol-Version": REV, "Mcp-Method": "tools/call", "Mcp-Name": "read_calendar" },
        initBody,
      );
      expect(res.status).toBe(400);
      const json = (await res.json()) as { error: { code: number; data: { findings: { rule: string }[] } }; id: unknown };
      expect(json.error.code).toBe(-32020);
      expect(json.error.data.findings.map((f) => f.rule)).toContain("header-body-mismatch");
      expect(json.id).toBe(1);
    } finally {
      await listener.close();
      await mgr.closeAll();
    }
  });

  it("does not reject a conforming request, nor a pre-revision client that sends no routing headers", async () => {
    const mgr = new UpstreamManager(cfg({ mock: { command: process.execPath, args: [mockStdio] } }));
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
    try {
      const conforming = await post(listener.url, { "MCP-Protocol-Version": REV, "Mcp-Method": "initialize" }, initBody);
      expect(conforming.status).not.toBe(400);
      const legacy = await post(listener.url, {}, { ...initBody, params: { ...initBody.params, _meta: undefined } });
      expect(legacy.status).not.toBe(400);
    } finally {
      await listener.close();
      await mgr.closeAll();
    }
  });

  it("can be switched off (validateRoutingHeaders: false)", async () => {
    const mgr = new UpstreamManager(cfg({ mock: { command: process.execPath, args: [mockStdio] } }));
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, {
      host: "127.0.0.1",
      port: 0,
      path: "/mcp",
      validateRoutingHeaders: false,
    });
    try {
      const res = await post(listener.url, { "MCP-Protocol-Version": REV, "Mcp-Method": "tools/call" }, initBody);
      expect(res.status).not.toBe(400);
    } finally {
      await listener.close();
      await mgr.closeAll();
    }
  });
});

describe("2026-07-28 wiring: cache policy on upstream list results", () => {
  const poisoned = JSON.stringify({ ttlMs: 2_592_000_000, cacheScope: "public" });

  it("clamps an implausible upstream ttlMs to the configured ceiling", async () => {
    const mgr = new UpstreamManager(
      cfg({ mock: { command: process.execPath, args: [mockStdio], env: { MOCK_CACHE_HINTS: poisoned } } }),
    );
    await mgr.connectAll();
    try {
      expect(mgr.listCacheHints()).toEqual({ ttlMs: 3_600_000, cacheScope: "public" });
    } finally {
      await mgr.closeAll();
    }
  });

  it("honours security.maxCacheTtlMs", async () => {
    const mgr = new UpstreamManager(
      cfg(
        { mock: { command: process.execPath, args: [mockStdio], env: { MOCK_CACHE_HINTS: poisoned } } },
        { security: { maxCacheTtlMs: 1000 } },
      ),
    );
    await mgr.connectAll();
    try {
      expect(mgr.listCacheHints()?.ttlMs).toBe(1000);
    } finally {
      await mgr.closeAll();
    }
  });

  it("adds nothing when the upstream sent no hints (pre-revision servers unchanged)", async () => {
    const mgr = new UpstreamManager(cfg({ mock: { command: process.execPath, args: [mockStdio] } }));
    await mgr.connectAll();
    try {
      expect(mgr.listCacheHints()).toBeUndefined();
    } finally {
      await mgr.closeAll();
    }
  });

  it("forwards the policed hints on Bastion's own tools/list", async () => {
    const mgr = new UpstreamManager(
      cfg({ mock: { command: process.execPath, args: [mockStdio], env: { MOCK_CACHE_HINTS: poisoned } } }),
    );
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
    const client = new Client({ name: "c", version: "0" }, { capabilities: {} });
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(listener.url)));
      const result = (await client.listTools()) as { ttlMs?: number; cacheScope?: string };
      expect(result.ttlMs).toBe(3_600_000);
      expect(result.cacheScope).toBe("public");
    } finally {
      await client.close();
      await listener.close();
      await mgr.closeAll();
    }
  });
});
