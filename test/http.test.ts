import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { BastionConfigSchema, type BastionConfig } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";
import { startHttpServer } from "../src/proxy/index.js";
// @ts-expect-error -- untyped .mjs test helper
import { startMockHttpMcpServer } from "./helpers/http-mcp-server.mjs";

const mockStdio = fileURLToPath(new URL("./fixtures/mock-server.mjs", import.meta.url));
const textOf = (r: CallToolResult) =>
  r.content.map((c) => (c.type === "text" ? c.text : "")).join("");

function cfg(servers: Record<string, unknown>): BastionConfig {
  return BastionConfigSchema.parse({
    servers,
    reconnect: { auto: false },
    healthCheck: { enabled: false },
  });
}

describe("Streamable HTTP transport", () => {
  it("proxies a remote HTTP upstream (upstream-facing HTTP)", async () => {
    const remote = (await startMockHttpMcpServer()) as { url: string; close: () => Promise<void> };
    const mgr = new UpstreamManager(cfg({ remote: { transport: "http", url: remote.url } }));
    try {
      await mgr.connectAll();
      expect(mgr.listUpstreamTools().map((t) => t.name)).toContain("remote__echo");
      expect(textOf(await mgr.callUpstreamTool("remote__echo", { msg: "hi" }))).toContain("hi");
    } finally {
      await mgr.closeAll();
      await remote.close();
    }
  });

  it("reports auth status for HTTP upstreams", async () => {
    const remote = (await startMockHttpMcpServer()) as { url: string; close: () => Promise<void> };
    try {
      const noAuth = new UpstreamManager(cfg({ remote: { transport: "http", url: remote.url } }));
      await noAuth.connectAll();
      expect(noAuth.status()[0]).toMatchObject({ transport: "http", authenticated: false });
      await noAuth.closeAll();

      const withAuth = new UpstreamManager(
        cfg({
          remote: { transport: "http", url: remote.url, headers: { Authorization: "Bearer x" } },
        }),
      );
      await withAuth.connectAll();
      expect(withAuth.status()[0].authenticated).toBe(true);
      await withAuth.closeAll();
    } finally {
      await remote.close();
    }
  });

  it("marks stdio upstreams as not-applicable for auth", async () => {
    const mgr = new UpstreamManager(
      cfg({ mock: { command: process.execPath, args: [mockStdio] } }),
    );
    await mgr.connectAll();
    try {
      expect(mgr.status()[0]).toMatchObject({ transport: "stdio", authenticated: null });
    } finally {
      await mgr.closeAll();
    }
  });

  it("serves Bastion over Streamable HTTP to a client (client-facing HTTP)", async () => {
    const mgr = new UpstreamManager(
      cfg({ mock: { command: process.execPath, args: [mockStdio] } }),
    );
    await mgr.connectAll();
    const listener = await startHttpServer(mgr, { host: "127.0.0.1", port: 0, path: "/mcp" });
    const client = new Client({ name: "http-client", version: "0.0.0" }, { capabilities: {} });
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(listener.url)));
      const names = (await client.listTools()).tools.map((t) => t.name);
      expect(names).toContain("mock__echo");
      expect(names).toContain("bastion__status");

      const res = (await client.callTool({
        name: "mock__echo",
        arguments: { msg: "viahttp" },
      })) as CallToolResult;
      expect(textOf(res)).toContain("viahttp");
    } finally {
      await client.close();
      await listener.close();
      await mgr.closeAll();
    }
  });
});
