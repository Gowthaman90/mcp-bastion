import { afterEach, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { BastionConfigSchema, type BastionConfig } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";

const mockServer = fileURLToPath(new URL("./fixtures/mock-server.mjs", import.meta.url));

/** Build a test config with auto-reconnect + health checks off (no dangling timers). */
function cfg(servers: Record<string, unknown>): BastionConfig {
  return BastionConfigSchema.parse({
    servers,
    reconnect: { auto: false },
    healthCheck: { enabled: false },
  });
}

function textOf(res: CallToolResult): string {
  return res.content.map((c) => (c.type === "text" ? c.text : "")).join("");
}

const oneMock = { mock: { command: process.execPath, args: [mockServer] } };

describe("UpstreamManager (core aggregation & routing)", () => {
  let mgr: UpstreamManager;

  afterEach(async () => {
    await mgr?.closeAll();
  });

  it("namespaces upstream tools (control tools are added by the proxy, not here)", async () => {
    mgr = new UpstreamManager(cfg(oneMock));
    await mgr.connectAll();

    const names = mgr.listUpstreamTools().map((t) => t.name);
    expect(names).toEqual(["mock__echo"]);
  });

  it("routes a namespaced tool call to the correct upstream", async () => {
    mgr = new UpstreamManager(cfg(oneMock));
    await mgr.connectAll();

    const res = await mgr.callUpstreamTool("mock__echo", { msg: "hi" });
    expect(res.isError).toBeFalsy();
    expect(textOf(res)).toContain("hi");
  });

  it("returns a legible error (not a throw) for an unknown tool", async () => {
    mgr = new UpstreamManager(cfg(oneMock));
    await mgr.connectAll();

    const res = await mgr.callUpstreamTool("mock__does_not_exist", {});
    expect(res.isError).toBe(true);
    expect(textOf(res)).toMatch(/unknown tool/i);
  });

  it("status() reports a connected upstream", async () => {
    mgr = new UpstreamManager(cfg(oneMock));
    await mgr.connectAll();

    const [status] = mgr.status();
    expect(status).toMatchObject({ name: "mock", connected: true, state: "connected", tools: 1 });
  });

  it("status() reports an upstream that never connected as disconnected/failed", async () => {
    mgr = new UpstreamManager(
      cfg({ broken: { command: "definitely-not-a-real-binary-xyz", args: [] } }),
    );
    await mgr.connectAll();

    const [status] = mgr.status();
    expect(status.name).toBe("broken");
    expect(status.connected).toBe(false);
    expect(status.state).toMatch(/disconnected|failed/);
  });

  it("reconnect() succeeds for a known server and fails cleanly for an unknown one", async () => {
    mgr = new UpstreamManager(cfg(oneMock));
    await mgr.connectAll();

    const ok = await mgr.reconnect("mock");
    expect(ok).toMatchObject({ ok: true, server: "mock", state: "connected" });

    const missing = await mgr.reconnect("ghost");
    expect(missing.ok).toBe(false);
    expect(missing.message).toMatch(/no server named/i);
  });
});
