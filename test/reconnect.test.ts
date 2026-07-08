import { afterEach, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { BastionConfigSchema, type BastionConfig } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";

const crashable = fileURLToPath(new URL("./fixtures/crashable-server.mjs", import.meta.url));

function textOf(res: CallToolResult): string {
  return res.content.map((c) => (c.type === "text" ? c.text : "")).join("");
}

/** Poll `predicate` until it returns true or the timeout elapses. */
async function waitFor(predicate: () => boolean, timeoutMs = 8000, stepMs = 20): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error("waitFor: condition not met in time");
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
}

function cfg(reconnect: Record<string, unknown>): BastionConfig {
  return BastionConfigSchema.parse({
    servers: { crashable: { command: process.execPath, args: [crashable] } },
    reconnect,
    healthCheck: { enabled: false },
  });
}

describe("kill-and-recover (reliability MVP core scenario)", () => {
  let mgr: UpstreamManager;

  afterEach(async () => {
    await mgr?.closeAll();
  });

  it("detects a crash, returns a legible error, and recovers via bastion__reconnect", async () => {
    // Auto-reconnect OFF: this exercises the agent-driven recovery path.
    mgr = new UpstreamManager(cfg({ auto: false }));
    await mgr.connectAll();

    // Healthy to start.
    expect(mgr.status()[0].connected).toBe(true);
    expect(textOf(await mgr.callUpstreamTool("crashable__echo", { msg: "before" }))).toContain(
      "before",
    );

    // Kill the server mid-session.
    await mgr.callUpstreamTool("crashable__crash", {});
    await waitFor(() => !mgr.status()[0].connected);

    // While down, calls return an actionable message pointing at reconnect — never a throw.
    const down = await mgr.callUpstreamTool("crashable__echo", { msg: "during" });
    expect(down.isError).toBe(true);
    expect(textOf(down)).toMatch(/reconnect/i);

    // The agent recovers the server itself.
    const recon = await mgr.reconnect("crashable");
    expect(recon.ok).toBe(true);
    expect(textOf(await mgr.callUpstreamTool("crashable__echo", { msg: "after" }))).toContain(
      "after",
    );
  });

  it("auto-reconnects after a crash without human intervention", async () => {
    // Auto-reconnect ON with fast backoff: this exercises self-healing.
    mgr = new UpstreamManager(
      cfg({ auto: true, initialBackoffMs: 50, maxBackoffMs: 200, maxRetries: 20 }),
    );
    await mgr.connectAll();
    expect(mgr.status()[0].connected).toBe(true);

    // Kill it, then observe both the drop AND the automatic recovery.
    await mgr.callUpstreamTool("crashable__crash", {});
    const observed = new Set<boolean>();
    await waitFor(() => {
      observed.add(mgr.status()[0].connected);
      return observed.has(false) && mgr.status()[0].connected;
    }, 10000);

    expect(observed.has(false)).toBe(true); // we actually saw it go down
    expect(textOf(await mgr.callUpstreamTool("crashable__echo", { msg: "healed" }))).toContain(
      "healed",
    );
  });
});
