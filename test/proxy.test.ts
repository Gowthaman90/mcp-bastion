import { afterEach, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { BastionConfigSchema } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";
import { buildBastionServer } from "../src/proxy/index.js";

const mockServer = fileURLToPath(new URL("./fixtures/mock-server.mjs", import.meta.url));

function textOf(res: CallToolResult): string {
  return res.content.map((c) => (c.type === "text" ? c.text : "")).join("");
}

/** Wire a real MCP client to a Bastion server over a linked in-memory transport pair. */
async function connectClient(): Promise<{ client: Client; manager: UpstreamManager }> {
  const config = BastionConfigSchema.parse({
    servers: { mock: { command: process.execPath, args: [mockServer] } },
    reconnect: { auto: false },
    healthCheck: { enabled: false },
  });
  const manager = new UpstreamManager(config);
  await manager.connectAll();

  const server = buildBastionServer(manager);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);

  const client = new Client({ name: "test-client", version: "0.0.0" }, { capabilities: {} });
  await client.connect(clientTransport);

  return { client, manager };
}

describe("buildBastionServer (proxy end-to-end)", () => {
  let manager: UpstreamManager;
  let client: Client;

  afterEach(async () => {
    await client?.close();
    await manager?.closeAll();
  });

  it("exposes upstream tools plus Bastion control tools via tools/list", async () => {
    ({ client, manager } = await connectClient());

    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toContain("mock__echo");
    expect(names).toContain("bastion__status");
    expect(names).toContain("bastion__reconnect");
  });

  it("proxies a namespaced tool call through to the upstream", async () => {
    ({ client, manager } = await connectClient());

    const res = (await client.callTool({
      name: "mock__echo",
      arguments: { msg: "end-to-end" },
    })) as CallToolResult;
    expect(textOf(res)).toContain("end-to-end");
  });

  it("handles the bastion__status control tool locally", async () => {
    ({ client, manager } = await connectClient());

    const res = (await client.callTool({
      name: "bastion__status",
      arguments: {},
    })) as CallToolResult;
    expect(textOf(res)).toContain("mock");
    expect(textOf(res)).toContain("connected");
  });

  it("handles the bastion__reconnect control tool locally", async () => {
    ({ client, manager } = await connectClient());

    const res = (await client.callTool({
      name: "bastion__reconnect",
      arguments: { server: "mock" },
    })) as CallToolResult;
    expect(res.isError).toBeFalsy();
    expect(textOf(res)).toContain('"ok": true');
  });
});
