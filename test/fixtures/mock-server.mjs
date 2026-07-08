// A minimal stdio MCP server used as an upstream in tests.
// Run directly with node: `node test/fixtures/mock-server.mjs`.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "mock", version: "0.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "echo",
      description: "Echo back the given message",
      inputSchema: {
        type: "object",
        properties: { msg: { type: "string" } },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => ({
  content: [{ type: "text", text: `echo: ${JSON.stringify(req.params.arguments ?? {})}` }],
}));

await server.connect(new StdioServerTransport());
