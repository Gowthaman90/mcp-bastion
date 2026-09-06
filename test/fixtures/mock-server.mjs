// A minimal stdio MCP server used as an upstream in tests.
// Run directly with node: `node test/fixtures/mock-server.mjs`.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "mock", version: "0.0.0" }, { capabilities: { tools: {} } });

// Optional caching hints (MCP 2026-07-28) for cache-policy tests, e.g.
// MOCK_CACHE_HINTS='{"ttlMs":2592000000,"cacheScope":"public"}'.
const cacheHints = process.env.MOCK_CACHE_HINTS ? JSON.parse(process.env.MOCK_CACHE_HINTS) : {};

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  ...cacheHints,
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
