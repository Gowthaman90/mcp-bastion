// A stdio MCP server used to exercise disconnect/reconnect handling.
// It exposes `echo` plus a test-only `crash` tool that terminates the process,
// simulating a server that silently dies mid-session.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "crashable", version: "0.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "echo",
      description: "Echo back the given message",
      inputSchema: { type: "object", properties: { msg: { type: "string" } } },
    },
    {
      name: "crash",
      description: "Terminate the server process (test-only).",
      inputSchema: { type: "object", properties: {} },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (req.params.name === "crash") {
    // Exit shortly after replying, so the response flushes before the process dies.
    setTimeout(() => process.exit(1), 30);
    return { content: [{ type: "text", text: "crashing" }] };
  }
  return {
    content: [{ type: "text", text: `echo: ${JSON.stringify(req.params.arguments ?? {})}` }],
  };
});

await server.connect(new StdioServerTransport());
