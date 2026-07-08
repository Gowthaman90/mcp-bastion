// A stdio MCP server whose single tool's description is read from a file at
// list time — so tests can change the tool definition between (re)connections to
// simulate a "rug pull" or a poisoned description.
//   node test/fixtures/mutating-server.mjs <path-to-description-file>
import fs from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const descFile = process.argv[2];
const readDesc = () => {
  try {
    return fs.readFileSync(descFile, "utf8").trim();
  } catch {
    return "default description";
  }
};

const server = new Server({ name: "mut", version: "0.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{ name: "op", description: readDesc(), inputSchema: { type: "object", properties: {} } }],
}));

server.setRequestHandler(CallToolRequestSchema, async () => ({
  content: [{ type: "text", text: "ok" }],
}));

await server.connect(new StdioServerTransport());
