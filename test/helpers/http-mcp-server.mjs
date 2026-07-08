// An in-process Streamable HTTP MCP server used as a remote upstream in tests.
// Exposes a single `echo` tool. Listens on an ephemeral port.
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  isInitializeRequest,
} from "@modelcontextprotocol/sdk/types.js";

function makeServer() {
  const server = new Server(
    { name: "http-mock", version: "0.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "echo",
        description: "Echo back the given message",
        inputSchema: { type: "object", properties: { msg: { type: "string" } } },
      },
    ],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => ({
    content: [{ type: "text", text: `echo: ${JSON.stringify(req.params.arguments ?? {})}` }],
  }));
  return server;
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : undefined;
}

/**
 * @param {{ requireAuth?: boolean }} [opts]
 * @returns {Promise<{ url: string, close: () => Promise<void> }>}
 */
export async function startMockHttpMcpServer(opts = {}) {
  const transports = new Map();

  const httpServer = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  async function handle(req, res) {
    if (opts.requireAuth && !req.headers["authorization"]) {
      res.writeHead(401).end();
      return;
    }
    const sessionId = req.headers["mcp-session-id"];
    const existing = typeof sessionId === "string" ? transports.get(sessionId) : undefined;

    if (req.method === "POST") {
      const body = await readJson(req);
      let transport = existing;
      if (!transport) {
        if (!isInitializeRequest(body)) {
          res.writeHead(400).end();
          return;
        }
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => {
            transports.set(id, transport);
          },
        });
        transport.onclose = () => {
          if (transport.sessionId) transports.delete(transport.sessionId);
        };
        await makeServer().connect(transport);
      }
      await transport.handleRequest(req, res, body);
      return;
    }

    if (req.method === "GET" || req.method === "DELETE") {
      if (!existing) {
        res.writeHead(400).end();
        return;
      }
      await existing.handleRequest(req, res);
      return;
    }

    res.writeHead(405).end();
  }

  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", () => resolve(undefined)));
  const address = httpServer.address();
  const port = typeof address === "object" && address ? address.port : 0;

  return {
    url: `http://127.0.0.1:${port}/mcp`,
    close: async () => {
      for (const t of transports.values()) {
        try {
          await t.close();
        } catch {
          // ignore
        }
      }
      await new Promise((resolve) => httpServer.close(() => resolve(undefined)));
    },
  };
}
