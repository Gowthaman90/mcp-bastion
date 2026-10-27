// A stateless Streamable HTTP MCP upstream that serves a given tool list (protocol 2025-06-18 /
// 2025-03-26, one JSON-RPC POST in, one JSON answer out, GET answers 405).
//
// - `tools/call` answers `ran <tool>` and records the call's name and arguments.
// - Every HTTP request is recorded (JSON-RPC method), so a test can assert that a refused call
//   caused no upstream contact at all, not even an on-demand `initialize`.
import { createServer } from "node:http";

const SUPPORTED = ["2025-06-18", "2025-03-26"];

/**
 * @param {{ tools: { name: string, description?: string, inputSchema?: unknown }[] }} opts
 */
export async function startToolsHttpServer(opts) {
  /** @type {{ httpMethod: string, method?: string }[]} */
  const requests = [];
  /** @type {{ name: string, arguments: unknown }[]} */
  const calls = [];

  const httpServer = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  async function handle(req, res) {
    const record = { httpMethod: req.method ?? "" };
    requests.push(record);
    if (req.method !== "POST") {
      res.writeHead(405, { allow: "POST" }).end();
      return;
    }
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const msg = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    record.method = msg.method;
    if (msg.id === undefined) {
      res.writeHead(202).end();
      return;
    }

    let result;
    switch (msg.method) {
      case "initialize": {
        const asked = msg.params?.protocolVersion;
        result = {
          protocolVersion: SUPPORTED.includes(asked) ? asked : SUPPORTED[0],
          capabilities: { tools: {} },
          serverInfo: { name: "tools-upstream", version: "0.0.0" },
        };
        break;
      }
      case "ping":
        result = {};
        break;
      case "tools/list":
        result = {
          tools: opts.tools.map((t) => ({
            name: t.name,
            description: t.description ?? "",
            inputSchema: t.inputSchema ?? { type: "object" },
          })),
        };
        break;
      case "tools/call":
        calls.push({ name: msg.params?.name, arguments: msg.params?.arguments ?? {} });
        result = { content: [{ type: "text", text: `ran ${msg.params?.name}` }] };
        break;
      default:
        res.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            jsonrpc: "2.0",
            id: msg.id,
            error: { code: -32601, message: "Method not found" },
          }),
        );
        return;
    }
    res
      .writeHead(200, { "content-type": "application/json" })
      .end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }));
  }

  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", () => resolve(undefined)));
  const address = httpServer.address();
  const port = typeof address === "object" && address ? address.port : 0;

  return {
    url: `http://127.0.0.1:${port}/mcp`,
    requests,
    calls,
    close: () => new Promise((resolve) => httpServer.close(() => resolve(undefined))),
  };
}
