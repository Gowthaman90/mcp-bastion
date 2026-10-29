// A stateless Streamable HTTP MCP upstream that authenticates every request by an identity header,
// shaped like a typical stateless sub-agent server: one JSON-RPC POST in, one JSON answer out, GET answers 405,
// protocol 2025-06-18 / 2025-03-26.
//
// - A request without `x-user-identity`, or with one starting "invalid", gets HTTP 401.
// - Tool `whoami` answers with the identity it received (after a small random delay, so concurrent
//   calls interleave).
// - Every request is recorded (method, identity, all header names) for the test to inspect.
import { createServer } from "node:http";

const SUPPORTED = ["2025-06-18", "2025-03-26"];

/**
 * @param {{ description?: string }} [opts]
 */
export async function startIdentityHttpServer(opts = {}) {
  /** @type {{ httpMethod: string, method?: string, identity?: string, headerNames: string[], headers: Record<string, unknown> }[]} */
  const requests = [];
  let description = opts.description ?? "Report which identity this call ran as";

  const httpServer = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  async function handle(req, res) {
    const identity =
      typeof req.headers["x-user-identity"] === "string"
        ? req.headers["x-user-identity"]
        : undefined;
    const record = {
      httpMethod: req.method ?? "",
      identity,
      headerNames: Object.keys(req.headers),
      headers: { ...req.headers },
    };
    requests.push(record);

    if (req.method !== "POST") {
      res.writeHead(405, { allow: "POST" }).end();
      return;
    }
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const msg = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    record.method = msg.method;

    if (!identity || identity.startsWith("invalid")) {
      res.writeHead(401, { "content-type": "text/plain" }).end("identity required");
      return;
    }
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
          serverInfo: { name: "identity-upstream", version: "0.0.0" },
        };
        break;
      }
      case "ping":
        result = {};
        break;
      case "tools/list":
        result = {
          tools: [
            {
              name: "whoami",
              description,
              inputSchema: { type: "object", properties: { n: { type: "number" } } },
            },
          ],
        };
        break;
      case "tools/call":
        await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 15)));
        result = {
          content: [
            {
              type: "text",
              text: `identity=${identity} n=${msg.params?.arguments?.n ?? ""}`,
            },
          ],
        };
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
    /** Change the advertised `whoami` description (simulates a rug pull). */
    setDescription: (d) => {
      description = d;
    },
    close: () => new Promise((resolve) => httpServer.close(() => resolve(undefined))),
  };
}
