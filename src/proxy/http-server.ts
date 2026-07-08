/**
 * Client-facing Streamable HTTP server.
 *
 * Lets one or more MCP clients connect to Bastion over HTTP instead of stdio.
 * Each client session gets its own MCP {@link Server} instance (all sharing the
 * one {@link UpstreamManager}), tracked by the `Mcp-Session-Id` header per the
 * Streamable HTTP spec.
 *
 * @packageDocumentation
 */
import {
  createServer,
  type IncomingMessage,
  type Server as HttpServer,
  type ServerResponse,
} from "node:http";
import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

import type { UpstreamManager } from "../core/index.js";
import { logger } from "../observability/index.js";
import { buildBastionServer } from "./bastion-server.js";

/** Options for the HTTP listener. */
export interface HttpListenOptions {
  host: string;
  port: number;
  path: string;
}

/** A running HTTP listener with a graceful shutdown. */
export interface HttpListener {
  readonly url: string;
  close(): Promise<void>;
}

/**
 * Start the Streamable HTTP server. Resolves once it is listening.
 *
 * @param manager The shared upstream manager backing every session.
 * @param opts    Bind host/port/path.
 */
export async function startHttpServer(
  manager: UpstreamManager,
  opts: HttpListenOptions,
): Promise<HttpListener> {
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const httpServer = createServer((req, res) => {
    handle(req, res).catch((err) => {
      logger.error({ err: (err as Error)?.message ?? String(err) }, "http request handling failed");
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    if (url.pathname !== opts.path) {
      res.writeHead(404).end();
      return;
    }

    const sessionId = req.headers["mcp-session-id"];
    const existing = typeof sessionId === "string" ? transports.get(sessionId) : undefined;

    if (req.method === "POST") {
      const body = await readJson(req);
      let transport = existing;
      if (!transport) {
        if (!isInitializeRequest(body)) {
          res.writeHead(400, { "content-type": "application/json" }).end(
            JSON.stringify({
              jsonrpc: "2.0",
              error: {
                code: -32000,
                message: "No valid session; an initialize request is required",
              },
              id: null,
            }),
          );
          return;
        }
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (id) => {
            transports.set(id, transport!);
          },
        });
        transport.onclose = () => {
          if (transport!.sessionId) transports.delete(transport!.sessionId);
        };
        await buildBastionServer(manager).connect(transport);
      }
      await transport.handleRequest(req, res, body);
      return;
    }

    if (req.method === "GET" || req.method === "DELETE") {
      if (!existing) {
        res.writeHead(400).end("Missing or unknown Mcp-Session-Id");
        return;
      }
      await existing.handleRequest(req, res);
      return;
    }

    res.writeHead(405).end();
  }

  await new Promise<void>((resolve) => httpServer.listen(opts.port, opts.host, resolve));
  const address = httpServer.address();
  const boundPort = typeof address === "object" && address ? address.port : opts.port;
  const url = `http://${opts.host}:${boundPort}${opts.path}`;
  logger.info({ url }, "mcp-bastion HTTP listener started");

  return {
    url,
    close: () => shutdown(httpServer, transports),
  };
}

async function shutdown(
  httpServer: HttpServer,
  transports: Map<string, StreamableHTTPServerTransport>,
): Promise<void> {
  await Promise.allSettled([...transports.values()].map((t) => t.close()));
  transports.clear();
  await new Promise<void>((resolve, reject) =>
    httpServer.close((err) => (err ? reject(err) : resolve())),
  );
}

/** Read and JSON-parse a request body. */
async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : undefined;
}
