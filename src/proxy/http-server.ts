/**
 * Client-facing Streamable HTTP listener (MCP 2026-07-28 stateless core, with legacy support).
 *
 * Built on SDK 2.0's `createMcpHandler`: a fresh front-door {@link Server} serves every request and
 * nothing is held between requests. Pre-2026-07-28 clients are served statelessly by default
 * (`legacy: "stateless"` — no `Mcp-Session-Id` is minted or honoured, GET/DELETE answer 405,
 * `Last-Event-ID` is ignored) or refused outright (`legacy: "reject"`, downgrade prevention).
 *
 * Bastion's own gates run *before* the SDK sees the request: host/origin (DNS-rebinding), bearer
 * auth, body-size cap, and header/body coherence (`-32020`).
 *
 * @packageDocumentation
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { createMcpHandler } from "@modelcontextprotocol/server";
import type { AuthInfo, McpHttpHandler } from "@modelcontextprotocol/server";

import type { UpstreamManager } from "../core/index.js";
import { logger } from "../observability/index.js";
import { checkHeaderBodyCoherence, checkRequestOrigin } from "../security/index.js";
import { addToolsChangedTarget, buildBastionServer } from "./bastion-server.js";

/** Options for the HTTP listener. */
export interface HttpListenOptions {
  host: string;
  port: number;
  path: string;
  /** Bearer token required on every request (constant-time compared). */
  authToken?: string;
  /** Accepted for compatibility; sessions no longer exist in the stateless core. */
  maxSessions?: number;
  /** Max request body size in bytes before a 413. */
  maxBodyBytes?: number;
  /**
   * Reject requests whose mirrored routing headers disagree with the JSON-RPC body with
   * `-32020` HeaderMismatch (MCP 2026-07-28). Default `true`.
   */
  validateRoutingHeaders?: boolean;
  /** Serve pre-2026-07-28 clients statelessly (default) or refuse them (`-32022`). */
  legacy?: "stateless" | "reject";
}

/** JSON-RPC error code the 2026-07-28 revision assigns to a header/body disagreement. */
export const HEADER_MISMATCH_CODE = -32020;

/** Header findings that mean the request must be rejected (as opposed to merely logged). */
const REJECTING_HEADER_RULES = new Set([
  "header-body-mismatch",
  "header-invalid-value",
  "header-duplicate-conflict",
]);

/** Loopback hostname? (127/8, ::1, localhost) */
function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "::1" || /^127\./.test(hostname);
}

/** Extract the hostname (drop port / IPv6 brackets) from a Host header. */
function hostnameOf(hostHeader: string | undefined): string {
  if (!hostHeader) return "";
  const h = hostHeader.trim().toLowerCase();
  if (h.startsWith("[")) return h.slice(1, h.indexOf("]") === -1 ? h.length : h.indexOf("]"));
  return h.split(":")[0];
}

/** Constant-time bearer-token check. */
function isAuthorized(header: string | undefined, token: string): boolean {
  const m = /^Bearer\s+(.+)$/i.exec(header ?? "");
  if (!m) return false;
  const a = Buffer.from(m[1]);
  const b = Buffer.from(token);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * The principal a request acts as: a stable, non-reversible hash of the bearer token, or
 * `http-anonymous` on an unauthenticated loopback listener. Sealed `requestState` is bound to it.
 */
export function principalOf(authInfo: AuthInfo | undefined): string {
  if (!authInfo?.token) return "http-anonymous";
  return "bearer:" + createHash("sha256").update(authInfo.token).digest("hex").slice(0, 16);
}

/** A running HTTP listener with a graceful shutdown. */
export interface HttpListener {
  readonly url: string;
  close(): Promise<void>;
}

/**
 * Start the Streamable HTTP server. Resolves once it is listening.
 *
 * @param manager The shared upstream manager backing every request.
 * @param opts    Bind host/port/path and gates.
 */
export async function startHttpServer(
  manager: UpstreamManager,
  opts: HttpListenOptions,
): Promise<HttpListener> {
  // Fail closed: never expose an unauthenticated proxy on a non-loopback interface.
  if (!isLoopbackHostname(opts.host) && !opts.authToken) {
    throw new Error(
      `Refusing to bind mcp-bastion HTTP to non-loopback host "${opts.host}" without listen.authToken — ` +
        `an unauthenticated public bind would expose every proxied tool. Set listen.authToken or bind 127.0.0.1.`,
    );
  }
  const maxBodyBytes = opts.maxBodyBytes ?? 1_048_576;

  // One front-door Server per request (stateless core); the principal is derived from the bearer
  // token the SDK receives as `authInfo`, so sealed continuations cannot cross principals.
  const handler: McpHttpHandler = createMcpHandler(
    (ctx) => buildBastionServer(manager, { principal: principalOf(ctx.authInfo), persistent: false }),
    {
      legacy: opts.legacy ?? "stateless",
      onerror: (err) => logger.warn({ err: err.message }, "mcp handler error"),
    },
  );
  const removeTarget = addToolsChangedTarget(() => handler.notify.toolsChanged());

  const httpServer = createServer((req, res) => {
    handle(req, res).catch((err) => {
      logger.error({ err: (err as Error)?.message ?? String(err) }, "http request handling failed");
      if (!res.headersSent) res.writeHead(500).end();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Reject a foreign Origin targeting a loopback listener (DNS-rebinding defense). Fires only when
    // the request Host is loopback, so legitimate remote deployments (bound to a public host) are
    // unaffected. Non-browser clients send no Origin and pass through.
    const originFindings = checkRequestOrigin(req.headers.host, req.headers.origin);
    if (originFindings.length > 0) {
      logger.warn(
        { host: req.headers.host, origin: req.headers.origin },
        "blocked cross-origin request to loopback listener (possible DNS rebinding)",
      );
      res.writeHead(403).end("Cross-origin request blocked");
      return;
    }

    // DNS-rebinding defense (M2): on a loopback bind, reject any request whose Host is not
    // loopback — the shape of a rebinding attack (Host = attacker domain rebound to 127.0.0.1).
    if (isLoopbackHostname(opts.host) && !isLoopbackHostname(hostnameOf(req.headers.host))) {
      res.writeHead(403).end("Host not allowed");
      return;
    }

    // Authentication (M1): require the bearer token when one is configured.
    if (opts.authToken && !isAuthorized(req.headers.authorization, opts.authToken)) {
      res.writeHead(401, { "www-authenticate": "Bearer" }).end("Unauthorized");
      return;
    }
    const authInfo: AuthInfo | undefined = opts.authToken
      ? { token: opts.authToken, clientId: "mcp-bastion-bearer", scopes: [] }
      : undefined;

    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    if (url.pathname !== opts.path) {
      res.writeHead(404).end();
      return;
    }

    let raw = "";
    let body: unknown;
    if (req.method === "POST") {
      try {
        raw = await readBody(req, maxBodyBytes);
        body = raw ? JSON.parse(raw) : undefined;
      } catch (err) {
        if ((err as { statusCode?: number }).statusCode === 413) {
          res.writeHead(413).end("Payload too large");
          return;
        }
        res.writeHead(400, { "content-type": "application/json" }).end(
          JSON.stringify({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null }),
        );
        return;
      }

      // Header/body coherence (MCP 2026-07-28). A gateway that authorizes on the mirrored
      // `Mcp-Name` while the server executes `params.name` is the desync the spec calls out; the
      // body is the source of truth and a disagreement MUST be rejected with -32020. Runs before
      // the SDK so a forged routing header never reaches an upstream. Requests that carry no
      // routing headers (every pre-revision client) produce no findings.
      if (opts.validateRoutingHeaders !== false) {
        const findings = checkHeaderBodyCoherence(req.headers, body);
        const rejecting = findings.filter((f) => REJECTING_HEADER_RULES.has(f.rule));
        if (findings.length > 0) {
          logger.warn(
            { rules: findings.map((f) => f.rule), rejected: rejecting.length > 0 },
            "routing headers disagree with request body",
          );
        }
        if (rejecting.length > 0) {
          const id =
            body && typeof body === "object" && !Array.isArray(body)
              ? ((body as { id?: unknown }).id ?? null)
              : null;
          res.writeHead(400, { "content-type": "application/json" }).end(
            JSON.stringify({
              jsonrpc: "2.0",
              error: {
                code: HEADER_MISMATCH_CODE,
                message: "HeaderMismatch: routing headers do not match the request body",
                data: { findings: rejecting.map((f) => ({ rule: f.rule, excerpt: f.excerpt })) },
              },
              id,
            }),
          );
          return;
        }
      }
    }

    // Hand the request to the SDK handler as a web-standard Request and stream its Response back.
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (v === undefined) continue;
      if (Array.isArray(v)) for (const x of v) headers.append(k, x);
      else headers.set(k, v);
    }
    const webReq = new Request(url.href, {
      method: req.method ?? "GET",
      headers,
      ...(req.method === "POST" ? { body: raw } : {}),
    });
    const resp = await handler.fetch(webReq, { authInfo, parsedBody: body });
    const outHeaders: Record<string, string> = {};
    resp.headers.forEach((value, key) => {
      outHeaders[key] = value;
    });
    res.writeHead(resp.status, outHeaders);
    if (!resp.body) {
      res.end();
      return;
    }
    const reader = resp.body.getReader();
    req.on("close", () => void reader.cancel().catch(() => undefined));
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        res.write(Buffer.from(value));
      }
    } finally {
      res.end();
    }
  }

  await new Promise<void>((resolve) => httpServer.listen(opts.port, opts.host, resolve));
  const address = httpServer.address();
  const boundPort = typeof address === "object" && address ? address.port : opts.port;
  const url = `http://${opts.host}:${boundPort}${opts.path}`;
  logger.info({ url, legacy: opts.legacy ?? "stateless" }, "mcp-bastion HTTP listener started");

  return {
    url,
    close: async () => {
      removeTarget();
      await handler.close().catch(() => undefined);
      await new Promise<void>((resolve, reject) =>
        httpServer.close((err) => (err ? reject(err) : resolve())),
      );
    },
  };
}

/** Read a request body as text, enforcing a size cap. */
async function readBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > maxBytes) {
      const err = new Error("Payload too large") as Error & { statusCode: number };
      err.statusCode = 413;
      throw err;
    }
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}
