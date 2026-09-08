/**
 * The client-facing MCP server: Bastion's "front door".
 *
 * Built on SDK 2.0's low-level `Server`, one instance per stdio connection and — because the
 * 2026-07-28 revision is stateless — one instance *per HTTP request* (see `createMcpHandler` in
 * `http-server.ts`). This adapter wires the MCP protocol handlers to the core {@link UpstreamManager}
 * and the control tools. It intentionally contains no domain logic — it only translates protocol
 * requests into manager calls and composes the tool list.
 *
 * MRTR (multi-round-trip) relay: when an upstream answers `input_required`, the manager returns the
 * continuation (with a Bastion-sealed `requestState`) and this server passes it to the client
 * unchanged; on the retry the client's `inputResponses` and echoed `requestState` are read from the
 * request context and handed back to the manager, which verifies custody before forwarding.
 *
 * @packageDocumentation
 */
import { Server } from "@modelcontextprotocol/server";
import type { CallToolResult, InputRequiredResult } from "@modelcontextprotocol/server";

import { BASTION_NAME, BASTION_VERSION, type UpstreamManager } from "../core/index.js";
import { logger } from "../observability/index.js";
import { buildControlTools, handleControlTool, isControlToolName } from "./control-tools.js";

/** Per-connection (or per-request) options for the front door. */
export interface BastionServerOptions {
  /**
   * The calling principal: `stdio` for a local client, or a stable hash of the bearer token over
   * HTTP. Sealed `requestState` envelopes are bound to it.
   */
  principal?: string;
  /**
   * `true` for a long-lived (stdio) connection: the server is registered to receive
   * `tools/list_changed` pushes. Per-request HTTP servers pass `false` (the handler's notifier is
   * used instead).
   */
  persistent?: boolean;
}

/** Long-lived servers that should be told when the aggregate tool list changes. */
const liveServers = new Set<Server>();

/**
 * Construct the client-facing MCP {@link Server} backed by the given manager.
 *
 * The returned server is not yet connected to a transport; the caller (or `serveStdio` /
 * `createMcpHandler`) is responsible for that.
 *
 * @param manager The upstream manager providing tools, routing, and health.
 * @param opts    Principal and lifetime of this instance.
 */
export function buildBastionServer(manager: UpstreamManager, opts: BastionServerOptions = {}): Server {
  const principal = opts.principal ?? "stdio";
  // Policed cache hints (MCP 2026-07-28): never a longer TTL, never a wider scope, than policy allows.
  const hints = manager.listCacheHints();
  const server = new Server(
    { name: BASTION_NAME, version: BASTION_VERSION },
    {
      capabilities: { tools: { listChanged: true } },
      ...(hints ? { cacheHints: { "tools/list": hints } } : {}),
    },
  );

  // tools/list — aggregated upstream tools + Bastion's control tools. When an upstream attached
  // caching hints, Bastion forwards the *policed* hints so a downstream cache can never hold a
  // definition longer, or share it wider, than policy allows. Pre-revision upstreams send none.
  server.setRequestHandler("tools/list", async () => ({
    tools: [...manager.listUpstreamTools(), ...buildControlTools(manager.separator)],
    ...(hints ?? {}),
  }));

  // tools/call — dispatch control tools locally; route everything else upstream, carrying the
  // MRTR retry material (inputResponses + echoed requestState) when present.
  server.setRequestHandler("tools/call", async (req, ctx) => {
    const { name, arguments: args } = req.params;
    logger.debug({ tool: name, principal }, "tools/call");
    if (isControlToolName(name, manager.separator)) {
      return handleControlTool(name, (args ?? {}) as Record<string, unknown>, manager);
    }
    const mcpReq = ctx.mcpReq as { inputResponses?: Record<string, unknown>; requestState?: () => unknown };
    const requestState = typeof mcpReq.requestState === "function" ? mcpReq.requestState() : undefined;
    const outcome = await manager.callUpstreamTool(name, args ?? {}, {
      principal,
      inputResponses: mcpReq.inputResponses,
      requestState: typeof requestState === "string" ? requestState : undefined,
    });
    return outcome as CallToolResult | InputRequiredResult;
  });

  if (opts.persistent) {
    liveServers.add(server);
    server.onclose = () => {
      liveServers.delete(server);
    };
  }
  return server;
}

/**
 * Propagate an aggregate tool-list change to every long-lived client server. HTTP callers add the
 * handler's notifier via {@link addToolsChangedTarget}.
 */
const extraTargets = new Set<() => void>();

/** Register an additional `tools/list_changed` sink (e.g. an HTTP handler's `notify.toolsChanged`). */
export function addToolsChangedTarget(fn: () => void): () => void {
  extraTargets.add(fn);
  return () => extraTargets.delete(fn);
}

/** Fan a tools-changed event out to every registered target. Never throws. */
export function broadcastToolsChanged(): void {
  for (const server of liveServers) {
    sendToolListChanged(server).catch((err) =>
      logger.warn({ err: String(err) }, "failed to send tools/list_changed"),
    );
  }
  for (const fn of extraTargets) {
    try {
      fn();
    } catch (err) {
      logger.warn({ err: String(err) }, "tools-changed target failed");
    }
  }
}

/** Emit `notifications/tools/list_changed`, tolerant of SDK differences. */
async function sendToolListChanged(server: Server): Promise<void> {
  const maybeTyped = server as unknown as { sendToolListChanged?: () => Promise<void> | void };
  if (typeof maybeTyped.sendToolListChanged === "function") {
    await maybeTyped.sendToolListChanged();
    return;
  }
  await server.notification({ method: "notifications/tools/list_changed" });
}
