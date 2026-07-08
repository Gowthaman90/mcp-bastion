/**
 * The client-facing MCP server: Bastion's "front door".
 *
 * This adapter wires the MCP protocol handlers to the core {@link UpstreamManager}
 * and the control tools. It intentionally contains no domain logic — it only
 * translates protocol requests into manager calls and composes the tool list.
 *
 * v0.1 advertises only the `tools` capability (with `listChanged`), because that
 * is the full surface Bastion proxies today. Advertising only what we fully
 * proxy keeps every client working correctly; additional capabilities arrive in
 * later MVPs.
 *
 * @packageDocumentation
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import { BASTION_NAME, BASTION_VERSION, type UpstreamManager } from "../core/index.js";
import { logger } from "../observability/index.js";
import { buildControlTools, handleControlTool, isControlToolName } from "./control-tools.js";

/**
 * Construct the client-facing MCP {@link Server} backed by the given manager.
 *
 * The returned server is not yet connected to a transport; the caller is
 * responsible for `server.connect(transport)`.
 *
 * @param manager The upstream manager providing tools, routing, and health.
 */
export function buildBastionServer(manager: UpstreamManager): Server {
  const server = new Server(
    { name: BASTION_NAME, version: BASTION_VERSION },
    { capabilities: { tools: { listChanged: true } } },
  );

  // tools/list — aggregated upstream tools + Bastion's control tools.
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [...manager.listUpstreamTools(), ...buildControlTools(manager.separator)],
  }));

  // tools/call — dispatch control tools locally; route everything else upstream.
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args } = req.params;
    logger.debug({ tool: name }, "tools/call");
    if (isControlToolName(name, manager.separator)) {
      return handleControlTool(name, (args ?? {}) as Record<string, unknown>, manager);
    }
    return manager.callUpstreamTool(name, args ?? {});
  });

  // Propagate upstream availability/tool changes to the client so it re-lists.
  manager.setToolsChangedCallback(() => {
    sendToolListChanged(server).catch((err) =>
      logger.warn({ err: String(err) }, "failed to send tools/list_changed"),
    );
  });

  return server;
}

/**
 * Emit `notifications/tools/list_changed`, tolerant of SDK version differences
 * (newer SDKs expose a typed helper; older ones require a raw notification).
 */
async function sendToolListChanged(server: Server): Promise<void> {
  const maybeTyped = server as unknown as { sendToolListChanged?: () => Promise<void> };
  if (typeof maybeTyped.sendToolListChanged === "function") {
    await maybeTyped.sendToolListChanged();
    return;
  }
  await server.notification({ method: "notifications/tools/list_changed" });
}
