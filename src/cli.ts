#!/usr/bin/env node
/**
 * Command-line entrypoint for mcp-bastion.
 *
 * Responsibilities are intentionally thin: parse arguments, load config, wire the
 * core manager to the client-facing transport (stdio or Streamable HTTP), start
 * health checks, and handle graceful shutdown. All behaviour lives in the layered
 * modules under `src/`.
 *
 * @packageDocumentation
 */
import { Command } from "commander";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { loadConfig } from "./config/index.js";
import { BASTION_VERSION, UpstreamManager } from "./core/index.js";
import { logger } from "./observability/index.js";
import { buildBastionServer, startHttpServer } from "./proxy/index.js";

const program = new Command();

program
  .name("mcp-bastion")
  .description("Reliability + security proxy for the Model Context Protocol (MCP)")
  .version(BASTION_VERSION)
  .requiredOption("-c, --config <path>", "path to the Bastion config file")
  .option("--http <port>", "serve over Streamable HTTP on <port> (overrides listen.mode)")
  .action(run);

program.parseAsync(process.argv).catch((err) => {
  logger.error({ err: (err as Error)?.stack ?? String(err) }, "fatal");
  process.exit(1);
});

/** Boot the proxy for the given CLI options. */
async function run(opts: { config: string; http?: string }): Promise<void> {
  const config = await loadConfig(opts.config);
  const manager = new UpstreamManager(config);

  // Connect upstreams first so the initial tools/list is populated.
  await manager.connectAll();

  // Periodic health checks catch silent disconnects the transport doesn't surface.
  let healthTimer: ReturnType<typeof setInterval> | undefined;
  if (config.healthCheck.enabled) {
    healthTimer = setInterval(() => {
      for (const upstream of manager.upstreamsList()) {
        void upstream.healthCheck(config.healthCheck.timeoutMs);
      }
    }, config.healthCheck.intervalMs);
    healthTimer.unref?.();
  }

  // Resolve the client-facing transport (a `--http <port>` flag overrides config).
  const cliPort = opts.http !== undefined ? Number(opts.http) : undefined;
  if (cliPort !== undefined && !Number.isInteger(cliPort)) {
    throw new Error(`--http expects a port number, got "${opts.http}"`);
  }
  const useHttp = cliPort !== undefined || config.listen.mode === "http";

  let closeListener: () => Promise<void>;
  if (useHttp) {
    const listener = await startHttpServer(manager, {
      host: config.listen.host,
      port: cliPort ?? config.listen.port,
      path: config.listen.path,
    });
    closeListener = () => listener.close();
    logger.info(
      {
        servers: manager.serverNames(),
        version: BASTION_VERSION,
        transport: "http",
        url: listener.url,
      },
      "mcp-bastion started",
    );
  } else {
    const server = buildBastionServer(manager);
    await server.connect(new StdioServerTransport());
    closeListener = async () => {
      try {
        await server.close();
      } catch {
        // Best-effort during shutdown.
      }
    };
    logger.info(
      { servers: manager.serverNames(), version: BASTION_VERSION, transport: "stdio" },
      "mcp-bastion started",
    );
  }

  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, "shutting down");
    if (healthTimer) clearInterval(healthTimer);
    await closeListener();
    await manager.closeAll();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}
