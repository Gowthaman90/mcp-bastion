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
import { serveStdio } from "@modelcontextprotocol/server/stdio";

import { auditKeygen, auditVerify } from "./audit-cli.js";
import { loadConfig, defaultConfig, startupWarnings } from "./config/index.js";
import { BASTION_VERSION, UpstreamManager } from "./core/index.js";
import { logger } from "./observability/index.js";
import {
  broadcastToolsChanged,
  buildBastionServer,
  checkHttpListenOptions,
  resolveListenClients,
  startHttpServer,
} from "./proxy/index.js";

const program = new Command();

program
  .name("mcp-bastion")
  .description("Reliability + security proxy for the Model Context Protocol (MCP)")
  .version(BASTION_VERSION)
  .option(
    "-c, --config <path>",
    "path to the Bastion config file (omit to start with no upstreams — exposes only Bastion's control tools, useful for a zero-config smoke test or catalog introspection)",
  )
  .option("--http <port>", "serve over Streamable HTTP on <port> (overrides listen.mode)")
  .action(run);

const audit = program.command("audit").description("offline tools for Bastion audit logs");
audit
  .command("verify <log>")
  .description(
    "check an audit log's hash chain, seq continuity, signed checkpoints and run links (exit 0 intact, 1 tampered, 2 cannot verify)",
  )
  .option("--checkpoints <file>", "checkpoints from a separate witness sink (JSON lines)")
  .option("--public-key <file>", "Ed25519 public key (PEM) the checkpoints are signed with")
  .option(
    "--key-env <var>",
    "environment variable holding the chain's integrity key",
    "MCP_BASTION_AUDIT_KEY",
  )
  .option("--json", "print the report as JSON")
  .action(
    (
      log: string,
      o: { checkpoints?: string; publicKey?: string; keyEnv?: string; json?: boolean },
    ) => {
      const { code, output } = auditVerify(log, o);
      process.stdout.write(`${output}\n`);
      process.exitCode = code;
    },
  );
audit
  .command("keygen")
  .description("create an Ed25519 key pair for signed audit checkpoints")
  .requiredOption("--out <dir>", "directory for checkpoint-private.pem and checkpoint-public.pem")
  .action((o: { out: string }) => {
    const { code, output } = auditKeygen(o.out);
    process.stdout.write(`${output}\n`);
    process.exitCode = code;
  });

program.parseAsync(process.argv).catch((err) => {
  logger.error({ err: (err as Error)?.stack ?? String(err) }, "fatal");
  process.exit(1);
});

/** Boot the proxy for the given CLI options. */
async function run(opts: { config?: string; http?: string }): Promise<void> {
  const config = opts.config ? await loadConfig(opts.config) : defaultConfig();
  if (!opts.config) {
    logger.warn(
      "no --config provided: starting with no upstream servers, so only Bastion's control tools are exposed. Pass --config <path> to put Bastion in front of your MCP servers.",
    );
  }
  for (const w of startupWarnings(config)) logger[w.level](w.message);
  // Resolve and check the client-facing transport BEFORE any upstream is spawned, so a refused
  // configuration (bad port, unauthenticated public bind, bad client tokens) leaves no child processes.
  const cliPort = opts.http !== undefined ? Number(opts.http) : undefined;
  if (cliPort !== undefined && !Number.isInteger(cliPort)) {
    throw new Error(`--http expects a port number, got "${opts.http}"`);
  }
  const useHttp = cliPort !== undefined || config.listen.mode === "http";
  const clients = useHttp ? resolveListenClients(config.listen) : [];
  if (useHttp) {
    checkHttpListenOptions({
      host: config.listen.host,
      authToken: config.listen.authToken,
      clients,
    });
  }

  const manager = new UpstreamManager(config);
  manager.setToolsChangedCallback(() => broadcastToolsChanged());
  try {
    await startServing(manager, config, { cliPort, useHttp, clients });
  } catch (err) {
    // Upstreams may already be running: close them before the fatal exit so none is orphaned.
    await manager.closeAll().catch(() => undefined);
    throw err;
  }
}

/** Connect upstreams, start health checks and the client-facing transport, and wire shutdown. */
async function startServing(
  manager: UpstreamManager,
  config: Awaited<ReturnType<typeof loadConfig>>,
  t: {
    cliPort: number | undefined;
    useHttp: boolean;
    clients: ReturnType<typeof resolveListenClients>;
  },
): Promise<void> {
  const { cliPort, useHttp, clients } = t;
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

  let closeListener: () => Promise<void>;
  if (useHttp) {
    const listener = await startHttpServer(manager, {
      host: config.listen.host,
      port: cliPort ?? config.listen.port,
      path: config.listen.path,
      authToken: config.listen.authToken,
      clients,
      maxSessions: config.listen.maxSessions,
      maxBodyBytes: config.listen.maxBodyBytes,
      validateRoutingHeaders: config.listen.validateRoutingHeaders,
      legacy: config.listen.legacy,
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
    // SDK 2.0 stdio entry: negotiates the era at connection open; `legacy: "reject"` refuses
    // pre-2026-07-28 clients (downgrade prevention) when configured.
    const handle = serveStdio(
      () => buildBastionServer(manager, { principal: "stdio", persistent: true }),
      { legacy: config.listen.legacy === "reject" ? "reject" : "serve" },
    );
    closeListener = async () => {
      try {
        await handle.close();
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
