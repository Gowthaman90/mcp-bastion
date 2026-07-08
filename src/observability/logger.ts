/**
 * Structured logging for mcp-bastion.
 *
 * @packageDocumentation
 */
import pino from "pino";

/**
 * The shared application logger.
 *
 * CRITICAL INVARIANT: on the stdio transport, **stdout is the JSON-RPC channel**.
 * All log output MUST go to stderr (file descriptor 2), or it corrupts the
 * protocol stream and breaks the client connection. This is the single most
 * important rule in a stdio MCP proxy, so we pin the destination explicitly.
 *
 * The log level is controlled by the `BASTION_LOG_LEVEL` environment variable
 * (default: `info`).
 */
export const logger = pino(
  {
    level: process.env.BASTION_LOG_LEVEL ?? "info",
    base: { name: "mcp-bastion" },
  },
  pino.destination(2), // 2 = stderr
);

/** The logger type, for annotating child loggers and injected dependencies. */
export type Logger = typeof logger;
