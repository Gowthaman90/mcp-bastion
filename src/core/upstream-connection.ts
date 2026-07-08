/**
 * Lifecycle management for a single upstream MCP server.
 *
 * An {@link UpstreamConnection} owns exactly one upstream: it connects to the
 * server as an MCP *client*, caches the server's tool list, health-checks it,
 * and — the core of the v0.1 reliability MVP — detects silent disconnects and
 * transparently reconnects with exponential backoff.
 *
 * @packageDocumentation
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

import type { ReconnectConfig, ServerConfig } from "../config/index.js";
import { UpstreamDisconnectedError } from "../errors.js";
import { buildEnv, withTimeout } from "../internal/index.js";
import { logger } from "../observability/index.js";
import { BASTION_NAME, BASTION_VERSION } from "./constants.js";
import type { ConnectionState } from "./types.js";

/** A callback fired whenever an upstream's availability or tool set changes. */
export type UpstreamChangeListener = () => void;

type ClientTransport = StdioClientTransport | StreamableHTTPClientTransport;

/** Header names that indicate a request carries authentication. */
const AUTH_HEADERS = ["authorization", "x-api-key", "api-key", "apikey", "x-auth-token", "cookie"];

/** Whether the given headers include a recognized authentication header. */
function headersCarryAuth(headers: Record<string, string> | undefined): boolean {
  if (!headers) return false;
  const present = new Set(Object.keys(headers).map((k) => k.toLowerCase()));
  return AUTH_HEADERS.some((h) => present.has(h));
}

export class UpstreamConnection {
  private client: Client | null = null;
  private transport: ClientTransport | null = null;
  private connectionState: ConnectionState = "disconnected";
  private lastErrorMessage?: string;
  private cachedTools: Tool[] = [];
  private reconnectAttempts = 0;
  private reconnectTimer?: ReturnType<typeof setTimeout>;
  /** When `true`, a close was requested by us and must NOT trigger auto-reconnect. */
  private closedByRequest = false;

  /**
   * @param name         The configured name of this upstream.
   * @param config       Transport/launch configuration for the upstream.
   * @param reconnectCfg Reconnect policy applied on unexpected disconnects.
   * @param onChange     Invoked whenever availability or the tool set changes.
   */
  constructor(
    public readonly name: string,
    private readonly config: ServerConfig,
    private readonly reconnectCfg: ReconnectConfig,
    private readonly onChange: UpstreamChangeListener = () => {},
  ) {}

  /** Current lifecycle state. */
  get state(): ConnectionState {
    return this.connectionState;
  }

  /** Most recent error message, if any. */
  get lastError(): string | undefined {
    return this.lastErrorMessage;
  }

  /** The tools most recently advertised by this upstream (retained across disconnects). */
  get lastKnownTools(): readonly Tool[] {
    return this.cachedTools;
  }

  /** `true` iff the upstream is connected and usable. */
  isConnected(): boolean {
    return this.connectionState === "connected" && this.client !== null;
  }

  /** Which transport this upstream uses. */
  get transportKind(): "stdio" | "http" {
    return this.config.transport === "http" ? "http" : "stdio";
  }

  /**
   * Authentication status:
   * - `null` for local stdio servers (not applicable);
   * - `true`/`false` for HTTP servers, based on whether an auth header is configured.
   */
  isAuthenticated(): boolean | null {
    if (this.config.transport !== "http") return null;
    return headersCarryAuth(this.config.headers);
  }

  /** Construct the transport for this upstream's configured protocol. */
  private createTransport(): ClientTransport {
    if (this.config.transport === "http") {
      const options = this.config.headers
        ? { requestInit: { headers: this.config.headers } }
        : undefined;
      return new StreamableHTTPClientTransport(new URL(this.config.url), options);
    }
    return new StdioClientTransport({
      command: this.config.command,
      args: this.config.args,
      env: buildEnv(this.config.env),
      cwd: this.config.cwd,
    });
  }

  /**
   * Establish (or re-establish) the connection and refresh the cached tool list.
   *
   * On failure the state is set to `disconnected`, a reconnect is scheduled (if
   * enabled), and the originating error is re-thrown for the caller to observe.
   *
   * @throws The underlying transport/connect error on failure.
   */
  async connect(): Promise<void> {
    this.closedByRequest = false;
    this.connectionState = this.reconnectAttempts > 0 ? "reconnecting" : "connecting";

    if (this.config.transport === "http" && !this.isAuthenticated()) {
      logger.warn(
        { server: this.name, url: this.config.url },
        "upstream reached over HTTP without an authentication header",
      );
    }

    const transport = this.createTransport();
    transport.onclose = () => this.handleUnexpectedClose();
    transport.onerror = (err: Error) => {
      this.lastErrorMessage = err?.message ?? String(err);
      logger.warn({ server: this.name, err: this.lastErrorMessage }, "upstream transport error");
    };

    const client = new Client(
      { name: BASTION_NAME, version: BASTION_VERSION },
      { capabilities: {} },
    );

    try {
      await client.connect(transport);
      this.client = client;
      this.transport = transport;
      this.connectionState = "connected";
      this.reconnectAttempts = 0;
      this.lastErrorMessage = undefined;
      await this.refreshTools();
      logger.info({ server: this.name, tools: this.cachedTools.length }, "upstream connected");
      this.onChange();
    } catch (err) {
      this.lastErrorMessage = (err as Error)?.message ?? String(err);
      this.connectionState = "disconnected";
      this.client = null;
      this.transport = null;
      logger.error({ server: this.name, err: this.lastErrorMessage }, "upstream connect failed");
      this.scheduleReconnect();
      throw err;
    }
  }

  /**
   * Probe the upstream with a `ping`. On failure the connection is treated as a
   * silent disconnect (which triggers the normal reconnect flow).
   *
   * @param timeoutMs Per-probe timeout in milliseconds.
   * @returns `true` if the upstream responded in time, otherwise `false`.
   */
  async healthCheck(timeoutMs: number): Promise<boolean> {
    if (!this.isConnected() || !this.client) return false;
    try {
      await withTimeout(this.client.ping(), timeoutMs, "ping timeout");
      return true;
    } catch (err) {
      logger.warn(
        { server: this.name, err: (err as Error)?.message ?? String(err) },
        "health check failed; marking disconnected",
      );
      this.handleUnexpectedClose();
      return false;
    }
  }

  /**
   * Invoke a tool on this upstream.
   *
   * @param toolName The tool's original (un-namespaced) name.
   * @param args     Tool arguments.
   * @returns The upstream's raw `CallToolResult`.
   * @throws {@link UpstreamDisconnectedError} if the upstream is not connected.
   */
  async callTool(toolName: string, args: unknown): Promise<unknown> {
    if (!this.isConnected() || !this.client) {
      throw new UpstreamDisconnectedError(this.name);
    }
    return this.client.callTool({
      name: toolName,
      arguments: (args ?? {}) as Record<string, unknown>,
    });
  }

  /**
   * Force a clean reconnect: tear down the current connection and connect afresh,
   * resetting the backoff counter. Used by the `bastion__reconnect` control tool.
   */
  async manualReconnect(): Promise<void> {
    await this.close(true);
    this.reconnectAttempts = 0;
    await this.connect();
  }

  /**
   * Tear down the connection.
   *
   * @param requested When `true` (default), the close was intentional and
   *   auto-reconnect is suppressed. Pass `false` only to model an unexpected drop.
   */
  async close(requested = true): Promise<void> {
    this.closedByRequest = requested;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    try {
      await this.client?.close();
    } catch {
      // Best-effort: the transport may already be gone.
    }
    this.client = null;
    this.transport = null;
    if (requested) this.connectionState = "disconnected";
  }

  /** Fetch the current tool list from the upstream, notifying listeners on change. */
  private async refreshTools(): Promise<void> {
    if (!this.client) return;
    const before = this.cachedTools.map((t) => t.name).join(" ");
    const { tools } = await this.client.listTools();
    this.cachedTools = tools;
    const after = tools.map((t) => t.name).join(" ");
    if (before !== after) this.onChange();
  }

  /** Transition to `disconnected` on an unexpected transport close and schedule recovery. */
  private handleUnexpectedClose(): void {
    if (this.closedByRequest) return;
    // Ignore spurious closes once we're already tearing down / retrying.
    if (this.connectionState === "disconnected" || this.connectionState === "reconnecting") return;

    logger.warn({ server: this.name }, "upstream disconnected unexpectedly");
    this.connectionState = "disconnected";
    this.client = null;
    this.transport = null;
    this.onChange();
    this.scheduleReconnect();
  }

  /** Schedule the next reconnect attempt using capped exponential backoff. */
  private scheduleReconnect(): void {
    if (!this.reconnectCfg.auto) return;
    if (this.reconnectTimer) return;

    const { maxRetries } = this.reconnectCfg;
    if (maxRetries >= 0 && this.reconnectAttempts >= maxRetries) {
      this.connectionState = "failed";
      logger.error(
        { server: this.name, attempts: this.reconnectAttempts },
        "giving up: max reconnect attempts reached",
      );
      this.onChange();
      return;
    }

    const delay = Math.min(
      this.reconnectCfg.initialBackoffMs * 2 ** this.reconnectAttempts,
      this.reconnectCfg.maxBackoffMs,
    );
    this.reconnectAttempts += 1;
    this.connectionState = "reconnecting";
    logger.info(
      { server: this.name, delayMs: delay, attempt: this.reconnectAttempts },
      "scheduling reconnect",
    );

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      void this.connect().catch(() => {
        // connect() already scheduled the next attempt on failure.
      });
    }, delay);
    // Never keep the process alive solely for a pending reconnect timer.
    this.reconnectTimer.unref?.();
  }
}
