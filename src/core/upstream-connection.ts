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
import {
  Client,
  SdkErrorCode,
  SdkHttpError,
  StreamableHTTPClientTransport,
  UnauthorizedError,
} from "@modelcontextprotocol/client";
import type {
  CacheableRequestOptions,
  FetchLike,
  McpSubscription,
  ProtocolEra,
} from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import type { Tool } from "@modelcontextprotocol/server";

import type { ReconnectConfig, ServerConfig } from "../config/index.js";
import {
  DelegationBlockedError,
  MissingForwardedHeaderError,
  UpstreamDisconnectedError,
} from "../errors.js";
import {
  checkCachePolicy,
  checkTransportSecurity,
  clampCacheHints,
  readCacheHints,
  type CacheHints,
  type ClampedCacheHints,
} from "../security/index.js";
import { buildEnv, withTimeout } from "../internal/index.js";
import { logger } from "../observability/index.js";
import { BASTION_NAME, BASTION_VERSION } from "./constants.js";
import { currentRequestContext, runOutsideRequest } from "./request-context.js";
import type { ConnectionState } from "./types.js";

/** A callback fired whenever an upstream's availability or tool set changes. */
export type UpstreamChangeListener = () => void;

type ClientTransport = StdioClientTransport | StreamableHTTPClientTransport;

/** Extra MRTR fields forwarded on a retry (MCP 2026-07-28). */
export interface CallToolExtra {
  inputResponses?: Record<string, unknown>;
  requestState?: string;
}

/** Map the configured `protocol` to the SDK's negotiation mode. */
function negotiationMode(
  protocol: "auto" | "legacy" | "2026-07-28",
): "auto" | "legacy" | { pin: string } {
  if (protocol === "2026-07-28") return { pin: "2026-07-28" };
  return protocol;
}

/** Header names that indicate a request carries authentication. */
const AUTH_HEADERS = ["authorization", "x-api-key", "api-key", "apikey", "x-auth-token", "cookie"];

/** Whether the given headers include a recognized authentication header. */
function headersCarryAuth(
  headers: Record<string, string> | undefined,
  extra: ReadonlySet<string> = new Set(),
): boolean {
  if (!headers) return false;
  const present = new Set(Object.keys(headers).map((k) => k.toLowerCase()));
  return AUTH_HEADERS.some((h) => present.has(h)) || [...extra].some((h) => present.has(h));
}

/** Whether an upstream error is an HTTP 401: the upstream refused the credentials it was sent. */
export function isAuthFailure(err: unknown): boolean {
  if (err instanceof UnauthorizedError) return true;
  if (err instanceof SdkHttpError) {
    return err.status === 401 || err.code === SdkErrorCode.ClientHttpAuthentication;
  }
  return false;
}

/** One `forwardHeaders` entry, names lower-cased. */
interface ForwardRule {
  /** Header name sent upstream. */
  upstream: string;
  /** Header name read from the downstream request. */
  incoming: string;
}

export class UpstreamConnection {
  private client: Client | null = null;
  private transport: ClientTransport | null = null;
  /** Modern-era change stream (`subscriptions/listen`), when the upstream speaks 2026-07-28. */
  private subscription: McpSubscription | null = null;
  private connectionState: ConnectionState = "disconnected";
  private lastErrorMessage?: string;
  private cachedTools: Tool[] = [];
  private reconnectAttempts = 0;
  private reconnectTimer?: ReturnType<typeof setTimeout>;
  /** When `true`, a close was requested by us and must NOT trigger auto-reconnect. */
  private closedByRequest = false;
  /** Caching hints the upstream attached to its last `tools/list` (MCP 2026-07-28), as sent. */
  private rawCacheHints: CacheHints = {};
  /** The same hints after policy: TTL clamped, scope narrowed. `undefined` until a list carried hints. */
  private policedCacheHints?: ClampedCacheHints;
  /** Gateway-mode header forwarding rules (empty unless `forwardHeaders` is configured). */
  private readonly forward: readonly ForwardRule[];
  /** Configured `authHeaders`, lower-cased. */
  private readonly authHeaderNames: ReadonlySet<string>;
  /** In-flight on-demand connect, shared by concurrent first requests. */
  private connecting?: Promise<void>;
  /**
   * Set when a forwarding upstream announces `tools/list_changed`: the re-list waits for the next
   * downstream request so it carries that request's identity rather than none.
   */
  private toolsStale = false;

  /**
   * @param name         The configured name of this upstream.
   * @param config       Transport/launch configuration for the upstream.
   * @param reconnectCfg Reconnect policy applied on unexpected disconnects.
   * @param onChange     Invoked whenever availability or the tool set changes.
   * @param policy       Cache-hint policy (`maxCacheTtlMs`) applied to upstream list results, and
   *                     `delegationBlock`: the delegation rules that block this upstream in the
   *                     current request (the fetch backstop refuses to send while any do).
   */
  constructor(
    public readonly name: string,
    private readonly config: ServerConfig,
    private readonly reconnectCfg: ReconnectConfig,
    private readonly onChange: UpstreamChangeListener = () => {},
    private readonly policy: {
      maxCacheTtlMs?: number;
      delegationBlock?: () => Promise<readonly string[]>;
    } = {},
  ) {
    const http = config.transport === "http" ? config : undefined;
    this.forward = Object.entries(http?.forwardHeaders ?? {}).map(([upstream, incoming]) => ({
      upstream: upstream.toLowerCase(),
      incoming: incoming.toLowerCase(),
    }));
    this.authHeaderNames = new Set((http?.authHeaders ?? []).map((h) => h.toLowerCase()));
    if (this.connectMode === "onDemand") this.connectionState = "idle";
  }

  /** `startup` connects at boot; `onDemand` connects on the first request that needs it. */
  get connectMode(): "startup" | "onDemand" {
    return this.config.transport === "http" ? this.config.connect : "startup";
  }

  /** Incoming (downstream) header names this upstream forwards, lower-cased. */
  get forwardedIncomingHeaders(): string[] {
    return this.forward.map((f) => f.incoming);
  }

  /**
   * Incoming headers this upstream needs that the current downstream request did not carry, when
   * that is an error (`onMissingForwardedHeader: "error"`). Outside any request nothing was carried.
   */
  missingForwardedHeaders(): string[] {
    if (this.forward.length === 0 || this.onMissing !== "error") return [];
    const headers = currentRequestContext()?.headers;
    return this.forward.filter((f) => !headers?.has(f.incoming)).map((f) => f.incoming);
  }

  /** Upstream header names that will be forwarded for the current request (names only, never values). */
  presentForwardedHeaders(): string[] {
    const headers = currentRequestContext()?.headers;
    if (!headers) return [];
    return this.forward.filter((f) => headers.has(f.incoming)).map((f) => f.upstream);
  }

  private get onMissing(): "error" | "omit" {
    return this.config.transport === "http" ? this.config.onMissingForwardedHeader : "error";
  }

  /**
   * Get this upstream ready to serve the current downstream request: connect an idle `onDemand`
   * upstream (with the request's forwarded headers), or re-list tools a change notification marked
   * stale. Concurrent first requests share one connect.
   *
   * @throws The connect / `tools/list` error, e.g. an HTTP 401 (see {@link isAuthFailure}).
   */
  async prepareForRequest(): Promise<void> {
    // Plain upstreams keep today's behaviour exactly: nothing to prepare per request.
    if (this.connectMode !== "onDemand" && this.forward.length === 0) return;
    // A connect in flight (ours or another request's) is "connected" before its first tools/list
    // has landed; wait for the whole of it, not just the state flip.
    while (this.connecting) await this.connecting.catch(() => undefined);
    if (this.isConnected()) {
      if (!this.toolsStale) return;
      this.toolsStale = false;
      try {
        await this.refreshTools(true);
      } catch (err) {
        this.toolsStale = true;
        this.lastErrorMessage = this.errorMessage(err);
        throw err;
      }
      return;
    }
    if (this.connectMode !== "onDemand") return;
    await this.connect();
  }

  /**
   * A message for an upstream failure that is safe to log, audit, or return: an HTTP 401 is named as
   * an authentication failure, and any forwarded header value is scrubbed out.
   */
  errorMessage(err: unknown): string {
    if (isAuthFailure(err)) {
      return `authentication failed: "${this.name}" answered HTTP 401 Unauthorized to the credentials it was sent`;
    }
    return this.scrub((err as Error)?.message ?? String(err));
  }

  /** Record a failure from a tool call as this upstream's last error; returns the safe message. */
  noteFailure(err: unknown): string {
    this.lastErrorMessage = this.errorMessage(err);
    return this.lastErrorMessage;
  }

  /** Remove the current request's forwarded header values from `text`. */
  private scrub(text: string): string {
    const headers = currentRequestContext()?.headers;
    if (!headers) return text;
    let out = text;
    for (const { incoming } of this.forward) {
      const value = headers.get(incoming);
      if (value && value.length >= 4) out = out.split(value).join("[redacted]");
    }
    return out;
  }

  /**
   * The `fetch` given to the HTTP transport when `forwardHeaders` is configured. It runs at send
   * time inside the async context of whichever downstream request caused the send, so it reads that
   * request's headers and no other. Outside a request only the static `headers` are sent.
   */
  private readonly forwardingFetch: FetchLike = async (url, init) => {
    const ctx = currentRequestContext();
    if (!ctx) return fetch(url, init);
    const headers = new Headers(init?.headers);
    const missing: string[] = [];
    for (const { upstream, incoming } of this.forward) {
      const value = ctx.headers.get(incoming);
      if (value !== undefined) headers.set(upstream, value);
      else if (this.onMissing === "error") missing.push(incoming);
    }
    // Backstop for every path (connect, list, call, ping): nothing is sent without the identity.
    if (missing.length > 0) throw new MissingForwardedHeaderError(this.name, missing);
    // ...and no delegate token is sent whose request verdict blocks this upstream (covers SSE GET and
    // reconnects made inside the request, which skip the manager's pre-flight check).
    const blocking = (await this.policy.delegationBlock?.()) ?? [];
    if (blocking.length > 0) throw new DelegationBlockedError(this.name, blocking);
    return fetch(url, { ...init, headers });
  };

  /**
   * Policed caching hints for this upstream's tool list (MCP 2026-07-28): never a longer TTL than
   * `maxCacheTtlMs`, never `"public"` when the upstream is authenticated. `undefined` when the upstream
   * sent no hints, so pre-revision servers add nothing to Bastion's own list result.
   */
  get cacheHints(): ClampedCacheHints | undefined {
    return this.policedCacheHints;
  }

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

  /** Negotiated protocol era (`legacy` = pre-2026-07-28 `initialize`; `modern` = 2026-07-28). */
  get era(): ProtocolEra | undefined {
    return this.client?.getProtocolEra();
  }

  /** Which transport this upstream uses. */
  get transportKind(): "stdio" | "http" {
    return this.config.transport === "http" ? "http" : "stdio";
  }

  /**
   * Authentication status:
   * - `null` for local stdio servers (not applicable);
   * - `true`/`false` for HTTP servers, based on whether an auth header is configured: a standard
   *   one, one named in `authHeaders`, or any `forwardHeaders` entry.
   */
  isAuthenticated(): boolean | null {
    if (this.config.transport !== "http") return null;
    if (this.forward.length > 0) return true;
    return headersCarryAuth(this.config.headers, this.authHeaderNames);
  }

  /** Construct the transport for this upstream's configured protocol. */
  private createTransport(): ClientTransport {
    if (this.config.transport === "http") {
      const options = {
        ...(this.config.headers ? { requestInit: { headers: this.config.headers } } : {}),
        ...(this.forward.length > 0 ? { fetch: this.forwardingFetch } : {}),
      };
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
    const attempt = this.establish();
    this.connecting = attempt;
    try {
      await attempt;
    } finally {
      if (this.connecting === attempt) this.connecting = undefined;
    }
  }

  /** One connect attempt: transport, handshake, first `tools/list`. */
  private async establish(): Promise<void> {
    this.closedByRequest = false;
    this.connectionState = this.reconnectAttempts > 0 ? "reconnecting" : "connecting";

    if (this.config.transport === "http" && !this.isAuthenticated()) {
      logger.warn(
        { server: this.name, url: this.config.url },
        "upstream reached over HTTP without an authentication header",
      );
    }
    if (this.config.transport === "http") {
      for (const finding of checkTransportSecurity(this.config.url)) {
        logger.warn(
          { server: this.name, url: this.config.url, rule: finding.rule },
          "insecure upstream transport: plaintext HTTP to a remote host (MITM exposure)",
        );
      }
    }

    const transport = this.createTransport();
    transport.onclose = () => this.handleUnexpectedClose();
    transport.onerror = (err: Error) => {
      this.lastErrorMessage = this.errorMessage(err);
      logger.warn({ server: this.name, err: this.lastErrorMessage }, "upstream transport error");
    };

    // SDK 2.0 client. Bastion is a gateway, so it never auto-fulfils an `input_required` round —
    // the continuation is relayed to *its* client, whose user answers. Era negotiation follows the
    // upstream's configured `protocol` (default `auto`: probe 2026-07-28, fall back to `initialize`).
    const client = new Client(
      { name: BASTION_NAME, version: BASTION_VERSION },
      {
        // A gateway advertises the input capabilities its *own* clients may have, so an upstream is
        // allowed to answer `input_required`; Bastion relays (and gates) each round downstream.
        capabilities: { elicitation: { form: {}, url: {} }, sampling: {} },
        versionNegotiation: { mode: negotiationMode(this.config.protocol) },
        inputRequired: { autoFulfill: false },
      },
    );
    // Re-list tools when the upstream announces a change. Without this, the cached tool set (and
    // thus rug-pull detection) only refreshes at connect, so a mid-session definition swap advertised
    // via `notifications/tools/list_changed` would be missed until the next reconnect. Refreshing the
    // cache here means the change is re-hashed and caught by the security re-sync before the next
    // tool call. A raw notification handler is used (not the SDK's list-diffing option) because a
    // rug pull changes a *description*, not the set of names.
    client.setNotificationHandler("notifications/tools/list_changed", () => {
      // A forwarding upstream is re-listed on the next downstream request, under that request's
      // identity; a background re-list would carry no identity (or a stale one).
      if (this.forward.length > 0) {
        this.toolsStale = true;
        return;
      }
      void runOutsideRequest(() => this.refreshTools(true)).catch((err) =>
        logger.warn(
          { server: this.name, err: this.errorMessage(err) },
          "failed to refresh tools after list_changed",
        ),
      );
    });

    try {
      await client.connect(transport);
      this.client = client;
      this.transport = transport;
      this.connectionState = "connected";
      this.reconnectAttempts = 0;
      this.lastErrorMessage = undefined;
      await this.refreshTools();
      // Modern-era upstreams push nothing unsolicited: open the change stream explicitly.
      if (client.getProtocolEra() === "modern") {
        try {
          this.subscription = await client.listen({ toolsListChanged: true });
        } catch (err) {
          logger.debug(
            { server: this.name, err: (err as Error)?.message ?? String(err) },
            "no change stream",
          );
        }
      }
      logger.info(
        { server: this.name, tools: this.cachedTools.length, era: client.getProtocolEra() },
        "upstream connected",
      );
      this.onChange();
    } catch (err) {
      this.lastErrorMessage = this.errorMessage(err);
      this.client = null;
      this.transport = null;
      logger.error({ server: this.name, err: this.lastErrorMessage }, "upstream connect failed");
      if (this.connectMode === "onDemand") {
        // No reconnect timer: the next request that needs this upstream connects it, with its own
        // identity. A 401 in particular must not turn into a retry storm.
        this.connectionState = "idle";
        this.closedByRequest = true;
        await client.close().catch(() => undefined);
      } else {
        this.connectionState = "disconnected";
        this.scheduleReconnect();
      }
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
    // An on-demand upstream is only ever reached with a caller's identity; a timer has none.
    if (this.connectMode === "onDemand") return this.isConnected();
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
  async callTool(toolName: string, args: unknown, extra: CallToolExtra = {}): Promise<unknown> {
    if (!this.isConnected() || !this.client) {
      throw new UpstreamDisconnectedError(this.name);
    }
    const params: Record<string, unknown> = {
      name: toolName,
      arguments: (args ?? {}) as Record<string, unknown>,
    };
    if (extra.inputResponses) params.inputResponses = extra.inputResponses;
    if (extra.requestState !== undefined) params.requestState = extra.requestState;
    // `allowInputRequired` lets an `input_required` continuation come back as a value instead of
    // being auto-fulfilled or rejected — a gateway relays it.
    return this.client.callTool(
      params as unknown as Parameters<Client["callTool"]>[0],
      { allowInputRequired: true } as unknown as Parameters<Client["callTool"]>[1],
    );
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
    if (this.subscription) {
      await this.subscription.close().catch(() => undefined);
      this.subscription = null;
    }
    this.client = null;
    this.transport = null;
    if (requested) this.connectionState = this.connectMode === "onDemand" ? "idle" : "disconnected";
  }

  /**
   * Fetch the current tool list from the upstream, notifying listeners on change.
   *
   * A `list_changed` notification invalidates any cached copy immediately (the spec's rule for
   * notifications arriving while a response is still fresh), which is why this re-lists at once
   * rather than waiting out a TTL — a stale cache would otherwise hide the very definition change
   * that rug-pull pinning exists to catch.
   *
   * @param afterInvalidation `true` when triggered by `notifications/tools/list_changed`.
   */
  private async refreshTools(afterInvalidation = false): Promise<void> {
    if (!this.client) return;
    const before = this.cachedTools.map((t) => t.name).join(" ");
    // Bypass the SDK client's own list cache: Bastion polices cache hints itself and must see the
    // upstream's current definitions (a stale cache would hide exactly the rug pull pinning catches).
    const result = await this.client.listTools(undefined, {
      cacheMode: "bypass",
    } as CacheableRequestOptions);
    // The client and server packages each bundle their own (structurally equal) `Tool` type.
    this.cachedTools = result.tools as unknown as Tool[];
    this.policeCacheHints(result, afterInvalidation);
    const after = this.cachedTools.map((t) => t.name).join(" ");
    if (before !== after) this.onChange();
  }

  /**
   * Apply cache policy (MCP 2026-07-28) to the hints on a list result: log every violation and
   * retain a clamped copy for Bastion's own downstream `tools/list`.
   */
  private policeCacheHints(result: unknown, afterInvalidation: boolean): void {
    this.rawCacheHints = readCacheHints(result);
    if (this.rawCacheHints.ttlMs === undefined && this.rawCacheHints.cacheScope === undefined) {
      this.policedCacheHints = undefined;
      return;
    }
    const ctx = {
      maxTtlMs: this.policy.maxCacheTtlMs,
      authenticated: this.isAuthenticated() === true,
      // We have just re-listed, so no invalidation is pending; the notification is what caused this.
      invalidationPending: false,
    };
    for (const f of checkCachePolicy(result, ctx)) {
      logger.warn(
        { server: this.name, rule: f.rule, afterInvalidation },
        `cache policy: ${f.excerpt}`,
      );
    }
    this.policedCacheHints = clampCacheHints(result, ctx);
    if (this.policedCacheHints.changed) {
      logger.info(
        { server: this.name, requested: this.rawCacheHints, applied: this.policedCacheHints },
        "cache hints clamped",
      );
    }
  }

  /** Transition to `disconnected` on an unexpected transport close and schedule recovery. */
  private handleUnexpectedClose(): void {
    if (this.closedByRequest) return;
    // Ignore spurious closes once we're already tearing down / retrying.
    if (
      this.connectionState === "disconnected" ||
      this.connectionState === "reconnecting" ||
      this.connectionState === "idle"
    ) {
      return;
    }

    logger.warn({ server: this.name }, "upstream disconnected unexpectedly");
    this.client = null;
    this.transport = null;
    if (this.connectMode === "onDemand") {
      this.connectionState = "idle";
      this.onChange();
      return;
    }
    this.connectionState = "disconnected";
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
      // Never inherit the identity of the request whose failure scheduled this retry.
      void runOutsideRequest(() => this.connect()).catch(() => {
        // connect() already scheduled the next attempt on failure.
      });
    }, delay);
    // Never keep the process alive solely for a pending reconnect timer.
    this.reconnectTimer.unref?.();
  }
}
