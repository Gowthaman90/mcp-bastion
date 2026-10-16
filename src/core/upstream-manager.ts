/**
 * Aggregation and routing across all configured upstream MCP servers.
 *
 * The {@link UpstreamManager} is the heart of the reliability MVP. It owns one
 * {@link UpstreamConnection} per configured server and presents a single, merged
 * view of their tools to the proxy layer:
 *
 * - **listing** — namespaced tools from currently-connected upstreams;
 * - **routing** — dispatching a namespaced tool call to the right upstream,
 *   translating unavailability into legible, recoverable messages;
 * - **health** — a status snapshot and an on-demand reconnect.
 *
 * It deliberately knows nothing about the MCP server surface or the control
 * tools; that composition happens one layer up, in `proxy/`.
 *
 * @packageDocumentation
 */
import type { InputRequiredResult, Tool } from "@modelcontextprotocol/server";

import { AuditEngine, createSinks, type ComplianceReport } from "../audit/index.js";
import type { BastionConfig } from "../config/index.js";
import { MissingForwardedHeaderError, UpstreamDisconnectedError } from "../errors.js";
import { textResult } from "../internal/index.js";
import { logger } from "../observability/index.js";
import {
  generateRequestStateKey,
  isInputRequired,
  openRequestState,
  runPipeline,
  sealRequestState,
  SecurityEngine,
} from "../security/index.js";
import type {
  Interceptor,
  ToolCallContext,
  ToolCallOutcome,
  ToolSecurityReport,
} from "../security/index.js";
import { ControlAction, controlToolName } from "./constants.js";
import type { ReconnectResult, ServerStatus, ToolRoute } from "./types.js";
import { isAuthFailure, UpstreamConnection } from "./upstream-connection.js";

export class UpstreamManager {
  private readonly upstreams = new Map<string, UpstreamConnection>();
  private readonly namespaceSeparator: string;
  private readonly security: SecurityEngine;
  private readonly audit?: AuditEngine;
  private readonly interceptors: readonly Interceptor[];
  private toolsChangedListener: () => void = () => {};
  /** Per-server manual-reconnect timestamps — bounds agent-driven subprocess thrash (M5). */
  private readonly lastReconnectAt = new Map<string, number>();
  /** HMAC key sealing `requestState` envelopes (MCP 2026-07-28 MRTR custody). */
  private readonly requestStateKey: Uint8Array;
  private readonly requestStateTtlSeconds: number;

  /**
   * @param config The validated Bastion configuration.
   */
  constructor(config: BastionConfig) {
    this.namespaceSeparator = config.namespace.separator;
    const configuredKey =
      config.security.requestStateKey ?? process.env.MCP_BASTION_REQUEST_STATE_KEY;
    this.requestStateKey = configuredKey
      ? Buffer.from(configuredKey, "utf8")
      : generateRequestStateKey();
    this.requestStateTtlSeconds = config.security.requestStateTtlSeconds;
    this.security = new SecurityEngine(config.security, this.namespaceSeparator);

    // Audit is placed FIRST so it records blocked calls (short-circuited by the
    // security interceptors) as well as allowed ones.
    if (config.audit.enabled) {
      this.audit = new AuditEngine(config.audit, createSinks(config.audit.sinks));
      this.interceptors = [this.audit.buildInterceptor(), ...this.security.buildInterceptors()];
    } else {
      this.interceptors = this.security.buildInterceptors();
    }

    for (const [name, serverConfig] of Object.entries(config.servers)) {
      this.upstreams.set(
        name,
        new UpstreamConnection(
          name,
          serverConfig,
          config.reconnect,
          () => this.toolsChangedListener(),
          { maxCacheTtlMs: config.security.maxCacheTtlMs },
        ),
      );
    }
  }

  /**
   * Caching hints for the aggregate tool list (MCP 2026-07-28), derived from the policed hints of
   * every connected upstream that sent any: the TTL is the *shortest* clamped TTL and the scope is
   * `"public"` only if every contributing upstream may be cached publicly. Returns `undefined` when
   * no upstream sent hints, so pre-revision deployments see an unchanged `tools/list`.
   */
  listCacheHints(): { ttlMs: number; cacheScope: "public" | "private" } | undefined {
    let ttlMs: number | undefined;
    let cacheScope: "public" | "private" = "public";
    for (const upstream of this.upstreams.values()) {
      if (!upstream.isConnected()) continue;
      const hints = upstream.cacheHints;
      if (!hints) continue;
      ttlMs = ttlMs === undefined ? hints.ttlMs : Math.min(ttlMs, hints.ttlMs);
      if (hints.cacheScope === "private") cacheScope = "private";
    }
    return ttlMs === undefined ? undefined : { ttlMs, cacheScope };
  }

  /** The configured namespace separator (used by the proxy layer for control tools). */
  get separator(): string {
    return this.namespaceSeparator;
  }

  /**
   * Register a callback fired whenever the aggregate tool list may have changed
   * (an upstream connected, dropped, recovered, or changed its tools).
   */
  setToolsChangedCallback(listener: () => void): void {
    this.toolsChangedListener = listener;
  }

  /**
   * Connect all `startup` upstreams concurrently. Individual failures are non-fatal (they
   * auto-reconnect). `onDemand` upstreams stay idle until a request needs them.
   */
  async connectAll(): Promise<void> {
    await Promise.allSettled(
      [...this.upstreams.values()]
        .filter((u) => u.connectMode === "startup")
        .map((u) => u.connect()),
    );
  }

  /**
   * Incoming header names any upstream forwards (lower-cased). The HTTP listener keeps only these
   * from each request, so no other incoming header can reach an upstream.
   */
  forwardedIncomingHeaders(): string[] {
    const names = new Set<string>();
    for (const upstream of this.upstreams.values()) {
      for (const h of upstream.forwardedIncomingHeaders) names.add(h);
    }
    return [...names];
  }

  /**
   * Before a `tools/list`: connect every idle `onDemand` upstream the current request can reach
   * (it carries the headers that upstream forwards), and re-list any marked stale. Failures are
   * logged and recorded as the upstream's `lastError`; the list simply omits that upstream.
   */
  async prepareUpstreams(): Promise<void> {
    await Promise.allSettled(
      [...this.upstreams.values()].map(async (upstream) => {
        if (upstream.missingForwardedHeaders().length > 0) return;
        try {
          await upstream.prepareForRequest();
        } catch (err) {
          logger.warn(
            { server: upstream.name, err: upstream.errorMessage(err) },
            "upstream not available for this request",
          );
        }
      }),
    );
  }

  /**
   * The aggregate, namespaced tool list from currently-connected upstreams.
   *
   * Control tools are intentionally NOT included here — the proxy layer appends
   * them — keeping this method focused on upstream aggregation.
   */
  listUpstreamTools(): Tool[] {
    this.syncSecurity(); // pin definitions on discovery so later changes are caught
    const tools: Tool[] = [];
    for (const [name, upstream] of this.upstreams) {
      if (!upstream.isConnected()) continue;
      for (const tool of upstream.lastKnownTools) {
        tools.push({ ...tool, name: this.prefixToolName(name, tool.name) });
      }
    }
    return tools;
  }

  /**
   * Route a namespaced tool call to its upstream, converting any failure into a
   * legible {@link CallToolResult} rather than throwing — so the agent always
   * receives an actionable message (e.g. "call bastion__reconnect").
   *
   * @param name The namespaced tool name (e.g. `github__create_issue`).
   * @param args Tool arguments.
   */
  async callUpstreamTool(
    name: string,
    args: unknown,
    opts: {
      principal?: string;
      inputResponses?: Record<string, unknown>;
      requestState?: string;
    } = {},
  ): Promise<ToolCallOutcome> {
    const callArgs = (args ?? {}) as Record<string, unknown>;
    const principal = opts.principal ?? "stdio";

    // Gateway mode: the target upstream may need this request's forwarded identity. Without it the
    // upstream is never called; with it, an idle on-demand upstream is connected as this caller.
    const target = this.upstreams.get(this.serverOfName(name) ?? "");
    if (target) {
      const missing = target.missingForwardedHeaders();
      if (missing.length > 0) {
        const message = new MissingForwardedHeaderError(target.name, missing).message;
        logger.warn({ tool: name, server: target.name, missing }, "call not forwarded");
        return textResult(message, true);
      }
      try {
        await target.prepareForRequest();
      } catch (err) {
        return textResult(this.failureText(target, name, err), true);
      }
    }

    // Re-observe current definitions so a rug pull since the last listing is caught.
    this.syncSecurity();

    const route = this.resolveRoute(name);
    if (!route) {
      return textResult(
        `Unknown tool "${name}". It is not exposed by any connected server. Call ` +
          `"${controlToolName(ControlAction.Status, this.separator)}" to see which servers and tools are available.`,
        true,
      );
    }

    const upstream = this.upstreams.get(route.server);
    if (!upstream || !upstream.isConnected()) {
      const state = upstream?.state ?? "unknown";
      return textResult(
        `Upstream server "${route.server}" is currently ${state}, so the tool "${route.originalName}" ` +
          `is temporarily unavailable. Call "${controlToolName(ControlAction.Reconnect, this.separator)}" with ` +
          `{"server":"${route.server}"} to attempt recovery, or ` +
          `"${controlToolName(ControlAction.Status, this.separator)}" to inspect.`,
        true,
      );
    }

    // MRTR retry (MCP 2026-07-28): the client echoes the `requestState` Bastion issued on the
    // previous round. It must be Bastion's own sealed envelope, unexpired, bound to this principal
    // and this server/tool — only then is the upstream's original state unwrapped and forwarded.
    let upstreamState: string | undefined;
    if (opts.requestState !== undefined || opts.inputResponses !== undefined) {
      const opened = openRequestState(opts.requestState, {
        key: this.requestStateKey,
        principal,
        server: route.server,
        tool: route.originalName,
      });
      if (!opened.ok) {
        const rules = opened.findings.map((f) => f.rule).join(", ");
        logger.warn(
          { tool: name, principal, rules },
          "rejected MRTR retry: requestState custody check failed",
        );
        return textResult(
          `Blocked by mcp-bastion: the requestState presented for "${name}" failed verification (${rules}). ` +
            `A continuation must be echoed unchanged, by the same principal, before it expires.`,
          true,
        );
      }
      upstreamState = opened.upstreamState === "" ? undefined : opened.upstreamState;
    }

    const ctx: ToolCallContext = {
      server: route.server,
      toolName: route.originalName,
      namespacedName: name,
      args: callArgs,
      principal,
      inputResponses: opts.inputResponses,
      requestState: upstreamState,
    };
    const forwarded = upstream.presentForwardedHeaders();
    if (forwarded.length > 0) ctx.forwardedHeaders = forwarded;
    try {
      // Security interceptors run first; the terminal step is the real upstream call.
      const outcome = await runPipeline(
        this.interceptors,
        ctx,
        async () =>
          (await upstream.callTool(route.originalName, callArgs, {
            inputResponses: opts.inputResponses,
            requestState: upstreamState,
          })) as ToolCallOutcome,
      );
      // Seal the upstream's continuation before it travels through the model context: the raw
      // state never leaves Bastion, and the retry can only succeed with this envelope, from this
      // principal, for this server/tool, before it expires.
      if (isInputRequired(outcome)) {
        const sealed = sealRequestState(
          typeof outcome.requestState === "string" ? outcome.requestState : "",
          {
            key: this.requestStateKey,
            ttlSeconds: this.requestStateTtlSeconds,
            principal,
            server: route.server,
            tool: route.originalName,
          },
        );
        return { ...(outcome as InputRequiredResult), requestState: sealed };
      }
      return outcome;
    } catch (err) {
      if (err instanceof UpstreamDisconnectedError) {
        return textResult(
          `Upstream server "${route.server}" disconnected while calling "${route.originalName}". Call ` +
            `"${controlToolName(ControlAction.Reconnect, this.separator)}" with {"server":"${route.server}"} to recover.`,
          true,
        );
      }
      const message = upstream.noteFailure(err);
      logger.error({ tool: name, err: message }, "tool call failed");
      return textResult(this.failureText(upstream, name, err), true);
    }
  }

  /** The tool-result text for an upstream failure; a 401 is reported as an authentication failure. */
  private failureText(upstream: UpstreamConnection, tool: string, err: unknown): string {
    if (err instanceof MissingForwardedHeaderError) return err.message;
    if (isAuthFailure(err)) {
      return (
        `${upstream.name}: authentication failed — the upstream answered HTTP 401 Unauthorized, so ` +
        `"${tool}" was not run. The identity sent with this request was missing, invalid or expired.`
      );
    }
    return `Tool "${tool}" failed: ${upstream.errorMessage(err)}`;
  }

  /**
   * The upstream a namespaced tool name belongs to, by its `<server><separator>` prefix (the
   * longest match wins), so an idle on-demand upstream can be found before its tools are known.
   */
  private serverOfName(namespacedName: string): string | undefined {
    let best: string | undefined;
    for (const server of this.upstreams.keys()) {
      if (!namespacedName.startsWith(server + this.separator)) continue;
      if (!best || server.length > best.length) best = server;
    }
    return best;
  }

  /** Snapshot the health of every upstream (backs `bastion__status`). */
  status(): ServerStatus[] {
    return [...this.upstreams.values()].map((upstream) => ({
      name: upstream.name,
      state: upstream.state,
      connected: upstream.isConnected(),
      transport: upstream.transportKind,
      authenticated: upstream.isAuthenticated(),
      tools: upstream.lastKnownTools.length,
      lastError: upstream.lastError ?? null,
    }));
  }

  /**
   * Force-reconnect a named upstream (backs `bastion__reconnect`).
   *
   * @param server The upstream name to reconnect.
   */
  async reconnect(server: string): Promise<ReconnectResult> {
    const upstream = this.upstreams.get(server);
    if (!upstream) {
      const known = [...this.upstreams.keys()].join(", ") || "(none)";
      return {
        ok: false,
        server,
        message: `No server named "${server}". Known servers: ${known}.`,
      };
    }
    // Rate-limit manual reconnects per server: a prompt-injected agent must not be able to
    // thrash upstream subprocesses (kill/respawn) by looping bastion__reconnect.
    const now = Date.now();
    if (now - (this.lastReconnectAt.get(server) ?? 0) < 5_000) {
      return {
        ok: false,
        server,
        message: `Reconnect for "${server}" was requested too recently; wait a few seconds and retry.`,
      };
    }
    this.lastReconnectAt.set(server, now);
    try {
      await upstream.manualReconnect();
      this.toolsChangedListener();
      return { ok: true, server, state: upstream.state, tools: upstream.lastKnownTools.length };
    } catch (err) {
      return {
        ok: false,
        server,
        state: upstream.state,
        message: (err as Error)?.message ?? String(err),
      };
    }
  }

  /** Per-tool security report (backs `bastion__security`). */
  securityStatus(): ToolSecurityReport[] {
    this.syncSecurity();
    return this.security.status();
  }

  /** Re-approve a changed tool definition (backs `bastion__approve`). */
  approveTool(server: string, tool: string): boolean {
    return this.security.approve(server, tool);
  }

  /** Audit/compliance summary mapped to governance frameworks (backs `bastion__compliance`). */
  complianceReport(): ComplianceReport {
    return (
      this.audit?.complianceReport() ?? {
        totalEvents: 0,
        byDecision: {},
        byOutcome: {},
        controls: { nistAiRmf: {}, owaspLlm: {} },
      }
    );
  }

  /** All upstream connections, e.g. for health-check iteration. */
  upstreamsList(): UpstreamConnection[] {
    return [...this.upstreams.values()];
  }

  /** Feed every connected upstream's current tools to the security engine. */
  private syncSecurity(): void {
    for (const [name, upstream] of this.upstreams) {
      if (upstream.isConnected()) this.security.observe(name, upstream.lastKnownTools);
    }
  }

  /** Names of all configured upstreams. */
  serverNames(): string[] {
    return [...this.upstreams.keys()];
  }

  /** Close every upstream connection and flush/close audit sinks (used during shutdown). */
  async closeAll(): Promise<void> {
    await Promise.allSettled(this.upstreamsList().map((u) => u.close(true)));
    await this.audit?.close();
  }

  /** Compose a namespaced tool name from a server + original tool name. */
  private prefixToolName(server: string, tool: string): string {
    return `${server}${this.separator}${tool}`;
  }

  /**
   * Resolve a namespaced tool name back to its upstream + original name.
   *
   * The routing table is built over ALL upstreams' last-known tools (including
   * currently-disconnected ones) so a call to a dropped server yields a helpful
   * recovery message rather than a bare "unknown tool".
   */
  private resolveRoute(namespacedName: string): ToolRoute | undefined {
    for (const [server, upstream] of this.upstreams) {
      for (const tool of upstream.lastKnownTools) {
        if (this.prefixToolName(server, tool.name) === namespacedName) {
          return { server, originalName: tool.name };
        }
      }
    }
    return undefined;
  }
}
