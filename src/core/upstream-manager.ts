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
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

import { AuditEngine, createSinks, type ComplianceReport } from "../audit/index.js";
import type { BastionConfig } from "../config/index.js";
import { UpstreamDisconnectedError } from "../errors.js";
import { textResult } from "../internal/index.js";
import { logger } from "../observability/index.js";
import { runPipeline, SecurityEngine } from "../security/index.js";
import type { Interceptor, ToolCallContext, ToolSecurityReport } from "../security/index.js";
import { ControlAction, controlToolName } from "./constants.js";
import type { ReconnectResult, ServerStatus, ToolRoute } from "./types.js";
import { UpstreamConnection } from "./upstream-connection.js";

export class UpstreamManager {
  private readonly upstreams = new Map<string, UpstreamConnection>();
  private readonly namespaceSeparator: string;
  private readonly security: SecurityEngine;
  private readonly audit?: AuditEngine;
  private readonly interceptors: readonly Interceptor[];
  private toolsChangedListener: () => void = () => {};

  /**
   * @param config The validated Bastion configuration.
   */
  constructor(config: BastionConfig) {
    this.namespaceSeparator = config.namespace.separator;
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
        new UpstreamConnection(name, serverConfig, config.reconnect, () =>
          this.toolsChangedListener(),
        ),
      );
    }
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

  /** Connect all upstreams concurrently. Individual failures are non-fatal (they auto-reconnect). */
  async connectAll(): Promise<void> {
    await Promise.allSettled([...this.upstreams.values()].map((u) => u.connect()));
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
  async callUpstreamTool(name: string, args: unknown): Promise<CallToolResult> {
    const callArgs = (args ?? {}) as Record<string, unknown>;

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

    const ctx: ToolCallContext = {
      server: route.server,
      toolName: route.originalName,
      namespacedName: name,
      args: callArgs,
    };
    try {
      // Security interceptors run first; the terminal step is the real upstream call.
      return await runPipeline(
        this.interceptors,
        ctx,
        async () => (await upstream.callTool(route.originalName, callArgs)) as CallToolResult,
      );
    } catch (err) {
      if (err instanceof UpstreamDisconnectedError) {
        return textResult(
          `Upstream server "${route.server}" disconnected while calling "${route.originalName}". Call ` +
            `"${controlToolName(ControlAction.Reconnect, this.separator)}" with {"server":"${route.server}"} to recover.`,
          true,
        );
      }
      logger.error({ tool: name, err: (err as Error)?.message ?? String(err) }, "tool call failed");
      return textResult(`Tool "${name}" failed: ${(err as Error)?.message ?? String(err)}`, true);
    }
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
