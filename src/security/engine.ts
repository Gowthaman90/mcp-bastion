/**
 * The security engine: composes the tool registry and poisoning scanner into the
 * interceptors that guard tool calls, and backs the `bastion__security` and
 * `bastion__approve` control tools.
 *
 * It imports the control-tool naming helper from `core/constants` (a dependency-free
 * leaf module) so recovery hints reference the real tool names without creating a
 * dependency cycle with the manager.
 *
 * @packageDocumentation
 */
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

import type { SecurityConfig } from "../config/index.js";
import { ControlAction, controlToolName } from "../core/constants.js";
import { textResult } from "../internal/index.js";
import { logger, type Logger } from "../observability/index.js";
import { hasSeverityAtLeast } from "./poisoning.js";
import { ToolRegistry } from "./tool-registry.js";
import type { Interceptor, ToolSecurityReport } from "./types.js";

export class SecurityEngine {
  private readonly registry = new ToolRegistry();

  /**
   * @param policy    Security policy from configuration.
   * @param separator Namespace separator, used to name control tools in messages.
   * @param log       Logger (defaults to the shared application logger).
   */
  constructor(
    private readonly policy: SecurityConfig,
    private readonly separator: string,
    private readonly log: Logger = logger,
  ) {}

  /** Reconcile the registry with a server's current tools. */
  observe(server: string, tools: readonly Tool[]): void {
    this.registry.observe(server, tools, { inspectDescriptions: this.policy.inspectDescriptions });
  }

  /** Per-tool security report (backs `bastion__security`). */
  status(): ToolSecurityReport[] {
    return this.registry.report();
  }

  /** Re-approve a tool's current definition (backs `bastion__approve`). */
  approve(server: string, tool: string): boolean {
    return this.registry.approve(server, tool);
  }

  /** The ordered interceptors enforcing the configured policy. */
  buildInterceptors(): Interceptor[] {
    const interceptors: Interceptor[] = [];
    if (this.policy.pinTools) interceptors.push(this.rugPullInterceptor());
    if (this.policy.inspectDescriptions) interceptors.push(this.poisoningInterceptor());
    return interceptors;
  }

  /** Blocks (or warns on) calls to a tool whose definition changed after approval. */
  private rugPullInterceptor(): Interceptor {
    return (ctx, next) => {
      const state = this.registry.state(ctx.server, ctx.toolName);
      if (state) {
        ctx.definitionHash = state.currentHash;
        ctx.findings = [...state.findings];
      }
      if (state?.status === "changed") {
        this.log.warn(
          { server: ctx.server, tool: ctx.toolName },
          "rug pull detected: tool definition changed after approval",
        );
        if (this.policy.onRugPull === "block") {
          ctx.securityDecision = "blocked_rug_pull";
          return Promise.resolve(
            textResult(
              `Blocked by mcp-bastion: the definition of tool "${ctx.toolName}" on server ` +
                `"${ctx.server}" changed after it was first approved (a possible "rug pull"). Review the ` +
                `change, then call "${controlToolName(ControlAction.Approve, this.separator)}" with ` +
                `{"server":"${ctx.server}","tool":"${ctx.toolName}"} to re-approve it, or ` +
                `"${controlToolName(ControlAction.Security, this.separator)}" to inspect.`,
              true,
            ),
          );
        }
      }
      return next();
    };
  }

  /** Blocks (or warns on) calls to a tool whose description trips poisoning heuristics. */
  private poisoningInterceptor(): Interceptor {
    return (ctx, next) => {
      const state = this.registry.state(ctx.server, ctx.toolName);
      const findings = state?.findings ?? [];
      if (state) {
        ctx.definitionHash ??= state.currentHash;
        ctx.findings ??= [...findings];
      }
      if (findings.length > 0) {
        this.log.warn(
          { server: ctx.server, tool: ctx.toolName, rules: findings.map((f) => f.rule) },
          "tool description flagged by poisoning heuristics",
        );
        if (this.policy.onPoisoning === "block" && hasSeverityAtLeast(findings, "high")) {
          ctx.securityDecision = "blocked_poisoning";
          const rules = findings.map((f) => f.rule).join(", ");
          return Promise.resolve(
            textResult(
              `Blocked by mcp-bastion: the description of tool "${ctx.toolName}" on server ` +
                `"${ctx.server}" was flagged as potentially malicious (${rules}). Investigate the server, ` +
                `or set security.onPoisoning to "warn" if this is a false positive. Call ` +
                `"${controlToolName(ControlAction.Security, this.separator)}" for details.`,
              true,
            ),
          );
        }
      }
      return next();
    };
  }
}
