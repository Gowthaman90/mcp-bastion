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
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

import type { SecurityConfig } from "../config/index.js";
import { ControlAction, controlToolName } from "../core/constants.js";
import { textResult } from "../internal/index.js";
import { logger, type Logger } from "../observability/index.js";
import { scanToolSet } from "./correlation.js";
import { hasSeverityAtLeast, scanText } from "./poisoning.js";
import { validateArguments } from "./schema.js";
import { ToolRegistry } from "./tool-registry.js";
import type { Interceptor, SecurityFinding, ToolSecurityReport } from "./types.js";

/** Stringify tool-call arguments for heuristic scanning; never throws. */
function safeStringify(args: unknown): string {
  try {
    return JSON.stringify(args ?? {});
  } catch {
    return "";
  }
}

/** Concatenate the text blocks of a tool result for heuristic scanning. */
function resultText(result: CallToolResult): string {
  const content = (result.content ?? []) as Array<{ type?: string; text?: string }>;
  return content
    .filter((c) => c.type === "text" && typeof c.text === "string")
    .map((c) => c.text)
    .join("\n");
}

export class SecurityEngine {
  private readonly registry = new ToolRegistry();
  /** Cross-tool (split-poisoning) findings, per server. */
  private readonly crossTool = new Map<string, SecurityFinding[]>();

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

    if (this.policy.correlateTools) {
      const findings = scanToolSet(tools);
      if (findings.length > 0) {
        this.crossTool.set(server, findings);
        this.log.warn(
          { server, rules: findings.map((f) => f.rule) },
          "cross-tool correlation flagged possible split-payload poisoning",
        );
      } else {
        this.crossTool.delete(server);
      }
    }
  }

  /** Cross-tool (split-payload) findings per server, if any. */
  crossToolStatus(): { server: string; findings: SecurityFinding[] }[] {
    return [...this.crossTool.entries()].map(([server, findings]) => ({ server, findings }));
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
    if (this.policy.validateArguments) interceptors.push(this.argumentInterceptor());
    if (this.policy.scanResponses) interceptors.push(this.responseScanInterceptor());
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

  /**
   * Inspects a call's outgoing arguments two ways before they reach the server:
   *   - schema validation — undeclared parameters (smuggling) and type/enum violations (bypass); and
   *   - content scanning — the same heuristics used on descriptions, applied to argument *values*,
   *     to catch a call that reads a sensitive source (e.g. `~/.ssh/id_rsa`, `.env`) as the first
   *     leg of a cross-tool exfiltration.
   */
  private argumentInterceptor(): Interceptor {
    return (ctx, next) => {
      const state = this.registry.state(ctx.server, ctx.toolName);
      const findings = [
        ...validateArguments(state?.inputSchema, ctx.args),
        ...scanText(safeStringify(ctx.args)),
      ];
      if (findings.length === 0) return next();

      ctx.findings = [...(ctx.findings ?? []), ...findings];
      this.log.warn(
        { server: ctx.server, tool: ctx.toolName, rules: findings.map((f) => f.rule) },
        "tool arguments failed inspection",
      );

      if (this.policy.onSchemaViolation === "block") {
        ctx.securityDecision = "blocked_schema";
        const rules = findings.map((f) => f.rule).join(", ");
        return Promise.resolve(
          textResult(
            `Blocked by mcp-bastion: the call to tool "${ctx.toolName}" on server "${ctx.server}" ` +
              `failed argument validation (${rules}). The arguments do not match the tool's declared ` +
              `input schema — a possible parameter-smuggling or validation-bypass attempt. Set ` +
              `security.onSchemaViolation to "warn" if this is a false positive.`,
            true,
          ),
        );
      }
      return next();
    };
  }

  /**
   * Scans a tool's *result* for injected instructions / exfiltration signals. Runs after
   * the upstream call so it can inspect what the server actually returned — the
   * response-handling stage that definition-only checks miss.
   */
  private responseScanInterceptor(): Interceptor {
    return async (ctx, next) => {
      const result = await next();
      // Don't second-guess a call another interceptor already blocked.
      if (ctx.securityDecision) return result;

      const findings = scanText(resultText(result));
      if (findings.length === 0) return result;

      ctx.responseFindings = findings;
      ctx.findings = [...(ctx.findings ?? []), ...findings];
      this.log.warn(
        { server: ctx.server, tool: ctx.toolName, rules: findings.map((f) => f.rule) },
        "tool result flagged by response heuristics",
      );

      if (this.policy.onResponse === "block" && hasSeverityAtLeast(findings, "high")) {
        ctx.securityDecision = "blocked_response";
        const rules = findings.map((f) => f.rule).join(", ");
        return textResult(
          `Blocked by mcp-bastion: the result from tool "${ctx.toolName}" on server ` +
            `"${ctx.server}" was flagged as potentially malicious (${rules}) — a possible injected ` +
            `instruction or data-exfiltration attempt in the response. Set security.onResponse to ` +
            `"warn" if this is a false positive.`,
          true,
        );
      }
      return result;
    };
  }
}
