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
import { checkCommandInjection } from "./command-injection.js";
import { checkConfigDrift } from "./config-drift.js";
import { redactSecrets } from "./dlp.js";
import { scanToolSet } from "./correlation.js";
import { checkServerIdentity, hashServerIdentity, type ServerIdentity } from "./identity.js";
import { TaintTracker } from "./taint.js";
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
  /** Trust-on-first-use config snapshot per server, for drift detection. */
  private readonly pinnedConfig = new Map<string, Record<string, unknown>>();
  /** Config-drift findings, per server. */
  private readonly configDrift = new Map<string, SecurityFinding[]>();
  /** Trust-on-first-use identity fingerprint per server. */
  private readonly pinnedIdentity = new Map<string, string>();
  /** Server-identity findings (unverified or changed), per server. */
  private readonly identityFindings = new Map<string, SecurityFinding[]>();
  /** Session-scoped cross-server data-flow (taint) tracker. */
  private readonly taint = new TaintTracker();

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
    this.registry.observe(server, tools, {
      inspectDescriptions: this.policy.inspectDescriptions,
      normalizeEvasion: this.policy.normalizeEvasion,
    });

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

  /**
   * Observe a server's effective configuration snapshot. Pins the first snapshot (trust-on-first-use)
   * and, on a later snapshot, flags any security-relevant *weakening* versus the pinned baseline
   * (e.g. a TLS downgrade or a host allowlist widened with a wildcard).
   */
  observeConfig(server: string, snapshot: Record<string, unknown>): void {
    if (!this.policy.detectConfigDrift) return;
    const baseline = this.pinnedConfig.get(server);
    if (!baseline) {
      this.pinnedConfig.set(server, { ...snapshot });
      return;
    }
    const findings = checkConfigDrift(baseline, snapshot);
    if (findings.length > 0) {
      this.configDrift.set(server, findings);
      this.log.warn(
        { server, rules: findings.map((f) => f.rule) },
        "configuration drift detected: server config weakened versus its reviewed baseline",
      );
    } else {
      this.configDrift.delete(server);
    }
  }

  /** Config-drift findings per server, if any. */
  configDriftStatus(): { server: string; findings: SecurityFinding[] }[] {
    return [...this.configDrift.entries()].map(([server, findings]) => ({ server, findings }));
  }

  /**
   * Observe a server's advertised identity at (re)connect. Flags a claimed identity that lacks a
   * verified binding, and — trust-on-first-use — flags a later identity that differs from the pinned
   * one (endpoint/name/TLS change), a strong impersonation signal. Version/protocol changes do not
   * trip the pin, so a benign redeploy is not flagged.
   */
  observeIdentity(server: string, identity: ServerIdentity): void {
    if (!this.policy.pinServerIdentity) return;
    const findings = [...checkServerIdentity(identity)];

    const fingerprint = hashServerIdentity(identity);
    const pinned = this.pinnedIdentity.get(server);
    if (pinned === undefined) {
      this.pinnedIdentity.set(server, fingerprint);
    } else if (pinned !== fingerprint) {
      findings.push({
        rule: "server-identity-changed",
        severity: "high",
        excerpt: `server "${server}" identity changed after it was first pinned (possible impersonation)`,
      });
    }

    if (findings.length > 0) {
      this.identityFindings.set(server, findings);
      this.log.warn(
        { server, rules: findings.map((f) => f.rule) },
        "server-identity check flagged a possible impersonation",
      );
    } else {
      this.identityFindings.delete(server);
    }
  }

  /** Server-identity findings per server, if any. */
  identityStatus(): { server: string; findings: SecurityFinding[] }[] {
    return [...this.identityFindings.entries()].map(([server, findings]) => ({ server, findings }));
  }

  /** Whether a server's pinned identity has changed (backs the identity interceptor / enforcement). */
  private identityChanged(server: string): boolean {
    return (this.identityFindings.get(server) ?? []).some(
      (f) => f.rule === "server-identity-changed",
    );
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
    if (this.policy.pinServerIdentity) interceptors.push(this.identityInterceptor());
    if (this.policy.pinTools) interceptors.push(this.rugPullInterceptor());
    if (this.policy.inspectDescriptions) interceptors.push(this.poisoningInterceptor());
    if (this.policy.validateArguments) interceptors.push(this.argumentInterceptor());
    if (this.policy.trackDataFlow) interceptors.push(this.dataFlowInterceptor());
    if (this.policy.scanResponses) interceptors.push(this.responseScanInterceptor());
    return interceptors;
  }

  /**
   * Blocks (or warns on) calls to a server whose pinned identity changed after first connect
   * (endpoint/name/TLS) — the server-layer analogue of rug-pull detection. Defaults to block,
   * since a mid-session identity change is a strong impersonation/hijack signal.
   */
  private identityInterceptor(): Interceptor {
    return (ctx, next) => {
      if (!this.identityChanged(ctx.server)) return next();
      const findings = this.identityFindings.get(ctx.server) ?? [];
      ctx.findings = [...(ctx.findings ?? []), ...findings];
      this.log.warn(
        { server: ctx.server, tool: ctx.toolName },
        "server identity changed after pinning: possible impersonation",
      );
      if (this.policy.onIdentityChange === "block") {
        ctx.securityDecision = "blocked_identity";
        return Promise.resolve(
          textResult(
            `Blocked by mcp-bastion: the identity of server "${ctx.server}" (endpoint / name / TLS ` +
              `fingerprint) changed after it was first pinned — a possible server-impersonation or ` +
              `hijack. Verify the server, then re-approve, or set security.onIdentityChange to "warn" ` +
              `if this change is expected.`,
            true,
          ),
        );
      }
      return next();
    };
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
        ...scanText(safeStringify(ctx.args), this.policy.normalizeEvasion),
        ...(this.policy.detectCommandInjection ? checkCommandInjection(ctx.args) : []),
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
              `failed argument inspection (${rules}) — a possible parameter-smuggling, ` +
              `validation-bypass, or command-injection attempt. Set security.onSchemaViolation to ` +
              `"warn" if this is a false positive.`,
            true,
          ),
        );
      }
      return next();
    };
  }

  /**
   * Tracks sensitive data across the trust boundary between servers. Before a call, checks its
   * outgoing arguments for a credential-shaped token that a *different* server returned earlier
   * (the exfiltration leg of a cross-server / tool-transfer attack); after the call, records any
   * sensitive tokens the result (or arguments) carry, sourced to this call's server.
   */
  private dataFlowInterceptor(): Interceptor {
    return async (ctx, next) => {
      const argText = safeStringify(ctx.args);
      const pre = this.taint.check(ctx.server, [argText]);
      if (pre.length > 0) {
        ctx.findings = [...(ctx.findings ?? []), ...pre];
        this.log.warn(
          { server: ctx.server, tool: ctx.toolName, rules: pre.map((f) => f.rule) },
          "cross-server data flow: another server's sensitive data is in this call's arguments",
        );
        if (this.policy.onDataFlow === "block") {
          ctx.securityDecision = "blocked_dataflow";
          return textResult(
            `Blocked by mcp-bastion: the call to tool "${ctx.toolName}" on server "${ctx.server}" ` +
              `would send data that was read from a different server across the trust boundary — a ` +
              `possible cross-server exfiltration. Set security.onDataFlow to "warn" if this is a ` +
              `false positive.`,
            true,
          );
        }
      }
      const result = await next();
      if (!ctx.securityDecision) this.taint.record(ctx.server, [resultText(result), argText]);
      return result;
    };
  }

  /**
   * Apply inline DLP redaction to a result's text blocks, returning a new result (with secret values
   * replaced) and the total number of redactions. The original result is left untouched.
   */
  private redactResultSecrets(result: CallToolResult): {
    result: CallToolResult;
    redactions: number;
  } {
    const content = (result.content ?? []) as Array<{ type?: string; text?: string }>;
    let redactions = 0;
    const newContent = content.map((block) => {
      if (block?.type !== "text" || typeof block.text !== "string") return block;
      const { text, redactions: n } = redactSecrets(block.text);
      redactions += n;
      return n > 0 ? { ...block, text } : block;
    });
    return redactions > 0
      ? { result: { ...result, content: newContent } as CallToolResult, redactions }
      : { result, redactions: 0 };
  }

  /**
   * Scans a tool's *result* for injected instructions / exfiltration signals. Runs after
   * the upstream call so it can inspect what the server actually returned — the
   * response-handling stage that definition-only checks miss.
   */
  private responseScanInterceptor(): Interceptor {
    return async (ctx, next) => {
      let result = await next();
      // Don't second-guess a call another interceptor already blocked.
      if (ctx.securityDecision) return result;

      const findings = scanText(resultText(result), this.policy.normalizeEvasion);

      // Inline DLP: strip credential-shaped secret *values* from the result (an enforcing
      // mitigation), independent of whether the response also tripped an injection heuristic.
      if (this.policy.redactResponseSecrets) {
        const { result: redacted, redactions } = this.redactResultSecrets(result);
        if (redactions > 0) {
          result = redacted;
          ctx.redactedSecrets = redactions;
          ctx.findings = [
            ...(ctx.findings ?? []),
            {
              rule: "secret-redacted",
              severity: "high",
              excerpt: `${redactions} secret value(s) redacted from the tool result`,
            },
          ];
          this.log.warn(
            { server: ctx.server, tool: ctx.toolName, redactions },
            "inline DLP: redacted secret value(s) from tool result",
          );
        }
      }

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
