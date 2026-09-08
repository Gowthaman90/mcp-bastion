/**
 * Bastion's built-in control tools.
 *
 * These are exposed to the client alongside the aggregated upstream tools so the
 * agent can inspect connection health and recover dropped servers on its own —
 * the core reliability capability of v0.1. They are defined in the proxy layer
 * because they are part of the client-facing MCP surface, and they delegate to
 * the core {@link UpstreamManager} for the actual work.
 *
 * **Authority separation (security):** only *recovery* actions (status, reconnect,
 * security report, compliance) are exposed to the client. Re-approving a changed
 * tool — clearing a rug-pull block — is a *security* authority and is deliberately
 * NOT on the client surface: a prompt-injected agent must never be able to clear
 * the very block that protects it. `bastion__approve` is therefore not advertised,
 * and an explicit call to it over the client channel is refused (see
 * {@link handleControlTool}). Re-approval is operator-only / out-of-band.
 *
 * @packageDocumentation
 */
import type { CallToolResult, Tool } from "@modelcontextprotocol/server";

import { ControlAction, controlToolName, type UpstreamManager } from "../core/index.js";
import { textResult } from "../internal/index.js";

/**
 * Build the control-tool definitions for the configured namespace separator.
 *
 * @param separator The namespace separator (e.g. `"__"`).
 */
export function buildControlTools(separator: string): Tool[] {
  return [
    {
      name: controlToolName(ControlAction.Status, separator),
      description:
        "Report the health of every MCP server proxied by Bastion: which are connected, " +
        "disconnected, reconnecting, or failed; how many tools each exposes; and the last error. " +
        "Call this when a tool seems to be missing or a server may have dropped mid-session.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
    },
    {
      name: controlToolName(ControlAction.Reconnect, separator),
      description:
        "Attempt to reconnect a disconnected or failed MCP server by name. Use this after " +
        "bastion status shows a server is not connected, to restore its tools without human intervention.",
      inputSchema: {
        type: "object",
        properties: {
          server: {
            type: "string",
            description: "Name of the upstream server to reconnect (as shown by bastion status).",
          },
        },
        required: ["server"],
        additionalProperties: false,
      },
    },
    {
      name: controlToolName(ControlAction.Security, separator),
      description:
        "Report the security state of every proxied tool: whether its definition matches what was " +
        "first approved (or changed — a possible 'rug pull'), any poisoning heuristics its description " +
        "triggered, and whether another server exposes a tool with the same name (shadowing).",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
    },
    // NOTE: `bastion__approve` is intentionally NOT exposed here. Clearing a rug-pull
    // block is a security authority, not a recovery action — exposing it to the client
    // would let a prompt-injected agent re-approve the malicious tool it was blocked from.
    // Re-approval is operator-only / out-of-band; a client call to it is refused below.
    {
      name: controlToolName(ControlAction.Compliance, separator),
      description:
        "Report an audit/compliance summary of recent tool activity, mapped to governance " +
        "frameworks (NIST AI RMF functions and OWASP LLM Top 10 categories). Requires audit to be enabled.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
    },
  ];
}

/**
 * Whether `name` addresses one of Bastion's control tools.
 *
 * @param name      The tool name from a `tools/call` request.
 * @param separator The configured namespace separator.
 */
export function isControlToolName(name: string, separator: string): boolean {
  return Object.values(ControlAction).some((action) => name === controlToolName(action, separator));
}

/**
 * Execute a control tool against the manager.
 *
 * @param name    The control tool name (must satisfy {@link isControlToolName}).
 * @param args    Parsed tool arguments.
 * @param manager The upstream manager to operate on.
 */
export async function handleControlTool(
  name: string,
  args: Record<string, unknown>,
  manager: UpstreamManager,
): Promise<CallToolResult> {
  const separator = manager.separator;

  if (name === controlToolName(ControlAction.Status, separator)) {
    return textResult(JSON.stringify({ servers: manager.status() }, null, 2));
  }

  if (name === controlToolName(ControlAction.Reconnect, separator)) {
    const server = typeof args?.server === "string" ? args.server : undefined;
    if (!server) {
      return textResult('Missing required argument "server" (string).', true);
    }
    const result = await manager.reconnect(server);
    return textResult(JSON.stringify(result, null, 2), !result.ok);
  }

  if (name === controlToolName(ControlAction.Security, separator)) {
    return textResult(JSON.stringify({ tools: manager.securityStatus() }, null, 2));
  }

  if (name === controlToolName(ControlAction.Approve, separator)) {
    // Refuse: re-approving a changed tool is a security authority, not a client-callable
    // recovery action. Detecting a boundary violation is not authority to clear it — a
    // prompt-injected agent must not be able to re-approve the malicious tool it was
    // blocked from. Re-approval must happen out-of-band via an operator, never over this
    // (model-reachable) channel. This branch is defense-in-depth: the tool is not
    // advertised (see buildControlTools), and a hardcoded call is rejected here.
    return textResult(
      JSON.stringify(
        {
          ok: false,
          refused: "operator-only",
          message:
            "Re-approval is an operator action and is not available over the client tool channel. " +
            "A changed tool stays blocked until an operator clears it out-of-band.",
        },
        null,
        2,
      ),
      true,
    );
  }

  if (name === controlToolName(ControlAction.Compliance, separator)) {
    return textResult(JSON.stringify(manager.complianceReport(), null, 2));
  }

  return textResult(`Unknown control tool "${name}".`, true);
}
