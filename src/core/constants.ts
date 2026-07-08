/**
 * Core identifiers and the naming contract for Bastion's built-in control tools.
 *
 * The control-tool *names* are part of Bastion's contract, so the naming helper
 * lives in the core layer. The proxy layer builds the concrete tool definitions
 * from these names, and the core layer references them when composing the
 * recovery hints embedded in error messages.
 *
 * @packageDocumentation
 */

/** Server name Bastion reports as, and the client identity it uses upstream. */
export const BASTION_NAME = "mcp-bastion";

/** Current Bastion version. Keep in sync with `package.json` on release. */
export const BASTION_VERSION = "0.1.0";

/** Namespace under which Bastion exposes its own control tools. */
export const CONTROL_NAMESPACE = "bastion";

/** The set of control actions Bastion exposes as tools. */
export const ControlAction = {
  /** Report the health of every proxied upstream. */
  Status: "status",
  /** Reconnect a named upstream. */
  Reconnect: "reconnect",
  /** Report the security state of proxied tools (pinning, poisoning, shadowing). */
  Security: "security",
  /** Re-approve a tool whose definition changed (clears a rug-pull block). */
  Approve: "approve",
  /** Report an audit/compliance summary mapped to governance frameworks. */
  Compliance: "compliance",
} as const;

export type ControlAction = (typeof ControlAction)[keyof typeof ControlAction];

/**
 * Compose the full, client-visible name of a control tool.
 *
 * @param action    One of the {@link ControlAction} values.
 * @param separator The configured namespace separator (e.g. `"__"`).
 * @returns e.g. `"bastion__status"`.
 */
export function controlToolName(action: ControlAction, separator: string): string {
  return `${CONTROL_NAMESPACE}${separator}${action}`;
}
