/**
 * Domain types shared across the core layer.
 *
 * @packageDocumentation
 */

/** Lifecycle state of a single upstream connection. */
export type ConnectionState =
  "connecting" | "connected" | "disconnected" | "reconnecting" | "failed";

/** A point-in-time health snapshot of one upstream, as surfaced by `bastion__status`. */
export interface ServerStatus {
  /** Configured server name. */
  name: string;
  /** Current lifecycle state. */
  state: ConnectionState;
  /** Convenience flag: `true` iff `state === "connected"`. */
  connected: boolean;
  /** Transport used to reach this upstream. */
  transport: "stdio" | "http";
  /**
   * Authentication status: `null` for local stdio servers (N/A), otherwise
   * whether an HTTP upstream is configured with an auth header.
   */
  authenticated: boolean | null;
  /** Number of tools last advertised by this upstream. */
  tools: number;
  /** Most recent error message, or `null` if none. */
  lastError: string | null;
}

/** Outcome of a `bastion__reconnect` request. */
export interface ReconnectResult {
  /** Whether the reconnect succeeded. */
  ok: boolean;
  /** The server that was targeted. */
  server: string;
  /** Resulting lifecycle state, when the server was known. */
  state?: ConnectionState;
  /** Number of tools available after reconnect, when successful. */
  tools?: number;
  /** Human-readable detail, typically present on failure. */
  message?: string;
}

/** Internal mapping from a namespaced tool name back to its upstream + original name. */
export interface ToolRoute {
  /** Owning upstream server name. */
  server: string;
  /** The tool's original (un-namespaced) name on that upstream. */
  originalName: string;
}
