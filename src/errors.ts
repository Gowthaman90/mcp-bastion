/**
 * Error hierarchy for mcp-bastion.
 *
 * Every error Bastion raises extends {@link BastionError}, so callers can
 * reliably distinguish Bastion-originated failures from arbitrary throwables
 * with a single `instanceof BastionError` check.
 *
 * @packageDocumentation
 */

/** Base class for all errors raised by mcp-bastion. */
export class BastionError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    // `new.target` yields the most-derived constructor, giving each subclass its own name.
    this.name = new.target.name;
    // Restore the prototype chain so `instanceof` works across all transpile targets.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Raised when a configuration file is missing, is not valid JSON, or fails schema validation. */
export class ConfigError extends BastionError {}

/**
 * Raised when a tool call is routed to an upstream server that is not currently
 * connected. The proxy layer catches this and translates it into a legible,
 * actionable message for the agent rather than surfacing a raw failure.
 */
export class UpstreamDisconnectedError extends BastionError {
  constructor(public readonly server: string) {
    super(`Upstream server "${server}" is disconnected`);
  }
}
