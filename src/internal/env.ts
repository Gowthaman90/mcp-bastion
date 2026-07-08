/**
 * Environment helpers for spawning upstream stdio servers.
 *
 * @packageDocumentation
 */

/**
 * Build the environment for a spawned upstream process.
 *
 * When no per-server overrides are provided we return `undefined` so the MCP SDK
 * applies its own safe default environment (which includes `PATH`). When overrides
 * are provided we merge them over the current process environment, dropping any
 * `undefined` values so the result is a clean `Record<string, string>`.
 *
 * @param overrides Optional per-server environment variables from config.
 * @returns The merged environment, or `undefined` to use the SDK default.
 */
export function buildEnv(overrides?: Record<string, string>): Record<string, string> | undefined {
  if (!overrides) return undefined;

  const base: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined) base[key] = value;
  }
  return { ...base, ...overrides };
}
