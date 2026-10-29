/**
 * Start-up warnings for configurations that are valid but easy to misread: settings that trust more
 * than an operator may realise, or that lose information across restarts. A pure function of the
 * configuration and environment, so a caller (the CLI, an embedding application, a future config
 * reload) can run it whenever it loads a configuration.
 *
 * @packageDocumentation
 */
import type { BastionConfig } from "./schema.js";

/** One start-up note. Never contains a key or token value. */
export interface StartupWarning {
  level: "warn" | "info";
  message: string;
}

/** Upstreams whose delegate-token claims Bastion checks structurally (no signature check). */
function structuralUpstreams(config: BastionConfig): string[] {
  return Object.entries(config.servers)
    .filter(
      ([, s]) =>
        "delegation" in s && s.delegation !== undefined && s.delegation.verify === "structural",
    )
    .map(([name]) => name);
}

/** Whether any upstream has delegation checks. */
function hasDelegation(config: BastionConfig): boolean {
  return Object.values(config.servers).some((s) => "delegation" in s && s.delegation !== undefined);
}

/**
 * The start-up warnings for `config`.
 *
 * - `authorization.trustStructuralClaims` on: names the upstreams whose user and agent identities come
 *   from delegate tokens whose signature Bastion does not check (or notes that it has no effect).
 * - Delegation subjects pseudonymised (`recordSubject: "hash"`) with no configured key: pseudonyms
 *   will not link across restarts or replicas. The key sources are those `DelegationGate` reads.
 */
export function startupWarnings(
  config: BastionConfig,
  env: NodeJS.ProcessEnv = process.env,
): StartupWarning[] {
  const out: StartupWarning[] = [];
  const a = config.authorization;
  if (a.enabled && a.trustStructuralClaims) {
    const structural = structuralUpstreams(config);
    out.push(
      structural.length > 0
        ? {
            level: "warn",
            message:
              `authorization.trustStructuralClaims is on: for ${structural.join(", ")} the user and ` +
              `agent identities come from delegate tokens whose signature Bastion does not check. A ` +
              `caller who can send such a token can name any user. This is safe only if each of these ` +
              `upstreams verifies the token itself; prefer delegation.verify: "signature".`,
          }
        : {
            level: "info",
            message:
              "authorization.trustStructuralClaims has no effect: no upstream uses structural " +
              "delegation checks.",
          },
    );
  }
  // Same sources, and the same `??` test, as DelegationGate's subject key.
  const keyed =
    (config.delegation.subjectKey ??
      env.MCP_BASTION_SUBJECT_KEY ??
      config.audit.integrityKey ??
      env.MCP_BASTION_AUDIT_KEY) !== undefined;
  if (hasDelegation(config) && config.delegation.recordSubject === "hash" && !keyed) {
    out.push({
      level: "warn",
      message:
        "no delegation.subjectKey, MCP_BASTION_SUBJECT_KEY, audit.integrityKey or " +
        "MCP_BASTION_AUDIT_KEY is set: audit subject pseudonyms use a random key for this process, " +
        "so one user's records do not link across restarts or replicas. Set one of them (16+ " +
        "characters, the same on every replica) to link them.",
    });
  }
  return out;
}
