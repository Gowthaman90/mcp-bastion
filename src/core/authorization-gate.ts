/**
 * Request-scoped enforcement of runtime authorization (see `security/authorization.ts`).
 *
 * The gate turns the `authorization` configuration into an {@link AuthorizationPolicy}, resolves
 * the identities a call carries, applies the enforcement setting (`onAuthorization`) and builds the
 * audit record. It keeps the last denial (rule and time only) for `bastion__status`.
 *
 * Identities come only from authentication:
 * - `client`: the Bastion bearer token the request presented (`listen.clients` name, `default` for
 *   `listen.authToken`, `stdio`, or `anonymous` on an unauthenticated loopback listener);
 * - `user` and `agent`: the `sub` and current actor of the delegate token carried for the target
 *   upstream, and only when that token is trusted: signature-verified, or structural with
 *   `trustStructuralClaims`, and with no delegation finding against it. A token that is present but
 *   untrusted refuses the call (`delegation:unverified`) instead of silently dropping identities,
 *   which would widen the grant. Prior actors never count.
 *
 * @packageDocumentation
 */
import type { AuditAuthorizationRecord } from "../audit/types.js";
import type { BastionConfig } from "../config/index.js";
import { ENFORCEMENT_PROFILES } from "../config/schema.js";
import {
  argumentShortfalls,
  authorize,
  mayList,
  patternReachesPrefix,
  principalMatches,
  type ArgumentShortfall,
  type AuthorizationDecision,
  type AuthorizationPolicy,
  type CallIdentities,
} from "../security/authorization.js";
import { DELEGATION_CHAIN_RULES } from "../security/delegation.js";
import type { DelegationGate } from "./delegation-gate.js";

/** Server name the control tools (`bastion__*`) are authorized under. */
export const CONTROL_SERVER = "bastion";

/** What the gate says about one call. */
export interface AuthorizationCheck {
  decision: AuthorizationDecision;
  /** Whether the call must be refused now (a denial under `onAuthorization: "block"`). */
  blocks: boolean;
  /** A denial the `warn` action let through that the `balanced` profile would have blocked. */
  wouldBlock: boolean;
  record: AuditAuthorizationRecord;
  /**
   * On a denial, what failed, for the refusal message: `rule <id>` for a deny rule, `no matching
   * grant`, or which arguments a matching grant did not allow. Names rule ids and argument names,
   * never constraint values.
   */
  explanation?: string;
}

/** `bastion__status` summary of the policy. Rule ids and times only. */
export interface AuthorizationStatus {
  enabled: true;
  default: "deny" | "allow";
  rules: number;
  action: "block" | "warn";
  trustStructuralClaims: boolean;
  lastDenial: { rule: string | null; at: string } | null;
}

/** The identities of one call, or a reason it cannot be trusted. */
type ResolvedIdentities =
  { ok: true; identities: CallIdentities } | { ok: false; identities: CallIdentities };

export class AuthorizationGate {
  private readonly policy: AuthorizationPolicy;
  private readonly active: boolean;
  private readonly trustStructural: boolean;
  private readonly action: "block" | "warn";
  private readonly separator: string;
  private lastDenial: { rule: string | null; at: string } | null = null;

  /**
   * @param config     The validated Bastion configuration.
   * @param delegation The delegation gate whose per-request verdict supplies user and agent.
   */
  constructor(
    config: BastionConfig,
    private readonly delegation: DelegationGate,
  ) {
    const a = config.authorization;
    this.active = a.enabled;
    this.trustStructural = a.trustStructuralClaims;
    this.action = config.security.onAuthorization;
    this.separator = config.namespace.separator;
    this.policy = { default: a.default, rules: a.rules };
  }

  /** Whether authorization is enabled. */
  get enabled(): boolean {
    return this.active;
  }

  /**
   * Decide a call of the namespaced tool `tool` on `server` (`bastion` for control tools) by
   * `client`. `undefined` when authorization is disabled. Notes a denial for status.
   */
  check(
    server: string,
    tool: string,
    args: unknown,
    client: string,
  ): AuthorizationCheck | undefined {
    if (!this.active) return undefined;
    const resolved = this.identities(server, client);
    let decision = authorize(this.policy, resolved.identities, tool, args);
    if (!resolved.ok) {
      decision = {
        ...decision,
        allowed: false,
        violations: [...decision.violations, "delegation:unverified"],
        rule: decision.allowed ? null : decision.rule,
        byDefault: false,
      };
    }
    if (!decision.allowed) {
      this.lastDenial = { rule: decision.rule, at: new Date().toISOString() };
    }
    const denied = !decision.allowed;
    return {
      decision,
      ...(denied
        ? { explanation: this.explain(decision, resolved.identities, tool, args, !resolved.ok) }
        : {}),
      blocks: denied && this.action === "block",
      wouldBlock:
        denied &&
        this.action === "warn" &&
        ENFORCEMENT_PROFILES.balanced.onAuthorization === "block",
      record: {
        effect: decision.allowed ? "allow" : "deny",
        rule: decision.rule,
        byDefault: decision.byDefault,
        client,
        identities: Object.keys(resolved.identities),
        violations: decision.violations,
      },
    };
  }

  /**
   * Whether `tool` (namespaced) on `server` belongs in `client`'s `tools/list`. Always `true` when
   * authorization is disabled; `false` when some identity could never be allowed it, whatever the
   * arguments, or when the carried delegate token is untrusted.
   */
  mayList(server: string, tool: string, client: string): boolean {
    if (!this.active) return true;
    const resolved = this.identities(server, client);
    return resolved.ok && mayList(this.policy, resolved.identities, tool);
  }

  /**
   * Whether `client` could be allowed any tool of `server` at all. When not (default deny, and no
   * allow rule for this client, or for every identity, reaches the server's tools), a `tools/list`
   * does not connect an idle on-demand upstream for it.
   */
  mayReach(server: string, client: string): boolean {
    if (!this.active || this.policy.default === "allow") return true;
    const prefix = server + this.separator;
    return this.policy.rules.some(
      (r) =>
        r.effect === "allow" &&
        principalMatches(r, "client", client) &&
        r.tools.some((p) => patternReachesPrefix(p, prefix)),
    );
  }

  /** Status summary, or `undefined` when authorization is disabled. */
  status(): AuthorizationStatus | undefined {
    if (!this.active) return undefined;
    return {
      enabled: true,
      default: this.policy.default,
      rules: this.policy.rules.length,
      action: this.action,
      trustStructuralClaims: this.trustStructural,
      lastDenial: this.lastDenial,
    };
  }

  /** Describe a denial: the deny rule, a missing grant, or the arguments a grant did not allow. */
  private explain(
    decision: AuthorizationDecision,
    identities: CallIdentities,
    tool: string,
    args: unknown,
    untrusted: boolean,
  ): string {
    if (decision.rule !== null) return `rule ${decision.rule}`;
    const parts: Array<{ kind: string; text: string }> = [];
    for (const v of decision.identities) {
      if (v.permitted) continue;
      const text =
        v.reason === "argument"
          ? describeShortfalls(
              argumentShortfalls(this.policy, v.kind, identities[v.kind] ?? "", tool, args),
            )
          : "no matching grant";
      parts.push({ kind: v.kind, text });
    }
    if (decision.identities.length === 0) parts.push({ kind: "none", text: "no matching grant" });
    const same = parts.every((p) => p.text === parts[0]?.text);
    const texts = same
      ? parts.slice(0, 1).map((p) => p.text)
      : parts.map((p) => `${p.kind}: ${p.text}`);
    if (untrusted) texts.push("delegate token not trusted");
    return texts.join("; ");
  }

  /** The authenticated identities of a call to `server` by `client` in the current request. */
  private identities(server: string, client: string): ResolvedIdentities {
    const identities: CallIdentities = { client };
    const mode = this.delegation.modeOf(server);
    // No delegation checks here, or claims nobody verified that the operator did not opt into.
    if (mode === undefined || (mode === "structural" && !this.trustStructural)) {
      return { ok: true, identities };
    }
    const token = this.delegation.tokenFor(server);
    const findings = this.delegation
      .findingsFor(server)
      .filter((f) => !DELEGATION_CHAIN_RULES.has(f.rule));
    if (!token) {
      // No token carried: only the client speaks. A token that did not decode is untrusted.
      return { ok: findings.length === 0, identities };
    }
    const verified = mode === "signature" ? token.verified === "signature" : true;
    if (token.subject !== null) identities.user = token.subject;
    if (token.actors.length > 0) identities.agent = token.actors[0];
    return { ok: verified && findings.length === 0, identities };
  }
}

/** `argument "env" not allowed by grant g1`, `argument "ref" missing, required by grant g2`, ... */
function describeShortfalls(shortfalls: ArgumentShortfall[]): string {
  const quote = (names: string[]) => names.map((n) => `"${n}"`).join(", ");
  const noun = (names: string[]) => (names.length === 1 ? "argument" : "arguments");
  const out: string[] = [];
  for (const s of shortfalls) {
    if (s.rejected.length > 0) {
      out.push(`${noun(s.rejected)} ${quote(s.rejected)} not allowed by grant ${s.rule}`);
    }
    if (s.missing.length > 0) {
      out.push(`${noun(s.missing)} ${quote(s.missing)} missing, required by grant ${s.rule}`);
    }
  }
  return out.length > 0 ? out.join(", ") : "arguments not allowed by any matching grant";
}
