/**
 * Request-scoped enforcement of the keyless delegation checks (see `security/delegation.ts`).
 *
 * The gate turns the configuration into a {@link DelegationPolicy}, computes one verdict per
 * downstream request on first need (cached in the request context, so `tools/call`, `tools/list`
 * and the fetch backstop agree; asynchronous when an upstream uses signature mode), resolves which findings block under the enforcement settings, and
 * builds the audit record. It also keeps, per upstream, the last violation for `bastion__status`
 * (rule id and time only).
 *
 * @packageDocumentation
 */
import { randomBytes } from "node:crypto";
import type { JSONWebKeySet } from "jose";

import type { AuditDelegationRecord } from "../audit/types.js";
import type { BastionConfig } from "../config/index.js";
import { ENFORCEMENT_PROFILES } from "../config/schema.js";
import {
  checkDelegation,
  checkDelegationAsync,
  DELEGATION_CHAIN_RULES,
  delegationKeySet,
  subjectPseudonym,
  type DelegationFinding,
  type DelegationPolicy,
  type DelegationResult,
  type DelegationRule,
  type DelegationUpstreamPolicy,
} from "../security/delegation.js";
import { currentRequestContext } from "./request-context.js";

/** One request's delegation verdict. */
export interface DelegationVerdict {
  result: DelegationResult;
  /** Upstream name → the rules that block it in this request (absent = not blocked). */
  blocked: Map<string, DelegationRule[]>;
}

/** What the gate says about one upstream in the current request. */
export interface DelegationCheck {
  /** All findings that apply: the upstream's own token, plus request-wide ones. */
  findings: DelegationFinding[];
  /** The subset that blocks under the enforcement settings (rule ids). */
  blocking: DelegationRule[];
  /** Whether a finding the configured actions let through would block under the `balanced` profile. */
  wouldBlock: boolean;
  /** The audit record, when the request carried a token for this upstream or a finding applies. */
  record?: AuditDelegationRecord;
}

/** Per-upstream delegation summary for `bastion__status`. */
export interface DelegationStatus {
  mode: "structural" | "signature";
  audience: string;
  /** Most recent finding on this upstream: rule id and time only. */
  lastViolation: { rule: DelegationRule; at: string } | null;
}

export class DelegationGate {
  private readonly policy: DelegationPolicy;
  private readonly audiences = new Map<string, string>();
  private readonly modes = new Map<string, "structural" | "signature">();
  /** Whether any upstream verifies signatures (the verdict is then computed asynchronously). */
  private readonly async: boolean;
  private readonly onDelegation: "block" | "warn";
  private readonly onChain: "block" | "warn";
  private readonly recordSubject: "hash" | "plain";
  private readonly subjectKey: string | Uint8Array;
  private readonly lastViolation = new Map<string, { rule: DelegationRule; at: string }>();

  /** @param config The validated Bastion configuration. */
  constructor(config: BastionConfig) {
    const upstreams: Record<string, DelegationUpstreamPolicy> = {};
    for (const [name, server] of Object.entries(config.servers)) {
      if (server.transport !== "http" || !server.delegation) continue;
      const d = server.delegation;
      const forward = Object.entries(server.forwardHeaders ?? {});
      // Schema validation guarantees a match (or exactly one key when `header` is unset).
      const entry = d.header
        ? forward.find(([up]) => up.toLowerCase() === d.header!.toLowerCase())
        : forward[0];
      if (!entry) continue;
      upstreams[name] = {
        incomingHeader: entry[1].toLowerCase(),
        audience: d.audience,
        maxLifetimeSeconds: d.maxLifetimeSeconds,
        clockSkewSeconds: d.clockSkewSeconds,
        allowedActors: d.allowedActors,
        requireActor: d.requireActor,
        maxChainDepth: d.maxChainDepth,
        ...(d.verify === "signature"
          ? {
              signature: {
                issuer: d.issuer!,
                algorithms: d.algorithms!,
                // Built once per upstream, so a remote set's cache and cooldown span requests.
                keys: delegationKeySet(
                  d.jwks ? { jwks: d.jwks as JSONWebKeySet } : { jwksUrl: d.jwksUrl! },
                ),
              },
            }
          : {}),
      };
      this.audiences.set(name, d.audience);
      this.modes.set(name, d.verify);
    }
    this.async = [...this.modes.values()].includes("signature");
    this.policy = {
      upstreams,
      gatewayAudiences: config.delegation.gatewayAudiences,
      oneUserPerRequest: config.delegation.oneUserPerRequest,
    };
    this.onDelegation = config.security.onDelegation;
    this.onChain = config.security.onDelegationChain;
    this.recordSubject = config.delegation.recordSubject;
    // A random key still gives stable pseudonyms within this process, but not across restarts.
    this.subjectKey =
      config.delegation.subjectKey ??
      process.env.MCP_BASTION_SUBJECT_KEY ??
      config.audit.integrityKey ??
      process.env.MCP_BASTION_AUDIT_KEY ??
      randomBytes(32);
  }

  /** Whether any upstream has delegation checks. */
  get enabled(): boolean {
    return this.audiences.size > 0;
  }

  /** Whether `server` has delegation checks. */
  covers(server: string): boolean {
    return this.audiences.has(server);
  }

  /**
   * Compute the current request's verdict once and cache it in the request context; concurrent
   * callers in the same request share one computation. `undefined` outside a request (nothing is
   * forwarded then) or when no upstream has delegation checks. Never rejects.
   */
  async ensure(): Promise<DelegationVerdict | undefined> {
    if (!this.enabled) return undefined;
    const ctx = currentRequestContext();
    if (!ctx) return undefined;
    if (ctx.delegation) return ctx.delegation;
    if (!this.async) return this.verdict();
    ctx.delegationPending ??= checkDelegationAsync(
      this.policy,
      ctx.headers,
      Math.floor(Date.now() / 1000),
    ).then((result) => (ctx.delegation = this.resolve(result)));
    return ctx.delegationPending;
  }

  /**
   * The current request's verdict if it is known now: computed on the spot in structural mode,
   * `undefined` while a signature-mode verdict has not been awaited ({@link ensure}).
   */
  verdict(): DelegationVerdict | undefined {
    if (!this.enabled) return undefined;
    const ctx = currentRequestContext();
    if (!ctx) return undefined;
    if (ctx.delegation || this.async) return ctx.delegation;
    ctx.delegation = this.resolve(
      checkDelegation(this.policy, ctx.headers, Math.floor(Date.now() / 1000)),
    );
    return ctx.delegation;
  }

  /**
   * Rules that block `server` in the current request (empty = go ahead). Fails closed: while a
   * signature-mode verdict is still pending, a covered upstream reports `delegation-pending`.
   */
  blockingRules(server: string): string[] {
    const verdict = this.verdict();
    if (!verdict) {
      return this.covers(server) && this.async && currentRequestContext()
        ? ["delegation-pending"]
        : [];
    }
    return verdict.blocked.get(server) ?? [];
  }

  /** An operational error behind a fail-closed finding for `server` (e.g. JWKS unreachable). */
  errorFor(server: string): string | undefined {
    return this.verdict()?.result.errors?.[server];
  }

  private resolve(result: DelegationResult): DelegationVerdict {
    const blocked = new Map<string, DelegationRule[]>();
    for (const server of this.audiences.keys()) {
      const rules = this.applicable(result, server)
        .filter((f) => this.blocks(f.rule))
        .map((f) => f.rule);
      if (rules.length > 0) blocked.set(server, [...new Set(rules)]);
    }
    return { result, blocked };
  }

  /**
   * Everything the gate says about `server` in the current request, or `undefined` when `server`
   * has no delegation checks or there is no request. Notes the last violation for status.
   */
  check(server: string): DelegationCheck | undefined {
    if (!this.covers(server)) return undefined;
    const verdict = this.verdict();
    if (!verdict) return undefined;
    const findings = this.applicable(verdict.result, server);
    if (findings.length > 0) {
      const first = findings.find((f) => this.blocks(f.rule)) ?? findings[0];
      this.lastViolation.set(server, { rule: first.rule, at: new Date().toISOString() });
    }
    const carried = server in verdict.result.perUpstream;
    const blocking = verdict.blocked.get(server) ?? [];
    return {
      findings,
      blocking,
      wouldBlock:
        blocking.length === 0 &&
        findings.some(
          (f) =>
            ENFORCEMENT_PROFILES.balanced[
              DELEGATION_CHAIN_RULES.has(f.rule) ? "onDelegationChain" : "onDelegation"
            ] === "block",
        ),
      ...(carried || findings.length > 0 ? { record: this.record(verdict, server, findings) } : {}),
    };
  }

  /** Status summary for `server`, or `undefined` when it has no delegation checks. */
  status(server: string): DelegationStatus | undefined {
    const audience = this.audiences.get(server);
    if (audience === undefined) return undefined;
    return {
      mode: this.modes.get(server)!,
      audience,
      lastViolation: this.lastViolation.get(server) ?? null,
    };
  }

  /** Findings that apply to `server`: its own token's, plus the request-wide ones. */
  private applicable(result: DelegationResult, server: string): DelegationFinding[] {
    return [...(result.perUpstream[server] ?? []), ...result.request];
  }

  private blocks(rule: DelegationRule): boolean {
    return (DELEGATION_CHAIN_RULES.has(rule) ? this.onChain : this.onDelegation) === "block";
  }

  private record(
    verdict: DelegationVerdict,
    server: string,
    findings: readonly DelegationFinding[],
  ): AuditDelegationRecord {
    const info = verdict.result.tokens[server];
    let subject: string | null = null;
    if (info?.subject != null) {
      subject =
        this.recordSubject === "plain"
          ? info.subject
          : subjectPseudonym(this.subjectKey, info.issuer ?? "", info.subject);
    }
    return {
      subject,
      issuer: info?.issuer ?? null,
      audience: this.audiences.get(server)!,
      tokenId: info?.tokenId ?? null,
      expiresAt: info?.expiresAt != null ? isoOrNull(info.expiresAt) : null,
      actors: info ? [...info.actors] : [],
      chainDepth: info?.actors.length ?? 0,
      verified:
        info?.verified ?? (this.modes.get(server) === "signature" ? "failed" : "structural"),
      findings: findings.map((f) => ({ rule: f.rule, severity: f.severity })),
    };
  }
}

/** A NumericDate as ISO-8601, or `null` when it is outside the representable range. */
function isoOrNull(seconds: number): string | null {
  const d = new Date(seconds * 1000);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}
