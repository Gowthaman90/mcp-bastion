/**
 * Runtime authorization: which authenticated caller may call which tool, with which arguments.
 *
 * A call carries up to three authenticated identities: the `client` (the application that holds a
 * Bastion bearer token, or `stdio`), the `user` (the `sub` of a trusted delegate token) and the
 * `agent` (that token's current actor). Prior actors in a delegation chain grant nothing
 * (RFC 8693 §4.1), and nothing the caller writes into the request (arguments, headers, `_meta`,
 * input responses) is ever an identity.
 *
 * The decision is an intersection: the call is allowed only if **every** identity it carries is
 * permitted, so an agent acting for a user needs both the user's grant and its own. Per identity,
 * a matching `deny` wins over any `allow` (deny overrides allow); otherwise an `allow` whose
 * argument constraints all hold is needed. A deny with argument constraints fails closed: it
 * applies unless its constraints evaluate and do not hold. The evaluator is pure: no I/O, no clock, no config
 * parsing.
 *
 * @packageDocumentation
 */

/** The kinds of authenticated identity a call can carry. */
export type IdentityKind = "client" | "user" | "agent";

/** Identity kinds in evaluation (and reporting) order. */
export const IDENTITY_KINDS: readonly IdentityKind[] = ["client", "user", "agent"];

/** A JSON scalar an `equals` / `in` constraint compares against. */
export type AuthorizationScalar = string | number | boolean;

/**
 * Constraints on one top-level argument. Every listed constraint must hold; a constrained argument
 * that is missing fails.
 */
export interface ArgumentConstraint {
  /** The value is a JSON string, boolean or finite number exactly equal to this (no coercion). */
  equals?: AuthorizationScalar;
  /** The value is a JSON string, boolean or finite number exactly equal to one of these. */
  in?: readonly AuthorizationScalar[];
  /** The value is a JSON number no greater than this. A numeric string fails. */
  max?: number;
  /** The value is a JSON number no smaller than this. A numeric string fails. */
  min?: number;
  /**
   * The value is an absolute POSIX path without NUL that, after resolving `.` and `..`, equals this
   * base or lies below it at a `/` boundary (`/a/b-archive` is not below `/a/b`).
   */
  pathWithin?: string;
}

/** Who a rule applies to: every identity (`"*"`), or the named identities of one or more kinds. */
export type RulePrincipal = "*" | Partial<Record<IdentityKind, string | readonly string[]>>;

/** One authorization rule. */
export interface AuthorizationRule {
  /** Stable id, recorded in the audit event and named in the refusal message of a deny rule. */
  id: string;
  effect: "allow" | "deny";
  principal: RulePrincipal;
  /** Client-visible (namespaced) tool names: exact, or with one trailing `*` as a prefix match. */
  tools: readonly string[];
  /** Constraints on top-level arguments; all must hold for the rule to match. */
  args?: Readonly<Record<string, ArgumentConstraint>>;
}

/** A complete policy. */
export interface AuthorizationPolicy {
  /**
   * What happens when an identity has no `allow` rule for the tool at all: `deny` (the safe
   * default) or `allow`. An identity that has an allow rule for the tool whose arguments do not
   * hold is refused under both defaults.
   */
  default: "deny" | "allow";
  rules: readonly AuthorizationRule[];
}

/** The authenticated identities of one call. Absent kind = not carried. */
export type CallIdentities = Partial<Record<IdentityKind, string>>;

/**
 * Why an identity was refused: an explicit `deny` matched, no `allow` exists for the tool, or every
 * `allow` for the tool has an argument constraint that does not hold.
 */
export type AuthorizationReason = "denied" | "no-grant" | "argument";

/** The verdict for one identity. */
export interface IdentityVerdict {
  kind: IdentityKind;
  permitted: boolean;
  /** Set when refused. */
  reason?: AuthorizationReason;
  /** The deciding rule: the matching deny, or the first matching allow. `null` = by default. */
  rule: string | null;
}

/** The verdict for one call. */
export interface AuthorizationDecision {
  allowed: boolean;
  /** One verdict per carried identity, in {@link IDENTITY_KINDS} order. */
  identities: IdentityVerdict[];
  /** `<kind>:<reason>` for each refused identity, e.g. `["agent:argument"]`. */
  violations: string[];
  /**
   * The deciding rule: on a refusal, the first matching deny rule (if any); on an allow, the first
   * identity's matching allow rule. `null` when the decision came from the default or from argument
   * constraints with no deny rule involved.
   */
  rule: string | null;
  /** Whether no rule decided: refused for lack of a grant, or allowed by `default: "allow"`. */
  byDefault: boolean;
}

/**
 * Whether a tool pattern matches a namespaced tool name: exact, or one trailing `*` as a prefix
 * match (`"ci__*"`, or `"*"` for every tool). A `*` anywhere else never matches.
 */
export function matchesToolPattern(pattern: string, name: string): boolean {
  const star = pattern.indexOf("*");
  if (star === -1) return pattern === name;
  if (star !== pattern.length - 1) return false;
  return name.startsWith(pattern.slice(0, -1));
}

/**
 * Whether a tool pattern could match some tool whose namespaced name starts with `prefix` (an
 * upstream's `<server><separator>`).
 */
export function patternReachesPrefix(pattern: string, prefix: string): boolean {
  if (!pattern.endsWith("*")) return pattern.startsWith(prefix);
  const head = pattern.slice(0, -1);
  return head.startsWith(prefix) || prefix.startsWith(head);
}

/** Whether a tool pattern is well formed (non-empty; at most one `*`, and only at the end). */
export function isValidToolPattern(pattern: string): boolean {
  if (pattern.length === 0) return false;
  const star = pattern.indexOf("*");
  return star === -1 || star === pattern.length - 1;
}

/**
 * Resolve `.` and `..` in an absolute POSIX path, collapsing repeated `/`. `..` at the root stays at
 * the root. Returns `undefined` for a relative path or one containing NUL. Nothing is decoded:
 * `%2e%2e` stays a literal segment.
 */
export function resolvePosixPath(path: string): string | undefined {
  if (!path.startsWith("/") || path.includes("\0")) return undefined;
  const out: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") out.pop();
    else out.push(segment);
  }
  return "/" + out.join("/");
}

/** Whether `value` is an absolute path that resolves to `base` or below it at a `/` boundary. */
export function isPathWithin(base: string, value: unknown): boolean {
  if (typeof value !== "string") return false;
  const root = resolvePosixPath(base);
  const resolved = resolvePosixPath(value);
  if (root === undefined || resolved === undefined) return false;
  if (resolved === root || root === "/") return true;
  return resolved.startsWith(root + "/");
}

function isComparableScalar(value: unknown): value is AuthorizationScalar {
  return (
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  );
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/**
 * The result of evaluating constraints on an argument: they `hold`, they evaluate and `fail`, or
 * they cannot be evaluated (`unevaluable`: the argument is missing, or its type is one the
 * constraint cannot compare). An allow needs `holds`; a deny applies unless the result is `fails`.
 */
export type ConstraintResult = "holds" | "fails" | "unevaluable";

/** Combine per-constraint results: any `fails` wins, then any `unevaluable`, else `holds`. */
function combine(results: readonly ConstraintResult[]): ConstraintResult {
  if (results.includes("fails")) return "fails";
  return results.includes("unevaluable") ? "unevaluable" : "holds";
}

/**
 * Evaluate one argument against its constraints. `present` is `false` for a missing argument.
 * A value whose type a constraint cannot compare is `unevaluable`: for `equals`, a non-scalar or a
 * scalar of a different JSON type; for `in`, one matching the type of no member; for `max`/`min`,
 * anything but a finite JSON number (a numeric string included); for `pathWithin`, anything but an
 * absolute POSIX path without NUL.
 */
export function evaluateConstraint(
  constraint: ArgumentConstraint,
  present: boolean,
  value: unknown,
): ConstraintResult {
  if (!present) return "unevaluable";
  const results: ConstraintResult[] = [];
  if (constraint.equals !== undefined) {
    const expected = constraint.equals;
    results.push(
      !isComparableScalar(value) || typeof value !== typeof expected
        ? "unevaluable"
        : value === expected
          ? "holds"
          : "fails",
    );
  }
  if (constraint.in !== undefined) {
    const members = constraint.in;
    results.push(
      !isComparableScalar(value) || !members.some((v) => typeof v === typeof value)
        ? "unevaluable"
        : members.some((v) => v === value)
          ? "holds"
          : "fails",
    );
  }
  if (constraint.max !== undefined) {
    const max = constraint.max;
    results.push(!isFiniteNumber(value) ? "unevaluable" : value <= max ? "holds" : "fails");
  }
  if (constraint.min !== undefined) {
    const min = constraint.min;
    results.push(!isFiniteNumber(value) ? "unevaluable" : value >= min ? "holds" : "fails");
  }
  if (constraint.pathWithin !== undefined) {
    results.push(
      typeof value !== "string" || resolvePosixPath(value) === undefined
        ? "unevaluable"
        : isPathWithin(constraint.pathWithin, value)
          ? "holds"
          : "fails",
    );
  }
  return combine(results);
}

/**
 * Whether one argument satisfies its constraints (they evaluate and hold). A missing argument, or
 * one of a type the constraint cannot compare, does not.
 */
export function satisfiesConstraint(
  constraint: ArgumentConstraint,
  present: boolean,
  value: unknown,
): boolean {
  return evaluateConstraint(constraint, present, value) === "holds";
}

/** Evaluate every argument constraint of `rule` against `args` (a rule without `args` holds). */
export function evaluateArguments(rule: AuthorizationRule, args: unknown): ConstraintResult {
  if (!rule.args) return "holds";
  const record =
    args !== null && typeof args === "object" && !Array.isArray(args)
      ? (args as Record<string, unknown>)
      : {};
  const results: ConstraintResult[] = [];
  for (const [name, constraint] of Object.entries(rule.args)) {
    const present =
      Object.prototype.hasOwnProperty.call(record, name) && record[name] !== undefined;
    results.push(evaluateConstraint(constraint, present, present ? record[name] : undefined));
  }
  return combine(results);
}

/** Whether every argument constraint of `rule` holds for `args` (a rule without `args` holds). */
export function argumentsSatisfied(rule: AuthorizationRule, args: unknown): boolean {
  return evaluateArguments(rule, args) === "holds";
}

/**
 * Whether a deny rule applies to `args`. Fails closed: it applies unless its constraints evaluate
 * and do not hold, so a missing argument, or one of a type the constraint cannot compare, is
 * refused. (Stricter than the benchmark's prereg §4 rule 3, where a deny needs its args satisfied.)
 */
export function denyApplies(rule: AuthorizationRule, args: unknown): boolean {
  return evaluateArguments(rule, args) !== "fails";
}

/** Whether `rule` applies to the identity `kind` = `id` (ignoring tools). */
export function principalMatches(rule: AuthorizationRule, kind: IdentityKind, id: string): boolean {
  if (rule.principal === "*") return true;
  const named = rule.principal[kind];
  if (named === undefined) return false;
  return typeof named === "string" ? named === id : named.includes(id);
}

/** The rules that apply to one identity for one tool, in policy order. */
function applicableRules(
  policy: AuthorizationPolicy,
  kind: IdentityKind,
  id: string,
  tool: string,
): AuthorizationRule[] {
  return policy.rules.filter(
    (r) => principalMatches(r, kind, id) && r.tools.some((p) => matchesToolPattern(p, tool)),
  );
}

/** The verdict for one identity. */
function judgeIdentity(
  policy: AuthorizationPolicy,
  kind: IdentityKind,
  id: string,
  tool: string,
  args: unknown,
): IdentityVerdict {
  const rules = applicableRules(policy, kind, id, tool);
  const deny = rules.find((r) => r.effect === "deny" && denyApplies(r, args));
  if (deny) return { kind, permitted: false, reason: "denied", rule: deny.id };
  const allows = rules.filter((r) => r.effect === "allow");
  if (allows.length === 0) {
    return policy.default === "allow"
      ? { kind, permitted: true, rule: null }
      : { kind, permitted: false, reason: "no-grant", rule: null };
  }
  const allow = allows.find((r) => argumentsSatisfied(r, args));
  if (!allow) return { kind, permitted: false, reason: "argument", rule: null };
  return { kind, permitted: true, rule: allow.id };
}

/**
 * Decide one `tools/call`. `tool` is the client-visible (namespaced) name and `args` the call's
 * arguments. A call that carries no identity at all is refused.
 */
export function authorize(
  policy: AuthorizationPolicy,
  identities: CallIdentities,
  tool: string,
  args: unknown,
): AuthorizationDecision {
  const verdicts: IdentityVerdict[] = [];
  for (const kind of IDENTITY_KINDS) {
    const id = identities[kind];
    if (id !== undefined) verdicts.push(judgeIdentity(policy, kind, id, tool, args));
  }
  if (verdicts.length === 0) {
    return {
      allowed: false,
      identities: [],
      violations: ["none:no-grant"],
      rule: null,
      byDefault: true,
    };
  }
  const refused = verdicts.filter((v) => !v.permitted);
  if (refused.length > 0) {
    const deny = refused.find((v) => v.reason === "denied");
    return {
      allowed: false,
      identities: verdicts,
      violations: refused.map((v) => `${v.kind}:${v.reason}`),
      rule: deny?.rule ?? null,
      byDefault: !deny && refused.every((v) => v.reason === "no-grant"),
    };
  }
  return {
    allowed: true,
    identities: verdicts,
    violations: [],
    rule: verdicts[0].rule,
    byDefault: verdicts.some((v) => v.rule === null),
  };
}

/**
 * Whether a tool should appear in this caller's `tools/list`: `false` when, for some carried
 * identity, an argument-free deny applies or (under `default: "deny"`) no allow rule matches the
 * tool at all. Argument constraints are ignored, so a tool with an argument-constrained allow stays
 * listed (each call is still decided by {@link authorize}).
 */
export function mayList(
  policy: AuthorizationPolicy,
  identities: CallIdentities,
  tool: string,
): boolean {
  let carried = 0;
  for (const kind of IDENTITY_KINDS) {
    const id = identities[kind];
    if (id === undefined) continue;
    carried++;
    const rules = applicableRules(policy, kind, id, tool);
    if (rules.some((r) => r.effect === "deny" && !r.args)) return false;
    if (policy.default === "deny" && !rules.some((r) => r.effect === "allow")) return false;
  }
  return carried > 0;
}
