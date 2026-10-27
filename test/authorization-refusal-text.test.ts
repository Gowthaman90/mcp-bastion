/**
 * The refusal text says what actually failed: a deny rule, a missing grant, or the arguments a
 * matching grant did not allow. The decision itself is covered in `authorization.test.ts`.
 */
import { describe, expect, it } from "vitest";

import { BastionConfigSchema } from "../src/config/index.js";
import { AuthorizationGate } from "../src/core/authorization-gate.js";
import type { DelegationGate } from "../src/core/delegation-gate.js";
import { argumentShortfalls, type AuthorizationPolicy } from "../src/security/authorization.js";

const rules = [
  {
    id: "release-staging",
    effect: "allow",
    principal: { client: "release-bot" },
    tools: ["deploy__promote"],
    args: { env: { in: ["staging", "qa"] }, ref: { equals: "main" } },
  },
  {
    id: "release-canary",
    effect: "allow",
    principal: { client: "release-bot" },
    tools: ["deploy__promote"],
    args: { env: { equals: "canary" } },
  },
  { id: "no-rollback", effect: "deny", principal: "*", tools: ["deploy__rollback"] },
  {
    id: "bot-rollback",
    effect: "allow",
    principal: { client: "release-bot" },
    tools: ["deploy__rollback"],
  },
  { id: "maintainer", effect: "allow", principal: { user: "maintainer" }, tools: ["deploy__*"] },
  {
    id: "agent-staging",
    effect: "allow",
    principal: { agent: "release-agent" },
    tools: ["deploy__promote"],
    args: { env: { equals: "staging" } },
  },
];

/** A gate over `rules`, with an optional (trusted or untrusted) delegate token for `deploy`. */
function gate(token?: { subject: string; actors: string[]; verified: string }) {
  const config = BastionConfigSchema.parse({
    servers: {},
    listen: { clients: { "release-bot": { tokenEnv: "T1" }, "docs-bot": { tokenEnv: "T2" } } },
    authorization: { enabled: true, rules },
  });
  const delegation = {
    modeOf: () => (token ? "signature" : undefined),
    tokenFor: () => token,
    findingsFor: () => [],
  } as unknown as DelegationGate;
  return new AuthorizationGate(config, delegation);
}

const explain = (g: AuthorizationGate, tool: string, args: unknown, client = "release-bot") =>
  g.check("deploy", tool, args, client)?.explanation;

describe("authorization refusal text", () => {
  it("names the argument a matching grant did not allow, not 'no matching grant'", () => {
    expect(explain(gate(), "deploy__promote", { env: "prod", ref: "main" })).toBe(
      'argument "env" not allowed by grant release-staging, ' +
        'argument "env" not allowed by grant release-canary',
    );
  });

  it("says when a constrained argument is missing, and lists several per grant", () => {
    expect(explain(gate(), "deploy__promote", { env: "staging" })).toBe(
      'argument "ref" missing, required by grant release-staging, ' +
        'argument "env" not allowed by grant release-canary',
    );
    expect(explain(gate(), "deploy__promote", { env: "prod", ref: "dev" })).toMatch(
      /^arguments "env", "ref" not allowed by grant release-staging, /,
    );
  });

  it("an uncomparable value counts as not allowed", () => {
    expect(explain(gate(), "deploy__promote", { env: ["staging"], ref: "main" })).toMatch(
      /^argument "env" not allowed by grant release-staging/,
    );
  });

  it("keeps 'no matching grant' and 'rule <id>' as before", () => {
    expect(explain(gate(), "deploy__promote", { env: "staging" }, "docs-bot")).toBe(
      "no matching grant",
    );
    expect(explain(gate(), "deploy__rollback", {})).toBe("rule no-rollback");
  });

  it("an allowed call has no explanation", () => {
    const check = gate().check(
      "deploy",
      "deploy__promote",
      { env: "qa", ref: "main" },
      "release-bot",
    );
    expect(check?.decision.allowed).toBe(true);
    expect(check?.explanation).toBeUndefined();
  });

  it("prefixes the identity when refused identities failed differently", () => {
    const g = gate({ subject: "contributor", actors: ["release-agent"], verified: "signature" });
    expect(explain(g, "deploy__promote", { env: "prod", ref: "main" })).toBe(
      'client: argument "env" not allowed by grant release-staging, ' +
        'argument "env" not allowed by grant release-canary; ' +
        "user: no matching grant; " +
        'agent: argument "env" not allowed by grant agent-staging',
    );
  });

  it("says when the delegate token was not trusted", () => {
    const g = gate({ subject: "maintainer", actors: ["release-agent"], verified: "none" });
    const check = g.check(
      "deploy",
      "deploy__promote",
      { env: "staging", ref: "main" },
      "release-bot",
    );
    expect(check?.decision.violations).toEqual(["delegation:unverified"]);
    expect(check?.explanation).toBe("delegate token not trusted");
  });

  it("the audit record keeps the decision's reasons, unchanged", () => {
    const check = gate().check(
      "deploy",
      "deploy__promote",
      { env: "prod", ref: "main" },
      "release-bot",
    );
    expect(check?.record).toMatchObject({
      effect: "deny",
      rule: null,
      byDefault: false,
      violations: ["client:argument"],
    });
  });
});

describe("argumentShortfalls", () => {
  const policy: AuthorizationPolicy = {
    default: "deny",
    rules: BastionConfigSchema.parse({
      servers: {},
      listen: { clients: { "release-bot": { tokenEnv: "T1" } } },
      authorization: { enabled: true, rules: rules.slice(0, 2) },
    }).authorization.rules,
  };

  it("lists each matching grant and the arguments it fell short on, in policy order", () => {
    expect(
      argumentShortfalls(policy, "client", "release-bot", "deploy__promote", { env: "staging" }),
    ).toEqual([
      { rule: "release-staging", missing: ["ref"], rejected: [] },
      { rule: "release-canary", missing: [], rejected: ["env"] },
    ]);
  });

  it("ignores rules for other identities or tools, and non-object arguments are no arguments", () => {
    expect(argumentShortfalls(policy, "client", "docs-bot", "deploy__promote", {})).toEqual([]);
    expect(argumentShortfalls(policy, "client", "release-bot", "deploy__rollback", {})).toEqual([]);
    expect(argumentShortfalls(policy, "client", "release-bot", "deploy__promote", null)).toEqual([
      { rule: "release-staging", missing: ["env", "ref"], rejected: [] },
      { rule: "release-canary", missing: ["env"], rejected: [] },
    ]);
  });
});
