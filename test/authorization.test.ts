/**
 * The pure runtime-authorization evaluator: deny overrides allow, intersection across identities,
 * tool patterns, and every argument constraint (with the encodings that slip past naive checks).
 */
import { describe, expect, it } from "vitest";

import {
  authorize,
  isPathWithin,
  isValidToolPattern,
  matchesToolPattern,
  mayList,
  resolvePosixPath,
  satisfiesConstraint,
  type ArgumentConstraint,
  type AuthorizationPolicy,
} from "../src/security/index.js";

const policy: AuthorizationPolicy = {
  default: "deny",
  rules: [
    { id: "triage-ci", effect: "allow", principal: { client: "triage-bot" }, tools: ["ci__*"] },
    {
      id: "triage-no-cache",
      effect: "deny",
      principal: { client: "triage-bot" },
      tools: ["ci__delete_cache"],
    },
    {
      id: "release-staging",
      effect: "allow",
      principal: { client: "release-bot" },
      tools: ["deploy__*"],
      args: { env: { in: ["staging"] } },
    },
    {
      id: "docs-read",
      effect: "allow",
      principal: { client: "docs-bot" },
      tools: ["repo__read_file"],
      args: { path: { pathWithin: "/srv/checkouts/handbook" } },
    },
    {
      id: "ci-timeout",
      effect: "allow",
      principal: { client: "ci-bot" },
      tools: ["ci__extend_timeout"],
      args: { minutes: { max: 60, min: 1 } },
    },
    {
      id: "mei-all",
      effect: "allow",
      principal: { user: "user:mei.l" },
      tools: ["repo__*", "deploy__*"],
    },
    {
      id: "omar-read",
      effect: "allow",
      principal: { user: "user:omar.s" },
      tools: ["repo__read_file"],
    },
    {
      id: "triage-agent",
      effect: "allow",
      principal: { agent: "triage-agent" },
      tools: ["repo__read_file"],
    },
    {
      id: "release-agent",
      effect: "allow",
      principal: { agent: "release-agent" },
      tools: ["deploy__promote"],
      args: { env: { equals: "staging" } },
    },
    {
      id: "platform-agent",
      effect: "allow",
      principal: { agent: "platform-agent" },
      tools: ["deploy__*"],
    },
    { id: "host", effect: "allow", principal: { client: "agent-host" }, tools: ["*"] },
    {
      id: "no-prod-rollback",
      effect: "deny",
      principal: "*",
      tools: ["deploy__rollback"],
      args: { env: { equals: "prod" } },
    },
  ],
};

describe("authorize: per-identity verdicts", () => {
  it.each([
    // [identities, tool, args, allowed, violations, rule]
    [{ client: "triage-bot" }, "ci__rerun_job", {}, true, [], "triage-ci"],
    [{ client: "triage-bot" }, "ci__delete_cache", {}, false, ["client:denied"], "triage-no-cache"],
    [{ client: "triage-bot" }, "repo__merge_pr", {}, false, ["client:no-grant"], null],
    [{ client: "release-bot" }, "deploy__promote", { env: "staging" }, true, [], "release-staging"],
    [
      { client: "release-bot" },
      "deploy__promote",
      { env: "prod" },
      false,
      ["client:argument"],
      null,
    ],
    [{ client: "release-bot" }, "deploy__promote", {}, false, ["client:argument"], null],
    [{ client: "unknown-bot" }, "ci__rerun_job", {}, false, ["client:no-grant"], null],
  ] as const)("%j calls %s %j → %s", (identities, tool, args, allowed, violations, rule) => {
    const d = authorize(policy, identities, tool, args);
    expect(d.allowed).toBe(allowed);
    expect(d.violations).toEqual(violations);
    expect(d.rule).toBe(rule);
  });

  it("deny overrides allow regardless of rule order", () => {
    const reversed: AuthorizationPolicy = { ...policy, rules: [...policy.rules].reverse() };
    for (const p of [policy, reversed]) {
      expect(authorize(p, { client: "triage-bot" }, "ci__delete_cache", {})).toMatchObject({
        allowed: false,
        rule: "triage-no-cache",
        byDefault: false,
      });
    }
  });

  it("the first matching allow is the recorded rule", () => {
    const p: AuthorizationPolicy = {
      default: "deny",
      rules: [
        { id: "a", effect: "allow", principal: "*", tools: ["x__*"] },
        { id: "b", effect: "allow", principal: { client: "c" }, tools: ["x__y"] },
      ],
    };
    expect(authorize(p, { client: "c" }, "x__y", {})).toMatchObject({ allowed: true, rule: "a" });
  });

  it("an allow with failing constraints falls through to a later allow that holds", () => {
    const p: AuthorizationPolicy = {
      default: "deny",
      rules: [
        {
          id: "small",
          effect: "allow",
          principal: "*",
          tools: ["pay__send"],
          args: { amount: { max: 10 } },
        },
        {
          id: "eur",
          effect: "allow",
          principal: "*",
          tools: ["pay__send"],
          args: { currency: { equals: "EUR" } },
        },
      ],
    };
    expect(authorize(p, { client: "c" }, "pay__send", { amount: 500, currency: "EUR" }).rule).toBe(
      "eur",
    );
    expect(
      authorize(p, { client: "c" }, "pay__send", { amount: 500, currency: "USD" }).violations,
    ).toEqual(["client:argument"]);
  });

  it("a deny with argument constraints fails closed: it applies unless they evaluate and do not hold", () => {
    const host = { client: "agent-host", user: "user:mei.l", agent: "platform-agent" };
    // Evaluated and matching: refused.
    expect(authorize(policy, host, "deploy__rollback", { env: "prod" })).toMatchObject({
      allowed: false,
      rule: "no-prod-rollback",
    });
    // Evaluated and not matching: the deny does not apply.
    expect(authorize(policy, host, "deploy__rollback", { env: "staging" }).allowed).toBe(true);
    // Argument missing: cannot be evaluated, so the deny applies (stricter than prereg §4 rule 3).
    expect(authorize(policy, host, "deploy__rollback", {})).toMatchObject({
      allowed: false,
      rule: "no-prod-rollback",
      violations: ["client:denied", "user:denied", "agent:denied"],
    });
    expect(authorize(policy, host, "deploy__rollback", null).rule).toBe("no-prod-rollback");
    // Wrong type: cannot be compared, so the deny applies.
    for (const env of [1, true, null, ["prod"], { name: "prod" }]) {
      expect(authorize(policy, host, "deploy__rollback", { env }).rule).toBe("no-prod-rollback");
    }
  });

  it.each([
    // [constraint, value, deny applies]
    [{ min: 100 }, 500, true],
    [{ min: 100 }, 50, false],
    [{ min: 100 }, "500", true],
    [{ min: 100 }, undefined, true],
    [{ in: ["prod", "dr"] }, "dr", true],
    [{ in: ["prod", "dr"] }, "staging", false],
    [{ in: ["prod", "dr"] }, 7, true],
    [{ equals: 0 }, "0", true],
    [{ equals: 0 }, 1, false],
    [{ pathWithin: "/secrets" }, "/secrets/../secrets/key", true],
    [{ pathWithin: "/secrets" }, "/public/a", false],
    [{ pathWithin: "/secrets" }, "secrets/key", true],
    [{ pathWithin: "/secrets" }, "/secrets\0/key", true],
    [{ pathWithin: "/secrets" }, 42, true],
  ] as const)("deny %j with value %j → applies: %s", (constraint, value, applies) => {
    const p: AuthorizationPolicy = {
      default: "deny",
      rules: [
        { id: "all", effect: "allow", principal: "*", tools: ["t__x"] },
        { id: "guard", effect: "deny", principal: "*", tools: ["t__x"], args: { v: constraint } },
      ],
    };
    const args = value === undefined ? {} : { v: value };
    expect(authorize(p, { client: "c" }, "t__x", args).allowed).toBe(!applies);
  });

  it("a deny with several constraints does not apply once one evaluates and fails", () => {
    const p: AuthorizationPolicy = {
      default: "deny",
      rules: [
        { id: "all", effect: "allow", principal: "*", tools: ["t__x"] },
        {
          id: "guard",
          effect: "deny",
          principal: "*",
          tools: ["t__x"],
          args: { env: { equals: "prod" }, amount: { min: 1000 } },
        },
      ],
    };
    expect(authorize(p, { client: "c" }, "t__x", { env: "prod", amount: 5000 }).allowed).toBe(
      false,
    );
    expect(authorize(p, { client: "c" }, "t__x", { env: "prod" }).allowed).toBe(false); // amount missing
    expect(authorize(p, { client: "c" }, "t__x", { env: "qa" }).allowed).toBe(true); // env evaluates, fails
    expect(authorize(p, { client: "c" }, "t__x", { env: "prod", amount: 10 }).allowed).toBe(true);
  });

  it("allow rules are unchanged: a missing or wrong-type argument still fails the allow", () => {
    expect(authorize(policy, { client: "ci-bot" }, "ci__extend_timeout", {}).violations).toEqual([
      "client:argument",
    ]);
    expect(
      authorize(policy, { client: "ci-bot" }, "ci__extend_timeout", { minutes: "30" }).violations,
    ).toEqual(["client:argument"]);
  });

  it("default allow grants tools with no allow rule, but still enforces scoped allows and denies", () => {
    const open: AuthorizationPolicy = { ...policy, default: "allow" };
    expect(authorize(open, { client: "docs-bot" }, "issues__label", {})).toMatchObject({
      allowed: true,
      rule: null,
      byDefault: true,
    });
    expect(
      authorize(open, { client: "release-bot" }, "deploy__promote", { env: "prod" }).allowed,
    ).toBe(false);
    expect(authorize(open, { client: "triage-bot" }, "ci__delete_cache", {}).allowed).toBe(false);
  });

  it("refuses a call that carries no identity", () => {
    expect(authorize(policy, {}, "ci__rerun_job", {})).toMatchObject({
      allowed: false,
      violations: ["none:no-grant"],
    });
  });

  it("byDefault is true only when no rule decided", () => {
    expect(authorize(policy, { client: "nobody" }, "x__y", {}).byDefault).toBe(true);
    expect(
      authorize(policy, { client: "release-bot" }, "deploy__promote", { env: "prod" }).byDefault,
    ).toBe(false);
  });
});

describe("authorize: intersection across client, user and agent", () => {
  const host = (user: string, agent: string) => ({ client: "agent-host", user, agent });

  it("needs both the user's grant and the agent's own", () => {
    expect(
      authorize(policy, host("user:mei.l", "triage-agent"), "repo__read_file", {}).allowed,
    ).toBe(true);
    // The user may merge, the agent may not.
    expect(
      authorize(policy, host("user:mei.l", "triage-agent"), "repo__merge_pr", {}).violations,
    ).toEqual(["agent:no-grant"]);
    // The agent's broad grant is not used for a user who lacks it (confused deputy).
    expect(
      authorize(policy, host("user:omar.s", "platform-agent"), "deploy__rollback", {
        env: "staging",
      }).violations,
    ).toEqual(["user:no-grant"]);
  });

  it("an argument within the user's grant but outside the agent's is refused for the agent", () => {
    const d = authorize(policy, host("user:mei.l", "release-agent"), "deploy__promote", {
      env: "prod",
    });
    expect(d.violations).toEqual(["agent:argument"]);
    expect(
      authorize(policy, host("user:mei.l", "release-agent"), "deploy__promote", { env: "staging" })
        .allowed,
    ).toBe(true);
  });

  it("reports every refused identity", () => {
    const d = authorize(
      policy,
      { client: "docs-bot", user: "user:omar.s", agent: "triage-agent" },
      "deploy__promote",
      {
        env: "staging",
      },
    );
    expect(d.violations).toEqual(["client:no-grant", "user:no-grant", "agent:no-grant"]);
  });

  it("an asserted identity in the arguments is just data", () => {
    const d = authorize(policy, { client: "docs-bot" }, "deploy__rollback", {
      env: "staging",
      runAs: "release-bot",
      client: "release-bot",
      user: "user:mei.l",
    });
    expect(d.violations).toEqual(["client:no-grant"]);
  });

  it("a principal may list several names", () => {
    const p: AuthorizationPolicy = {
      default: "deny",
      rules: [{ id: "bots", effect: "allow", principal: { client: ["a", "b"] }, tools: ["t__x"] }],
    };
    expect(authorize(p, { client: "b" }, "t__x", {}).allowed).toBe(true);
    expect(authorize(p, { client: "c" }, "t__x", {}).allowed).toBe(false);
  });
});

describe("tool patterns", () => {
  it.each([
    ["ci__*", "ci__rerun_job", true],
    ["ci__*", "ci__", true],
    ["ci__*", "ci_x", false],
    ["ci__*", "cix__rerun", false],
    ["*", "anything__at_all", true],
    ["ci__rerun_job", "ci__rerun_job", true],
    ["ci__rerun_job", "ci__rerun_jobs", false],
    ["ci__rerun_job", "CI__rerun_job", false],
    ["*__delete_*", "ci__delete_cache", false],
    ["ci*__x", "ci__x", false],
  ] as const)("%s vs %s → %s", (pattern, name, expected) => {
    expect(matchesToolPattern(pattern, name)).toBe(expected);
  });

  it("validates patterns: one trailing * at most", () => {
    expect(isValidToolPattern("ci__*")).toBe(true);
    expect(isValidToolPattern("*")).toBe(true);
    expect(isValidToolPattern("ci__x")).toBe(true);
    expect(isValidToolPattern("")).toBe(false);
    expect(isValidToolPattern("*__delete_*")).toBe(false);
    expect(isValidToolPattern("ci**")).toBe(false);
  });
});

describe("argument constraints", () => {
  const check = (c: ArgumentConstraint, v: unknown, present = true) =>
    satisfiesConstraint(c, present, v);

  it("equals: exact, no coercion, no folding, no normalisation", () => {
    expect(check({ equals: "staging" }, "staging")).toBe(true);
    expect(check({ equals: "staging" }, "Staging")).toBe(false);
    expect(check({ equals: "staging" }, "staging ")).toBe(false);
    expect(check({ equals: "staging" }, "\u0455taging")).toBe(false); // Cyrillic dze look-alike
    expect(check({ equals: "caf\u00e9" }, "cafe\u0301")).toBe(false); // NFC vs NFD
    expect(check({ equals: 1 }, "1")).toBe(false);
    expect(check({ equals: "1" }, 1)).toBe(false);
    expect(check({ equals: true }, "true")).toBe(false);
    expect(check({ equals: true }, true)).toBe(true);
    expect(check({ equals: 5 }, 5)).toBe(true);
    expect(check({ equals: "staging" }, ["staging"])).toBe(false);
    expect(check({ equals: "staging" }, { env: "staging" })).toBe(false);
    expect(check({ equals: "staging" }, null)).toBe(false);
  });

  it("in: exact membership", () => {
    expect(check({ in: ["staging", "qa"] }, "qa")).toBe(true);
    expect(check({ in: ["staging", "qa"] }, "prod")).toBe(false);
    expect(check({ in: [1, 2] }, "2")).toBe(false);
    expect(check({ in: ["staging"] }, ["staging"])).toBe(false);
  });

  it("max / min: JSON numbers only, inclusive bounds", () => {
    expect(check({ max: 60 }, 60)).toBe(true);
    expect(check({ max: 60 }, 61)).toBe(false);
    expect(check({ max: 60 }, "45")).toBe(false);
    expect(check({ max: 60 }, Number.NaN)).toBe(false);
    expect(check({ max: 60 }, Infinity)).toBe(false);
    expect(check({ max: 60 }, -Infinity)).toBe(false);
    expect(check({ min: 1 }, 0)).toBe(false);
    expect(check({ min: 1, max: 60 }, 30)).toBe(true);
    expect(check({ max: 60 }, [30])).toBe(false);
    expect(check({ max: 60 }, true)).toBe(false);
  });

  it("all listed constraints must hold", () => {
    expect(check({ in: [10, 20, 30], max: 25 }, 30)).toBe(false);
    expect(check({ in: [10, 20, 30], max: 25 }, 20)).toBe(true);
  });

  it("a missing constrained argument fails", () => {
    expect(check({ max: 60 }, undefined, false)).toBe(false);
    expect(
      authorize(policy, { client: "ci-bot" }, "ci__extend_timeout", { job: "x" }).violations,
    ).toEqual(["client:argument"]);
    // Own properties only: an inherited value does not count.
    expect(
      authorize(policy, { client: "ci-bot" }, "ci__extend_timeout", Object.create({ minutes: 5 }))
        .allowed,
    ).toBe(false);
  });

  it("non-object arguments count as no arguments", () => {
    expect(authorize(policy, { client: "ci-bot" }, "ci__extend_timeout", [5]).allowed).toBe(false);
    expect(authorize(policy, { client: "ci-bot" }, "ci__extend_timeout", null).allowed).toBe(false);
  });
});

describe("pathWithin", () => {
  const base = "/srv/checkouts/handbook";
  it.each([
    ["/srv/checkouts/handbook", true],
    ["/srv/checkouts/handbook/", true],
    ["/srv/checkouts/handbook/docs/onboarding.md", true],
    ["/srv/checkouts/handbook/./docs/a.md", true],
    ["/srv/checkouts/handbook//docs//a.md", true],
    ["/srv/checkouts/handbook/docs/../a.md", true],
    ["/srv/checkouts/handbook/../payments-svc/.env", false],
    ["/srv/checkouts/handbook/docs/../../payments-svc", false],
    ["/srv/checkouts/handbook-archive/a.md", false],
    ["/srv/checkouts/handbookx", false],
    ["/srv/checkouts", false],
    ["/srv/checkouts/handbook/%2e%2e/payments-svc", true], // left literal: a directory named "%2e%2e"
    ["/srv/checkouts/%2e%2e/handbook", false],
    ["srv/checkouts/handbook/a.md", false],
    ["./srv/checkouts/handbook/a.md", false],
    ["", false],
    ["/srv/checkouts/handbook/a\0.md", false],
    ["/../srv/checkouts/handbook/a.md", true], // `..` at the root stays at the root
    ["\\srv\\checkouts\\handbook", false],
  ] as const)("%j → %s", (value, expected) => {
    expect(isPathWithin(base, value)).toBe(expected);
  });

  it("rejects non-string values", () => {
    expect(isPathWithin(base, ["/srv/checkouts/handbook/a.md"])).toBe(false);
    expect(isPathWithin(base, 42)).toBe(false);
    expect(isPathWithin(base, null)).toBe(false);
    expect(isPathWithin(base, { path: base })).toBe(false);
  });

  it("a base of / admits every absolute path and a base with a trailing slash is the same base", () => {
    expect(isPathWithin("/", "/etc/passwd")).toBe(true);
    expect(isPathWithin("/", "etc/passwd")).toBe(false);
    expect(isPathWithin("/srv/checkouts/", "/srv/checkouts/x")).toBe(true);
    expect(isPathWithin("/srv/checkouts/", "/srv/checkouts-old/x")).toBe(false);
  });

  it("resolves . and .. without touching the filesystem", () => {
    expect(resolvePosixPath("/a/./b/../c//d/")).toBe("/a/c/d");
    expect(resolvePosixPath("/..")).toBe("/");
    expect(resolvePosixPath("a/b")).toBeUndefined();
  });
});

describe("mayList: tools/list filtering", () => {
  it("hides a tool no allow could match, or that an argument-free deny removes", () => {
    expect(mayList(policy, { client: "triage-bot" }, "ci__rerun_job")).toBe(true);
    expect(mayList(policy, { client: "triage-bot" }, "ci__delete_cache")).toBe(false);
    expect(mayList(policy, { client: "triage-bot" }, "repo__merge_pr")).toBe(false);
  });

  it("keeps a tool whose only allow is argument-constrained, or whose deny is", () => {
    expect(mayList(policy, { client: "release-bot" }, "deploy__promote")).toBe(true);
    expect(
      mayList(
        policy,
        { client: "agent-host", user: "user:mei.l", agent: "platform-agent" },
        "deploy__rollback",
      ),
    ).toBe(true);
  });

  it("applies the intersection", () => {
    expect(
      mayList(
        policy,
        { client: "agent-host", user: "user:mei.l", agent: "triage-agent" },
        "repo__merge_pr",
      ),
    ).toBe(false);
    expect(mayList(policy, {}, "ci__rerun_job")).toBe(false);
  });

  it("under default allow, only argument-free denies hide a tool", () => {
    const open: AuthorizationPolicy = { ...policy, default: "allow" };
    expect(mayList(open, { client: "docs-bot" }, "issues__label")).toBe(true);
    expect(mayList(open, { client: "triage-bot" }, "ci__delete_cache")).toBe(false);
  });
});
