/** Start-up warnings: trusting unverified delegate claims, and unlinkable subject pseudonyms. */
import { describe, expect, it } from "vitest";

import { BastionConfigSchema, startupWarnings } from "../src/config/index.js";

const KEY = "k".repeat(24);

function config(
  over: { authorization?: object; delegation?: object; audit?: object; verify?: string } = {},
) {
  return BastionConfigSchema.parse({
    servers: {
      files: {
        transport: "http",
        url: "https://files.internal/mcp",
        forwardHeaders: { "x-delegate": "x-delegate-files" },
        delegation: {
          audience: "files",
          ...(over.verify === "signature"
            ? {
                verify: "signature",
                issuer: "https://idp.example",
                algorithms: ["ES256"],
                jwksUrl: "https://idp.example/jwks.json",
              }
            : {}),
        },
      },
      plain: { command: "node", args: ["server.js"] },
    },
    listen: { mode: "http" },
    authorization: { enabled: true, trustStructuralClaims: true, ...over.authorization },
    ...(over.delegation ? { delegation: over.delegation } : {}),
    ...(over.audit ? { audit: over.audit } : {}),
  });
}

const messages = (ws: { message: string }[]) => ws.map((w) => w.message).join("\n");

describe("startupWarnings: trustStructuralClaims", () => {
  it("names the structural upstreams and says what the setting trusts", () => {
    const [w] = startupWarnings(config({ delegation: { subjectKey: KEY } }), {});
    expect(w.level).toBe("warn");
    expect(w.message).toMatch(
      /^authorization\.trustStructuralClaims is on: for files the user and agent/,
    );
    expect(w.message).toMatch(/signature Bastion does not check/);
    expect(w.message).toMatch(/verify: "signature"/);
    expect(w.message).not.toMatch(/plain/);
  });

  it("is a note, not a warning, when no upstream is structural", () => {
    const ws = startupWarnings(
      config({ verify: "signature", delegation: { subjectKey: KEY } }),
      {},
    );
    expect(ws).toEqual([{ level: "info", message: expect.stringMatching(/has no effect/) }]);
  });

  it("says nothing while the setting is off or authorization is disabled", () => {
    const off = { delegation: { subjectKey: KEY } };
    expect(
      startupWarnings(config({ ...off, authorization: { trustStructuralClaims: false } }), {}),
    ).toEqual([]);
    expect(startupWarnings(config({ ...off, authorization: { enabled: false } }), {})).toEqual([]);
  });
});

describe("startupWarnings: subject pseudonym key", () => {
  const off = { authorization: { trustStructuralClaims: false } };

  it("warns when delegation subjects are hashed with a per-process random key", () => {
    const ws = startupWarnings(config(off), {});
    expect(ws).toHaveLength(1);
    expect(ws[0].level).toBe("warn");
    expect(ws[0].message).toMatch(/do not link across restarts or replicas/);
  });

  it("is silent once any of the four key sources is set, and never prints a key", () => {
    expect(startupWarnings(config({ ...off, delegation: { subjectKey: KEY } }), {})).toEqual([]);
    expect(startupWarnings(config({ ...off, audit: { integrityKey: KEY } }), {})).toEqual([]);
    expect(startupWarnings(config(off), { MCP_BASTION_SUBJECT_KEY: KEY })).toEqual([]);
    expect(startupWarnings(config(off), { MCP_BASTION_AUDIT_KEY: KEY })).toEqual([]);
    expect(
      messages(startupWarnings(config({ delegation: { subjectKey: KEY } }), {})),
    ).not.toContain(KEY);
  });

  it("is silent when subjects are recorded plain, or no upstream has delegation", () => {
    expect(startupWarnings(config({ ...off, delegation: { recordSubject: "plain" } }), {})).toEqual(
      [],
    );
    const none = BastionConfigSchema.parse({ servers: { plain: { command: "node" } } });
    expect(startupWarnings(none, {})).toEqual([]);
  });
});
