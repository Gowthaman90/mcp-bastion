import { describe, expect, it } from "vitest";

import { SecurityConfigSchema } from "../src/config/schema.js";
import {
  checkServerIdentity,
  hashServerIdentity,
  SecurityEngine,
  type ServerIdentity,
} from "../src/security/index.js";

describe("checkServerIdentity (verification)", () => {
  it("flags a claimed identity with no verified binding", () => {
    const f = checkServerIdentity({
      endpoint: "https://mcp.attacker.example",
      name: "acme/payments",
    });
    expect(f.map((x) => x.rule)).toContain("unverified-server-identity");
  });

  it("flags a claimed identity whose proof is not verified", () => {
    const f = checkServerIdentity({ name: "acme/payments", identityProof: { verified: false } });
    expect(f.length).toBeGreaterThan(0);
  });

  it("does NOT flag an identity with a verified binding", () => {
    const f = checkServerIdentity({
      endpoint: "https://mcp.acme.example",
      name: "acme/payments",
      identityProof: { wellKnown: "https://acme.example/.well-known/mcp", verified: true },
    });
    expect(f).toHaveLength(0);
  });

  it("does NOT flag when no identity is claimed", () => {
    expect(checkServerIdentity({ endpoint: "https://mcp.acme.example" })).toHaveLength(0);
  });
});

describe("hashServerIdentity (TOFU fingerprint)", () => {
  const base: ServerIdentity = {
    endpoint: "https://mcp.acme.example",
    name: "acme/payments",
    tlsFingerprint: "sha256:AAA",
  };

  it("changes when the endpoint changes", () => {
    expect(hashServerIdentity(base)).not.toBe(
      hashServerIdentity({ ...base, endpoint: "https://mcp.attacker.example" }),
    );
  });

  it("changes when the TLS fingerprint changes", () => {
    expect(hashServerIdentity(base)).not.toBe(
      hashServerIdentity({ ...base, tlsFingerprint: "sha256:BBB" }),
    );
  });

  it("is stable across a benign version bump", () => {
    expect(hashServerIdentity({ ...base, serverVersion: "1.2.0" })).toBe(
      hashServerIdentity({ ...base, serverVersion: "1.3.0" }),
    );
  });
});

describe("SecurityEngine.observeIdentity (trust-on-first-use)", () => {
  const engine = () => new SecurityEngine(SecurityConfigSchema.parse({}), "__");
  // A verified identity, so only the TOFU change-detection dimension is under test here.
  const acme: ServerIdentity = {
    endpoint: "https://mcp.acme.example",
    name: "acme/payments",
    tlsFingerprint: "sha256:AAA",
    identityProof: { wellKnown: "https://acme.example/.well-known/mcp", verified: true },
  };

  it("pins the first identity and reports nothing for a benign redeploy", () => {
    const e = engine();
    e.observeIdentity("pay", { ...acme, serverVersion: "1.2.0" });
    e.observeIdentity("pay", { ...acme, serverVersion: "1.3.0" });
    expect(e.identityStatus()).toHaveLength(0);
  });

  it("flags a changed identity (endpoint swap) after pinning", () => {
    const e = engine();
    e.observeIdentity("pay", acme);
    e.observeIdentity("pay", { ...acme, endpoint: "https://mcp.attacker.example" });
    const status = e.identityStatus();
    expect(status).toHaveLength(1);
    expect(status[0].findings.map((f) => f.rule)).toContain("server-identity-changed");
  });
});
