import { describe, expect, it } from "vitest";

import { SecurityConfigSchema } from "../src/config/schema.js";
import { checkConfigDrift, SecurityEngine } from "../src/security/index.js";

describe("config-drift detection", () => {
  it("flags a TLS downgrade (required → optional)", () => {
    const f = checkConfigDrift({ tls: "required" }, { tls: "optional" });
    expect(f.map((x) => x.rule)).toContain("config-drift");
  });

  it("flags a host allowlist widened with a wildcard", () => {
    const f = checkConfigDrift(
      { allowedHosts: ["api.internal"] },
      { allowedHosts: ["api.internal", "*"] },
    );
    expect(f.length).toBeGreaterThan(0);
  });

  it("flags a protective flag being disabled (true → false)", () => {
    const f = checkConfigDrift({ requireAuth: true }, { requireAuth: false });
    expect(f.map((x) => x.rule)).toContain("config-drift");
  });

  it("flags both a TLS downgrade and an allowlist widening together", () => {
    const f = checkConfigDrift(
      { tls: "required", allowedHosts: ["api.internal"] },
      { tls: "optional", allowedHosts: ["api.internal", "*"] },
    );
    expect(f.length).toBe(2);
  });

  it("does NOT flag an unchanged config", () => {
    const cfg = { tls: "required", allowedHosts: ["api.internal"] };
    expect(checkConfigDrift(cfg, { ...cfg, allowedHosts: [...cfg.allowedHosts] })).toHaveLength(0);
  });

  it("does NOT flag a strengthened config (optional → required)", () => {
    expect(checkConfigDrift({ tls: "optional" }, { tls: "required" })).toHaveLength(0);
  });

  it("does NOT flag adding a specific (non-wildcard) allowlist host", () => {
    const f = checkConfigDrift(
      { allowedHosts: ["api.internal"] },
      { allowedHosts: ["api.internal", "api2.internal"] },
    );
    expect(f).toHaveLength(0);
  });

  it("does NOT flag enabling a protection (false → true)", () => {
    expect(checkConfigDrift({ requireAuth: false }, { requireAuth: true })).toHaveLength(0);
  });
});

describe("SecurityEngine.observeConfig (trust-on-first-use drift)", () => {
  const engine = () => new SecurityEngine(SecurityConfigSchema.parse({}), "__");

  it("pins the first snapshot and reports no drift for it", () => {
    const e = engine();
    e.observeConfig("srv", { tls: "required", allowedHosts: ["api.internal"] });
    expect(e.configDriftStatus()).toHaveLength(0);
  });

  it("flags a later snapshot that weakens the pinned baseline", () => {
    const e = engine();
    e.observeConfig("srv", { tls: "required", allowedHosts: ["api.internal"] });
    e.observeConfig("srv", { tls: "optional", allowedHosts: ["api.internal", "*"] });
    const status = e.configDriftStatus();
    expect(status).toHaveLength(1);
    expect(status[0].server).toBe("srv");
    expect(status[0].findings.length).toBe(2);
  });
});
