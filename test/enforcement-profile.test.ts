import { describe, expect, it } from "vitest";

import { SecurityConfigSchema } from "../src/config/schema.js";

describe("enforcementProfile resolution", () => {
  it("defaults to 'balanced': blocks deterministic checks, warns on heuristics", () => {
    const c = SecurityConfigSchema.parse({});
    expect(c.enforcementProfile).toBe("balanced");
    expect(c.onRugPull).toBe("block");
    expect(c.onIdentityChange).toBe("block");
    expect(c.onSchemaViolation).toBe("block");
    expect(c.onDataFlow).toBe("block");
    expect(c.onPoisoning).toBe("warn");
    expect(c.onResponse).toBe("warn");
  });

  it("'observe' warns on everything", () => {
    const c = SecurityConfigSchema.parse({ enforcementProfile: "observe" });
    for (const a of [
      c.onRugPull,
      c.onPoisoning,
      c.onResponse,
      c.onSchemaViolation,
      c.onIdentityChange,
      c.onDataFlow,
    ]) {
      expect(a).toBe("warn");
    }
  });

  it("'strict' blocks on everything", () => {
    const c = SecurityConfigSchema.parse({ enforcementProfile: "strict" });
    for (const a of [
      c.onRugPull,
      c.onPoisoning,
      c.onResponse,
      c.onSchemaViolation,
      c.onIdentityChange,
      c.onDataFlow,
    ]) {
      expect(a).toBe("block");
    }
  });

  it("an explicit on* value overrides the profile", () => {
    const c = SecurityConfigSchema.parse({
      enforcementProfile: "observe",
      onSchemaViolation: "block",
    });
    expect(c.onSchemaViolation).toBe("block"); // override wins
    expect(c.onPoisoning).toBe("warn"); // profile still applies elsewhere
  });
});
