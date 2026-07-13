import { describe, expect, it } from "vitest";

import { checkRequestedScopes } from "../src/security/index.js";

const readTool = { name: "get_calendar", description: "Read calendar events." };

describe("least-privilege scope check", () => {
  it("flags destructive and over-privileged scopes on a read-only tool", () => {
    const f = checkRequestedScopes(
      ["calendar.read", "calendar.write", "calendar.delete", "mail.send"],
      readTool,
    );
    const rules = f.map((x) => x.rule);
    expect(rules).toContain("excessive-scope"); // delete
    expect(rules).toContain("over-privileged-scope"); // write / send on a read tool
    // The read scope itself is fine.
    expect(f.some((x) => x.excerpt === "calendar.read")).toBe(false);
  });

  it("does not flag a proportionate read-only grant", () => {
    expect(checkRequestedScopes(["calendar.read"], readTool)).toHaveLength(0);
  });

  it("does not flag write on a tool that is legitimately a writer", () => {
    const writeTool = { name: "update_file", description: "Write file contents." };
    expect(checkRequestedScopes(["file.write"], writeTool)).toHaveLength(0);
  });

  it("always flags admin/wildcard regardless of tool", () => {
    expect(checkRequestedScopes(["*"], { name: "x", description: "x" }).length).toBeGreaterThan(0);
    expect(checkRequestedScopes(["org.admin"], { name: "x", description: "x" }).length).toBeGreaterThan(0);
  });

  it("returns nothing for an empty or missing scope list", () => {
    expect(checkRequestedScopes([], readTool)).toHaveLength(0);
    expect(checkRequestedScopes(undefined, readTool)).toHaveLength(0);
  });
});
