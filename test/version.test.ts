import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { BASTION_VERSION } from "../src/core/constants.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

describe("version", () => {
  it("BASTION_VERSION matches package.json (prevents version drift in what the CLI reports)", () => {
    expect(BASTION_VERSION).toBe(pkg.version);
  });
});
