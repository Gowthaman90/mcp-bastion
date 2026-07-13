import { describe, expect, it } from "vitest";

import { checkRequestOrigin, checkTransportSecurity } from "../src/security/index.js";

describe("transport security", () => {
  describe("checkTransportSecurity", () => {
    it("flags plaintext http to a remote host", () => {
      const f = checkTransportSecurity("http://mcp.vendor.example/rpc");
      expect(f.map((x) => x.rule)).toContain("insecure-transport");
    });

    it("allows https to a remote host", () => {
      expect(checkTransportSecurity("https://mcp.vendor.example/rpc")).toHaveLength(0);
    });

    it("allows plaintext http to loopback (local dev)", () => {
      expect(checkTransportSecurity("http://127.0.0.1:7000/rpc")).toHaveLength(0);
      expect(checkTransportSecurity("http://localhost:7000/rpc")).toHaveLength(0);
    });
  });

  describe("checkRequestOrigin", () => {
    it("flags a foreign origin targeting a loopback server (DNS rebinding)", () => {
      const f = checkRequestOrigin("127.0.0.1:7000", "https://attacker.example");
      expect(f.map((x) => x.rule)).toContain("cross-origin-request");
    });

    it("allows a same-local origin", () => {
      expect(checkRequestOrigin("127.0.0.1:7000", "http://localhost:7000")).toHaveLength(0);
    });

    it("ignores requests with no Origin header (non-browser clients)", () => {
      expect(checkRequestOrigin("127.0.0.1:7000", undefined)).toHaveLength(0);
    });

    it("does not constrain a remote (non-loopback) listener", () => {
      expect(checkRequestOrigin("mcp.example.com", "https://attacker.example")).toHaveLength(0);
    });
  });
});
