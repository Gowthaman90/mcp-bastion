import { describe, expect, it } from "vitest";

import {
  checkHeaderBodyCoherence,
  decodeHeaderValue,
  requiresHeaderValidation,
} from "../src/security/index.js";

const REV = "2026-07-28";

/** Base64 sentinel form from streamable-http, Value Encoding. */
const sentinel = (s: string) => `=?base64?${Buffer.from(s, "utf8").toString("base64")}?=`;

/** A conforming 2026-07-28 tools/call, used as the benign baseline throughout. */
function conformingCall() {
  return {
    headers: {
      "mcp-protocol-version": REV,
      "mcp-method": "tools/call",
      "mcp-name": "get_weather",
    },
    body: {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "get_weather",
        arguments: { city: "Seattle" },
        _meta: { "io.modelcontextprotocol/protocolVersion": REV },
      },
    },
  };
}

describe("header/body coherence (2026-07-28)", () => {
  describe("no false positives", () => {
    it("passes a fully conforming request", () => {
      const { headers, body } = conformingCall();
      expect(checkHeaderBodyCoherence(headers, body)).toHaveLength(0);
    });

    it("passes a legacy request that sends no mirrored headers at all", () => {
      // Pre-2026-07-28 clients are never required to send these; flagging them would be a false alarm.
      const findings = checkHeaderBodyCoherence(
        {},
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_weather" } },
      );
      expect(findings).toHaveLength(0);
    });

    it("ignores a body that is not a JSON-RPC request", () => {
      expect(checkHeaderBodyCoherence({ "mcp-method": "tools/call" }, null)).toHaveLength(0);
      expect(checkHeaderBodyCoherence({ "mcp-method": "tools/call" }, "nonsense")).toHaveLength(0);
    });

    it("does not compare Mcp-Name on a method that does not mirror one", () => {
      const findings = checkHeaderBodyCoherence(
        { "mcp-protocol-version": REV, "mcp-method": "tools/list", "mcp-name": "anything" },
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
          params: { _meta: { "io.modelcontextprotocol/protocolVersion": REV } },
        },
      );
      expect(findings).toHaveLength(0);
    });

    it("matches header names case-insensitively, as RFC 9110 requires", () => {
      const { body } = conformingCall();
      const findings = checkHeaderBodyCoherence(
        { "MCP-Protocol-Version": REV, "Mcp-Method": "tools/call", "Mcp-Name": "get_weather" },
        body,
      );
      // Node lower-cases incoming header names; a bag that did not is simply not matched, and
      // absent headers on a declared 2026-07-28 request are reported as missing, not as a mismatch.
      expect(findings.every((f) => f.rule !== "header-body-mismatch")).toBe(true);
    });

    it("accepts a repeated header whose values agree", () => {
      const { body } = conformingCall();
      const findings = checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "tools/call",
          "mcp-name": ["get_weather", "get_weather"],
        },
        body,
      );
      expect(findings).toHaveLength(0);
    });
  });

  describe("Mcp-Name mismatch", () => {
    it("flags a routing header naming a different tool than the body calls", () => {
      const findings = checkHeaderBodyCoherence(
        { "mcp-protocol-version": REV, "mcp-method": "tools/call", "mcp-name": "read_calendar" },
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "transfer_funds",
            arguments: { amount: 5000 },
            _meta: { "io.modelcontextprotocol/protocolVersion": REV },
          },
        },
      );
      expect(findings.map((f) => f.rule)).toContain("header-body-mismatch");
      expect(findings.find((f) => f.rule === "header-body-mismatch")?.severity).toBe("high");
    });

    it("still catches the mismatch when hidden behind the base64 sentinel", () => {
      const findings = checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "tools/call",
          "mcp-name": sentinel("read_calendar"),
        },
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "transfer_funds",
            arguments: { amount: 5000 },
            _meta: { "io.modelcontextprotocol/protocolVersion": REV },
          },
        },
      );
      const mismatch = findings.find((f) => f.rule === "header-body-mismatch");
      expect(mismatch).toBeDefined();
      expect(mismatch?.excerpt).toContain("base64-sentinel");
    });

    it("accepts a sentinel-encoded value that decodes to the body value", () => {
      const findings = checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "tools/call",
          "mcp-name": sentinel("get_weather"),
        },
        conformingCall().body,
      );
      expect(findings).toHaveLength(0);
    });

    it("compares Mcp-Name against params.uri on resources/read", () => {
      const findings = checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "resources/read",
          "mcp-name": "file:///public/readme.md",
        },
        {
          jsonrpc: "2.0",
          id: 1,
          method: "resources/read",
          params: {
            uri: "file:///home/alice/.env",
            _meta: { "io.modelcontextprotocol/protocolVersion": REV },
          },
        },
      );
      expect(findings.map((f) => f.rule)).toContain("header-body-mismatch");
    });

    it("compares Mcp-Name against params.taskId on task methods", () => {
      const findings = checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "tasks/update",
          "mcp-name": "786512e2-9e0d-44bd-8f29-789f320fe840",
        },
        {
          jsonrpc: "2.0",
          id: 7,
          method: "tasks/update",
          params: {
            taskId: "c1f0a3d4-77b2-4e19-9a30-5b8e2f61c904",
            _meta: { "io.modelcontextprotocol/protocolVersion": REV },
          },
        },
      );
      expect(findings.map((f) => f.rule)).toContain("header-body-mismatch");
    });
  });

  describe("method and version", () => {
    it("flags Mcp-Method disagreeing with the body method", () => {
      const findings = checkHeaderBodyCoherence(
        { "mcp-protocol-version": REV, "mcp-method": "tools/list", "mcp-name": "get_weather" },
        conformingCall().body,
      );
      expect(findings.map((f) => f.rule)).toContain("header-body-mismatch");
    });

    it("flags a protocol version header disagreeing with body _meta", () => {
      const { headers, body } = conformingCall();
      const findings = checkHeaderBodyCoherence(
        { ...headers, "mcp-protocol-version": "2025-11-25" },
        body,
      );
      expect(findings.map((f) => f.rule)).toContain("header-body-mismatch");
    });

    it("flags routing headers carried under a version that does not mandate validation", () => {
      const findings = checkHeaderBodyCoherence(
        { "mcp-method": "tools/call", "mcp-name": "read_calendar" },
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "transfer_funds" } },
      );
      expect(findings.map((f) => f.rule)).toContain("unvalidated-header-routing");
    });

    it("reports a required header missing only when the revision requires it", () => {
      const withRevision = checkHeaderBodyCoherence(
        { "mcp-protocol-version": REV },
        conformingCall().body,
      );
      expect(withRevision.map((f) => f.rule)).toContain("header-missing-required");

      const legacy = checkHeaderBodyCoherence(
        {},
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_weather" } },
      );
      expect(legacy.map((f) => f.rule)).not.toContain("header-missing-required");
    });
  });

  describe("malformed headers", () => {
    it("flags a header repeated with conflicting values", () => {
      const findings = checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "tools/call",
          "mcp-name": ["get_weather", "transfer_funds"],
        },
        conformingCall().body,
      );
      expect(findings.map((f) => f.rule)).toContain("header-duplicate-conflict");
    });

    it("flags control characters in a header value", () => {
      const findings = checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "tools/call",
          "mcp-name": "get_weather\r\nX-Injected: 1",
        },
        conformingCall().body,
      );
      expect(findings.map((f) => f.rule)).toContain("header-invalid-value");
    });

    it("allows a horizontal tab, which RFC 9110 permits in a field value", () => {
      const findings = checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "tools/call",
          "mcp-name": "get_weather",
          "mcp-param-note": "a\tb",
        },
        conformingCall().body,
      );
      expect(findings.map((f) => f.rule)).not.toContain("header-invalid-value");
    });
  });

  describe("Mcp-Param-* against x-mcp-header annotations", () => {
    const schema = {
      type: "object",
      properties: {
        region: { type: "string", "x-mcp-header": "Region" },
        query: { type: "string" },
      },
      required: ["region", "query"],
    };

    function sqlCall(headerRegion: string, argRegion: string) {
      return checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "tools/call",
          "mcp-name": "execute_sql",
          "mcp-param-region": headerRegion,
        },
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "execute_sql",
            arguments: { region: argRegion, query: "SELECT 1" },
            _meta: { "io.modelcontextprotocol/protocolVersion": REV },
          },
        },
        { inputSchema: schema },
      );
    }

    it("passes when the mirrored parameter matches the argument", () => {
      expect(sqlCall("us-west1", "us-west1")).toHaveLength(0);
    });

    it("flags a mirrored parameter that disagrees with the argument", () => {
      const findings = sqlCall("us-west1", "eu-central1");
      expect(findings.map((f) => f.rule)).toContain("header-body-mismatch");
    });

    it("flags a Mcp-Param header with no matching annotation in the schema", () => {
      const findings = checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "tools/call",
          "mcp-name": "execute_sql",
          "mcp-param-tenant": "acme",
        },
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "execute_sql",
            arguments: { region: "us-west1", query: "SELECT 1" },
            _meta: { "io.modelcontextprotocol/protocolVersion": REV },
          },
        },
        { inputSchema: schema },
      );
      expect(findings.map((f) => f.rule)).toContain("header-unknown-param");
    });

    it("does not judge Mcp-Param headers without a schema to judge them against", () => {
      const findings = checkHeaderBodyCoherence(
        {
          "mcp-protocol-version": REV,
          "mcp-method": "tools/call",
          "mcp-name": "get_weather",
          "mcp-param-region": "us-west1",
        },
        conformingCall().body,
      );
      expect(findings).toHaveLength(0);
    });
  });
});

describe("helpers", () => {
  it("decodes the base64 sentinel and passes other values through", () => {
    expect(decodeHeaderValue(sentinel("Hello, 世界"))).toBe("Hello, 世界");
    expect(decodeHeaderValue("us-west1")).toBe("us-west1");
    expect(decodeHeaderValue("=?base64?not-valid-base64!?=")).toBe("=?base64?not-valid-base64!?=");
  });

  it("treats revisions as ISO dates, so ordering is chronological", () => {
    expect(requiresHeaderValidation("2026-07-28")).toBe(true);
    expect(requiresHeaderValidation("2027-01-01")).toBe(true);
    expect(requiresHeaderValidation("2025-11-25")).toBe(false);
    expect(requiresHeaderValidation(undefined)).toBe(false);
  });
});
