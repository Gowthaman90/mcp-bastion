import { afterEach, describe, expect, it, vi } from "vitest";

import { OtlpSink, toOtlpLogs } from "../src/audit/sinks/otlp.js";
import type { AuditEvent } from "../src/audit/index.js";

const event = (over: Partial<AuditEvent> = {}): AuditEvent => ({
  schemaVersion: 1,
  seq: 1,
  ts: "2026-07-08T00:00:00.000Z",
  traceId: "trace-1",
  server: "github",
  tool: "create_issue",
  namespacedName: "github__create_issue",
  decision: "allowed",
  outcome: "ok",
  durationMs: 12,
  frameworks: { nistAiRmf: ["MEASURE"], owaspLlm: [] },
  ...over,
});

interface OtlpPayload {
  resourceLogs: Array<{
    resource: { attributes: Array<{ key: string }> };
    scopeLogs: Array<{
      logRecords: Array<{
        severityText: string;
        timeUnixNano: string;
        attributes: Array<{ key: string }>;
      }>;
    }>;
  }>;
}

describe("toOtlpLogs", () => {
  it("maps events to OTLP resourceLogs/scopeLogs/logRecords", () => {
    const payload = toOtlpLogs([event()]) as OtlpPayload;
    const resourceLog = payload.resourceLogs[0];
    expect(resourceLog.resource.attributes[0].key).toBe("service.name");

    const record = resourceLog.scopeLogs[0].logRecords[0];
    expect(record.severityText).toBe("INFO");
    expect(typeof record.timeUnixNano).toBe("string");
    expect(record.timeUnixNano.length).toBeGreaterThanOrEqual(19); // nanoseconds

    const keys = record.attributes.map((a) => a.key);
    expect(keys).toEqual(
      expect.arrayContaining([
        "mcp.server",
        "mcp.tool",
        "mcp.decision",
        "duration_ms",
        "compliance.nist_ai_rmf",
      ]),
    );
  });

  it("carries the caller, shadow-mode verdict, findings and chain fields", () => {
    const full = event({
      client: "ci-agent",
      wouldBlock: "blocked_rug_pull",
      findings: [{ rule: "tool-definition-changed", severity: "high", kind: "deterministic" }],
      authorization: {
        effect: "allow",
        rule: "ci-tickets",
        byDefault: false,
        client: "ci-agent",
        identities: ["client"],
        violations: [],
      },
      runId: "run-1",
      prevHash: "0".repeat(64),
      hash: "a".repeat(64),
    });
    const record = (toOtlpLogs([full]) as OtlpPayload).resourceLogs[0].scopeLogs[0].logRecords[0];
    const attrs = new Map(
      (record.attributes as Array<{ key: string; value: Record<string, unknown> }>).map((a) => [
        a.key,
        a.value,
      ]),
    );
    expect(attrs.get("mcp.client")).toEqual({ stringValue: "ci-agent" });
    expect(attrs.get("mcp.would_block")).toEqual({ stringValue: "blocked_rug_pull" });
    expect(attrs.get("mcp.findings")).toEqual({
      arrayValue: { values: [{ stringValue: "tool-definition-changed" }] },
    });
    expect(attrs.get("mcp.authorization.rule")).toEqual({ stringValue: "ci-tickets" });
    expect(attrs.get("audit.seq")).toEqual({ intValue: 1 });
    expect(attrs.get("audit.hash")).toEqual({ stringValue: "a".repeat(64) });
    // The full event rides along, so a collector export can be chain-verified.
    expect(JSON.parse((attrs.get("audit.event") as { stringValue: string }).stringValue)).toEqual(
      full,
    );
    // A check that fired in shadow mode is a WARN even though the call ran.
    expect(record.severityText).toBe("WARN");
  });

  it("marks non-ok outcomes as WARN", () => {
    const payload = toOtlpLogs([
      event({ outcome: "blocked", decision: "blocked_rug_pull" }),
    ]) as OtlpPayload;
    expect(payload.resourceLogs[0].scopeLogs[0].logRecords[0].severityText).toBe("WARN");
  });
});

describe("OtlpSink", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("POSTs a batch to <endpoint>/v1/logs and awaits it on flush", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const sink = new OtlpSink({
      endpoint: "http://collector:4318/",
      batchSize: 10,
      timeoutMs: 1000,
    });
    sink.write(event());
    sink.write(event({ seq: 2 }));
    await sink.flush();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const url = fetchMock.mock.calls[0][0] as string;
    const init = fetchMock.mock.calls[0][1] as { method: string; body: string };
    expect(url).toBe("http://collector:4318/v1/logs");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body) as OtlpPayload;
    expect(body.resourceLogs[0].scopeLogs[0].logRecords).toHaveLength(2);
  });

  it("auto-dispatches when the batch size is reached", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const sink = new OtlpSink({ endpoint: "http://c:4318", batchSize: 2, timeoutMs: 1000 });
    sink.write(event());
    sink.write(event()); // reaches batchSize -> dispatch
    await sink.close();

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("sends a partial batch after flushIntervalMs, so a quiet gateway's events don't wait", async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn().mockResolvedValue({ ok: true });
      vi.stubGlobal("fetch", fetchMock);

      const sink = new OtlpSink({
        endpoint: "http://c:4318",
        batchSize: 50,
        flushIntervalMs: 1000,
        timeoutMs: 1000,
      });
      sink.write(event());
      await vi.advanceTimersByTimeAsync(999);
      expect(fetchMock).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(sink.health().queued).toBe(0);

      // Nothing queued: the timer sends nothing.
      await vi.advanceTimersByTimeAsync(5000);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      await sink.close();
    } finally {
      vi.useRealTimers();
    }
  });

  it("sends only full batches when flushIntervalMs is 0", async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn().mockResolvedValue({ ok: true });
      vi.stubGlobal("fetch", fetchMock);

      const sink = new OtlpSink({
        endpoint: "http://c:4318",
        batchSize: 50,
        flushIntervalMs: 0,
        timeoutMs: 1000,
      });
      sink.write(event());
      await vi.advanceTimersByTimeAsync(60_000);
      expect(fetchMock).not.toHaveBeenCalled();
      await sink.close();
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
