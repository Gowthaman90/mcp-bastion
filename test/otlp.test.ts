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
});
