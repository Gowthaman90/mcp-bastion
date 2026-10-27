import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuditEngine, WebhookSink } from "../src/audit/index.js";
import { backoffMs, resolveSinkHeaders } from "../src/audit/sinks/index.js";
import type { AuditEvent, AuditSink, SinkHealth } from "../src/audit/index.js";
import { AuditConfigSchema, BastionConfigSchema } from "../src/config/index.js";
import type { ToolCallContext } from "../src/security/index.js";

const ev = (seq: number) => ({ schemaVersion: 1, seq, tool: "t" }) as AuditEvent;
const sinkCfg = (sink: Record<string, unknown>) =>
  BastionConfigSchema.safeParse({ servers: {}, audit: { enabled: true, sinks: [sink] } });

describe("remote sinks require HTTPS", () => {
  it.each([
    ["webhook", "url", "http://siem.corp.example/ingest", false],
    ["webhook", "url", "https://siem.corp.example/ingest", true],
    ["webhook", "url", "http://127.0.0.1:8080/ingest", true],
    ["webhook", "url", "http://localhost:8080/ingest", true],
    ["otlp", "endpoint", "http://collector.corp.example:4318", false],
    ["otlp", "endpoint", "https://collector.corp.example:4318", true],
    ["otlp", "endpoint", "http://[::1]:4318", true],
  ])("%s %s %s → valid %s", (type, field, target, ok) => {
    expect(sinkCfg({ type, [field]: target }).success).toBe(ok);
  });

  it("accepts plain HTTP to a remote host only with allowInsecureTransport", () => {
    const r = sinkCfg({
      type: "webhook",
      url: "http://siem.corp.example/ingest",
      allowInsecureTransport: true,
    });
    expect(r.success).toBe(true);
  });

  it("names the field and the opt-out in the error", () => {
    const r = sinkCfg({ type: "webhook", url: "http://siem.corp.example/ingest" });
    expect(r.success).toBe(false);
    expect(JSON.stringify(r.error?.issues)).toMatch(/HTTPS.*allowInsecureTransport/);
  });
});

describe("sink headers from the environment", () => {
  it("merges static headers with values read from env vars", () => {
    expect(
      resolveSinkHeaders(
        "webhook:x",
        { "x-tenant": "t1" },
        { authorization: "AUDIT_TOKEN" },
        { AUDIT_TOKEN: "Bearer s3cret" },
      ),
    ).toEqual({ "x-tenant": "t1", authorization: "Bearer s3cret" });
  });

  it("refuses to start when a header's env var is missing or empty", () => {
    expect(() => resolveSinkHeaders("webhook:x", undefined, { authorization: "NOPE" }, {})).toThrow(
      /NOPE/,
    );
    expect(() =>
      resolveSinkHeaders("webhook:x", undefined, { authorization: "E" }, { E: "" }),
    ).toThrow(/E/);
  });
});

describe("HTTP sink delivery (bounded queue, retry, health)", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("keeps a failed batch, retries with backoff, then delivers it", async () => {
    const fetchMock = vi
      .fn()
      .mockRejectedValueOnce(new Error("ECONNREFUSED"))
      .mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);
    const sink = new WebhookSink({
      url: "https://siem.example/in",
      batchSize: 2,
      timeoutMs: 1000,
      maxQueue: 100,
    });

    sink.write(ev(1));
    sink.write(ev(2)); // batch full → first POST fails
    await vi.advanceTimersByTimeAsync(0);
    expect(sink.health()).toMatchObject({
      healthy: false,
      delivered: 0,
      queued: 2,
      failedAttempts: 1,
      lastError: "ECONNREFUSED",
    });

    await vi.advanceTimersByTimeAsync(30_000); // retry fires within the backoff ceiling
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(sink.health()).toMatchObject({ healthy: true, delivered: 2, queued: 0, dropped: 0 });
    const body = JSON.parse((fetchMock.mock.calls[1][1] as { body: string }).body);
    expect(body.events.map((e: AuditEvent) => e.seq)).toEqual([1, 2]); // same events, same order
  });

  it("drops the oldest events beyond maxQueue and counts them", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));
    const sink = new WebhookSink({
      url: "https://siem.example/in",
      batchSize: 1000,
      timeoutMs: 1000,
      maxQueue: 3,
    });
    for (let i = 1; i <= 5; i++) sink.write(ev(i));
    expect(sink.health()).toMatchObject({ queued: 3, dropped: 2 });
  });

  it("flush returns promptly while the receiver is down; close counts what is left as dropped", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("down")));
    const sink = new WebhookSink({
      url: "https://siem.example/in",
      batchSize: 10,
      timeoutMs: 1000,
      maxQueue: 100,
    });
    sink.write(ev(1));
    sink.write(ev(2));
    await sink.flush();
    expect(sink.health()).toMatchObject({ healthy: false, queued: 2 });
    await sink.close();
    expect(sink.health()).toMatchObject({ queued: 0, dropped: 2 });
  });

  it("sends resolved headers with every request", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);
    const sink = new WebhookSink({
      url: "https://siem.example/in",
      headers: { authorization: "Bearer t" },
      batchSize: 1,
      timeoutMs: 1000,
    });
    sink.write(ev(1));
    await sink.flush();
    expect(
      (fetchMock.mock.calls[0][1] as { headers: Record<string, string> }).headers.authorization,
    ).toBe("Bearer t");
  });

  it("backoff grows exponentially with jitter and is capped at 30 s", () => {
    expect(backoffMs(1, () => 0)).toBe(250);
    expect(backoffMs(1, () => 1)).toBe(500);
    expect(backoffMs(3, () => 1)).toBe(2000);
    expect(backoffMs(20, () => 1)).toBe(30_000);
  });
});

describe("audit.onSinkFailure", () => {
  class FakeSink implements AuditSink {
    readonly name = "fake";
    readonly events: AuditEvent[] = [];
    constructor(public up: boolean) {}
    write(e: AuditEvent): void {
      this.events.push(e);
    }
    async flush(): Promise<void> {}
    async close(): Promise<void> {}
    health(): SinkHealth {
      return {
        name: this.name,
        healthy: this.up,
        delivered: 0,
        dropped: 0,
        queued: 0,
        failedAttempts: 0,
      };
    }
  }
  const ctx = (): ToolCallContext => ({
    server: "s",
    toolName: "t",
    namespacedName: "s__t",
    args: {},
    principal: "p",
  });

  it("block: refuses calls while every sink is down, and records the refusal", async () => {
    const sink = new FakeSink(false);
    const engine = new AuditEngine(
      AuditConfigSchema.parse({ enabled: true, onSinkFailure: "block" }),
      [sink],
    );
    const next = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "ok" }] });
    const c = ctx();
    const res = await engine.buildInterceptor()(c, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.isError).toBe(true);
    expect(sink.events[0].decision).toBe("blocked_audit_unavailable");

    sink.up = true; // the sink recovers → calls flow again
    const ok = await engine.buildInterceptor()(ctx(), next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(ok.isError).toBeFalsy();
  });

  it("block: keeps serving while at least one sink is up", async () => {
    const engine = new AuditEngine(
      AuditConfigSchema.parse({ enabled: true, onSinkFailure: "block" }),
      [new FakeSink(false), new FakeSink(true)],
    );
    const next = vi.fn().mockResolvedValue({ content: [] });
    await engine.buildInterceptor()(ctx(), next);
    expect(next).toHaveBeenCalledTimes(1);
  });

  it("continue (default): serves even when every sink is down", async () => {
    const engine = new AuditEngine(AuditConfigSchema.parse({ enabled: true }), [
      new FakeSink(false),
    ]);
    const next = vi.fn().mockResolvedValue({ content: [] });
    await engine.buildInterceptor()(ctx(), next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(engine.sinkHealth()).toEqual([expect.objectContaining({ healthy: false })]);
  });
});
