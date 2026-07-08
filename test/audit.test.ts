import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AuditConfigSchema } from "../src/config/index.js";
import { AuditEngine } from "../src/audit/engine.js";
import { FileSink } from "../src/audit/sinks/file.js";
import { prepareArgs } from "../src/audit/redaction.js";
import { verifyChain } from "../src/audit/chain.js";
import { frameworksFor, buildComplianceReport } from "../src/audit/compliance.js";
import type { AuditEvent, AuditSink } from "../src/audit/types.js";
import type { ToolCallContext } from "../src/security/index.js";

class MemorySink implements AuditSink {
  readonly name = "memory";
  readonly events: AuditEvent[] = [];
  write(event: AuditEvent): void {
    this.events.push(event);
  }
  async flush(): Promise<void> {}
  async close(): Promise<void> {}
}

const ctx = (over: Partial<ToolCallContext> = {}): ToolCallContext => ({
  server: "s",
  toolName: "t",
  namespacedName: "s__t",
  args: {},
  ...over,
});

const ok = { content: [{ type: "text" as const, text: "ok" }], isError: false };

describe("redaction", () => {
  it("omits args entirely for 'none'", () => {
    expect(prepareArgs({ a: 1 }, "none", [])).toBeUndefined();
  });
  it("passes args through for 'full'", () => {
    expect(prepareArgs({ a: 1 }, "full", ["a"])).toEqual({ a: 1 });
  });
  it("redacts sensitive keys at any depth for 'redacted'", () => {
    const out = prepareArgs({ password: "x", nested: { token: "y", keep: 1 } }, "redacted", [
      "password",
      "token",
    ]);
    expect(out).toEqual({ password: "[REDACTED]", nested: { token: "[REDACTED]", keep: 1 } });
  });
});

describe("compliance mapping", () => {
  it("maps a rug-pull block to MANAGE + excessive agency", () => {
    const fw = frameworksFor("blocked_rug_pull");
    expect(fw.nistAiRmf).toContain("MANAGE");
    expect(fw.owaspLlm.join(" ")).toMatch(/Excessive Agency/);
  });
  it("aggregates a report across events", () => {
    const report = buildComplianceReport([
      { decision: "allowed", outcome: "ok", frameworks: frameworksFor("allowed") } as AuditEvent,
      {
        decision: "blocked_rug_pull",
        outcome: "blocked",
        frameworks: frameworksFor("blocked_rug_pull"),
      } as AuditEvent,
    ]);
    expect(report.totalEvents).toBe(2);
    expect(report.byDecision.blocked_rug_pull).toBe(1);
    expect(report.controls.nistAiRmf.MEASURE).toBe(2);
  });
});

describe("AuditEngine", () => {
  const cfg = (over: Record<string, unknown> = {}) =>
    AuditConfigSchema.parse({ enabled: true, ...over });

  it("records an allowed call with schema, sequence, and frameworks", async () => {
    const sink = new MemorySink();
    const engine = new AuditEngine(cfg(), [sink]);
    await engine.buildInterceptor()(ctx(), async () => ok);

    expect(sink.events).toHaveLength(1);
    const e = sink.events[0];
    expect(e.schemaVersion).toBe(1);
    expect(e.seq).toBe(1);
    expect(e.decision).toBe("allowed");
    expect(e.outcome).toBe("ok");
    expect(e.traceId).toBeTruthy();
    expect(e.frameworks.nistAiRmf).toContain("MEASURE");
  });

  it("records a blocked call annotated by a downstream interceptor", async () => {
    const sink = new MemorySink();
    const engine = new AuditEngine(cfg(), [sink]);
    await engine.buildInterceptor()(ctx(), async (): Promise<typeof ok> => {
      // Simulate a security interceptor blocking the call.
      return ok;
    });
    // Now a blocked one:
    await engine.buildInterceptor()(
      Object.assign(ctx(), { securityDecision: "blocked_rug_pull" as const }),
      async () => ({ content: [{ type: "text" as const, text: "blocked" }], isError: true }),
    );
    const blocked = sink.events.at(-1)!;
    expect(blocked.decision).toBe("blocked_rug_pull");
    expect(blocked.outcome).toBe("blocked");
  });

  it("produces a verifiable hash chain when tamperEvident is on", async () => {
    const sink = new MemorySink();
    const engine = new AuditEngine(cfg({ tamperEvident: true }), [sink]);
    for (let i = 0; i < 3; i++) await engine.buildInterceptor()(ctx(), async () => ok);

    expect(verifyChain(sink.events)).toBe(-1); // intact

    const tampered = sink.events.map((e) => ({ ...e }));
    tampered[1] = { ...tampered[1], tool: "changed" };
    expect(verifyChain(tampered)).toBe(1); // first broken link
  });

  it("aggregates a compliance report from recorded events", async () => {
    const engine = new AuditEngine(cfg(), [new MemorySink()]);
    await engine.buildInterceptor()(ctx(), async () => ok);
    expect(engine.complianceReport().totalEvents).toBe(1);
  });
});

describe("FileSink", () => {
  it("appends JSON lines and flushes on close", async () => {
    const path = join(mkdtempSync(join(tmpdir(), "bastion-audit-")), "audit.jsonl");
    const sink = new FileSink(path);
    const event = { schemaVersion: 1, seq: 1, tool: "t" } as AuditEvent;
    sink.write(event);
    sink.write({ ...event, seq: 2 });
    await sink.close();

    const lines = readFileSync(path, "utf8").trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).tool).toBe("t");
    expect(JSON.parse(lines[1]).seq).toBe(2);
  });
});
