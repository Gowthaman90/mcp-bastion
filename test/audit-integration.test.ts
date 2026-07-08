import { afterEach, describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { BastionConfigSchema, type BastionConfig } from "../src/config/index.js";
import { UpstreamManager } from "../src/core/index.js";
import { verifyChain } from "../src/audit/index.js";
import type { AuditEvent } from "../src/audit/index.js";

const mutating = fileURLToPath(new URL("./fixtures/mutating-server.mjs", import.meta.url));

function tmpFile(name: string, content = ""): string {
  const path = join(mkdtempSync(join(tmpdir(), "bastion-audit-")), name);
  writeFileSync(path, content);
  return path;
}

function cfg(descPath: string, auditPath: string): BastionConfig {
  return BastionConfigSchema.parse({
    servers: { mut: { command: process.execPath, args: [mutating, descPath] } },
    reconnect: { auto: false },
    healthCheck: { enabled: false },
    security: { onRugPull: "block" },
    audit: { enabled: true, tamperEvident: true, sinks: [{ type: "file", path: auditPath }] },
  });
}

function readEvents(path: string): AuditEvent[] {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l) as AuditEvent);
}

describe("audit & compliance (v0.3, end-to-end via the manager)", () => {
  let mgr: UpstreamManager;

  afterEach(async () => {
    await mgr?.closeAll();
  });

  it("writes a verifiable, framework-mapped audit trail for allowed and blocked calls", async () => {
    const descPath = tmpFile("desc.txt", "a safe read-only operation");
    const auditPath = tmpFile("audit.jsonl");
    mgr = new UpstreamManager(cfg(descPath, auditPath));
    await mgr.connectAll();

    // Allowed call.
    expect((await mgr.callUpstreamTool("mut__op", {})).isError).toBeFalsy();

    // Rug pull → blocked call.
    writeFileSync(descPath, "now it does something completely different");
    await mgr.reconnect("mut");
    expect((await mgr.callUpstreamTool("mut__op", {})).isError).toBe(true);

    // Compliance report reflects both calls.
    const report = mgr.complianceReport();
    expect(report.totalEvents).toBe(2);
    expect(report.byDecision.allowed).toBe(1);
    expect(report.byDecision.blocked_rug_pull).toBe(1);
    expect(report.controls.nistAiRmf.MEASURE).toBe(2);

    // Flush the file sink, then verify the persisted trail.
    await mgr.closeAll();
    const events = readEvents(auditPath);
    expect(events.map((e) => e.decision)).toEqual(["allowed", "blocked_rug_pull"]);
    expect(events[1].frameworks.owaspLlm.join(" ")).toMatch(/Excessive Agency/);
    expect(verifyChain(events)).toBe(-1); // tamper-evident chain intact
  });

  it("does nothing when audit is disabled (empty compliance report)", async () => {
    const descPath = tmpFile("desc.txt", "safe");
    mgr = new UpstreamManager(
      BastionConfigSchema.parse({
        servers: { mut: { command: process.execPath, args: [mutating, descPath] } },
        reconnect: { auto: false },
        healthCheck: { enabled: false },
      }),
    );
    await mgr.connectAll();
    await mgr.callUpstreamTool("mut__op", {});
    expect(mgr.complianceReport().totalEvents).toBe(0);
  });
});
