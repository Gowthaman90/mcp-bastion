import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AuditEngine,
  createSinks,
  generateCheckpointKeyPair,
  parseJsonl,
  verifyAuditLog,
  verifyChain,
} from "../src/audit/index.js";
import { toOtlpLogs } from "../src/audit/sinks/index.js";
import type { AuditCheckpoint, AuditRecord, AuditSink } from "../src/audit/index.js";
import { auditKeygen, auditVerify } from "../src/audit-cli.js";
import { AuditConfigSchema } from "../src/config/index.js";
import type { ToolCallContext } from "../src/security/index.js";

class MemorySink implements AuditSink {
  readonly name = "memory";
  readonly records: AuditRecord[] = [];
  constructor(public includeArgs?: "none" | "redacted" | "full") {}
  write(r: AuditRecord): void {
    this.records.push(JSON.parse(JSON.stringify(r)) as AuditRecord);
  }
  async flush(): Promise<void> {}
  async close(): Promise<void> {}
}

const KEY = "integrity-key-for-tests-0123456789";
const dir = () => mkdtempSync(join(tmpdir(), "bastion-cp-"));
const ctx = (i: number): ToolCallContext => ({
  server: "files",
  toolName: "read_file",
  namespacedName: "files__read_file",
  args: { path: `/srv/docs/${i}.md`, token: "s3cret-value" },
  principal: "p",
});
const ok = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "ok" }] });
async function calls(engine: AuditEngine, n: number, from = 1): Promise<void> {
  for (let i = from; i < from + n; i++) await engine.buildInterceptor()(ctx(i), ok);
}
const lines = (path: string) => parseJsonl(readFileSync(path, "utf8")).records;
const cps = (rs: readonly unknown[]) =>
  rs.filter(
    (r) => (r as AuditRecord & { recordType?: string }).recordType === "checkpoint",
  ) as AuditCheckpoint[];

afterEach(() => {
  delete process.env.MCP_BASTION_CHECKPOINT_KEY;
});

describe("per-sink includeArgs and chain v2", () => {
  it("keeps chain v1 (args hashed) when every sink records arguments the same way", async () => {
    const a = new MemorySink();
    const engine = new AuditEngine(
      AuditConfigSchema.parse({ enabled: true, tamperEvident: true, includeArgs: "redacted" }),
      [a],
    );
    await calls(engine, 2);
    expect(a.records[0]).not.toHaveProperty("chainVersion");
    expect((a.records[0] as { args?: unknown }).args).toEqual({
      path: "/srv/docs/1.md",
      token: "[REDACTED]",
    });
    expect(verifyChain(a.records)).toBe(-1);
  });

  it("gives each sink its own view, and both views verify the same chain (v2)", async () => {
    const full = new MemorySink("full");
    const none = new MemorySink("none");
    const engine = new AuditEngine(
      AuditConfigSchema.parse({
        enabled: true,
        tamperEvident: true,
        integrityKey: KEY,
        includeArgs: "none",
      }),
      [full, none],
    );
    await calls(engine, 3);
    expect(full.records[0]).toMatchObject({
      chainVersion: 2,
      args: { path: "/srv/docs/1.md", token: "s3cret-value" },
    });
    expect(none.records[0]).not.toHaveProperty("args");
    expect((full.records[0] as { hash: string }).hash).toBe(
      (none.records[0] as { hash: string }).hash,
    );
    expect(verifyChain(full.records, KEY)).toBe(-1);
    expect(verifyChain(none.records, KEY)).toBe(-1);
    expect(verifyAuditLog(full.records, { hmacKey: KEY }).status).toBe("intact");

    // An edited full-args view is not covered by the v2 chain, but argsDigest flags it.
    (full.records[1] as { args: Record<string, unknown> }).args.path = "/etc/shadow";
    const report = verifyAuditLog(full.records, { hmacKey: KEY });
    expect(report.issues.some((i) => /seq 2 args do not match argsDigest/.test(i.message))).toBe(
      true,
    );
  });
});

describe("signed checkpoints", () => {
  function setup(extra: Record<string, unknown> = {}) {
    const d = dir();
    const kp = generateCheckpointKeyPair();
    process.env.MCP_BASTION_CHECKPOINT_KEY = kp.privateKeyPem;
    const witness = join(d, "witness.jsonl");
    const main = new MemorySink();
    const config = AuditConfigSchema.parse({
      enabled: true,
      tamperEvident: true,
      integrityKey: KEY,
      checkpoint: { everyEvents: 2, sinks: [{ type: "file", path: witness }], ...extra },
    });
    return { d, kp, witness, main, config };
  }

  it("writes a run-start, periodic and final checkpoints; the log verifies intact", async () => {
    const { kp, witness, main, config } = setup();
    const engine = new AuditEngine(config, [main]);
    await calls(engine, 5);
    await engine.close();

    expect(main.records[0]).toMatchObject({ recordType: "run-start", seq: 0, runId: engine.runId });
    expect(cps(main.records).map((c) => c.seq)).toEqual([2, 4, 5]);
    expect(cps(lines(witness)).map((c) => c.seq)).toEqual([2, 4, 5]); // the witness gets only checkpoints
    expect(
      lines(witness).every((r) => (r as { recordType?: string }).recordType === "checkpoint"),
    ).toBe(true);
    const report = verifyAuditLog(main.records, {
      hmacKey: KEY,
      publicKeyPem: kp.publicKeyPem,
      witness: lines(witness),
    });
    expect(report).toMatchObject({
      status: "intact",
      runs: 1,
      events: 5,
      checkpoints: { valid: 3, invalid: 0 },
    });
  });

  it("detects a log cut short, using the witness", async () => {
    const { kp, witness, main, config } = setup();
    const engine = new AuditEngine(config, [main]);
    await calls(engine, 5);
    await engine.close();
    // Delete the last event and every checkpoint from the log itself.
    const cut = main.records.filter(
      (r) =>
        (r as { seq?: number }).seq !== 5 &&
        (r as { recordType?: string }).recordType !== "checkpoint",
    );
    const withWitness = verifyAuditLog(cut, {
      hmacKey: KEY,
      publicKeyPem: kp.publicKeyPem,
      witness: lines(witness),
    });
    expect(withWitness.status).toBe("tampered");
    expect(withWitness.issues.map((i) => i.message).join("\n")).toMatch(
      /ends at seq 4 but a signed checkpoint covers seq 5/,
    );
    // Honest limit: with no witness, a cut that also removes the checkpoints is invisible.
    expect(verifyAuditLog(cut, { hmacKey: KEY, publicKeyPem: kp.publicKeyPem }).status).toBe(
      "intact",
    );
  });

  it("detects an edited event, a reordered log and a forged checkpoint", async () => {
    const { kp, main, config } = setup();
    const engine = new AuditEngine(config, [main]);
    await calls(engine, 3);
    await engine.close();
    const pk = kp.publicKeyPem;

    const edited = JSON.parse(JSON.stringify(main.records));
    edited[2].decision = "blocked_authorization";
    expect(verifyAuditLog(edited, { hmacKey: KEY, publicKeyPem: pk }).status).toBe("tampered");

    const chained = main.records.filter(
      (r) => (r as { recordType?: string }).recordType !== "checkpoint",
    );
    const reordered = [chained[0], chained[2], chained[1], chained[3]];
    expect(
      verifyAuditLog(reordered, { hmacKey: KEY })
        .issues.map((i) => i.message)
        .join("\n"),
    ).toMatch(/missing or reordered/);

    const forged = JSON.parse(JSON.stringify(main.records));
    const cp = forged.find((r: { recordType?: string }) => r.recordType === "checkpoint");
    cp.head = "0".repeat(64);
    const r = verifyAuditLog(forged, { hmacKey: KEY, publicKeyPem: pk });
    expect(r.checkpoints.invalid).toBe(1);
    expect(r.status).toBe("tampered");
  });

  it("links runs through the state file and detects a deleted earlier run", async () => {
    const { d, kp, witness, config } = setup();
    const stateFile = join(d, "state.json");
    const cfg = AuditConfigSchema.parse({
      ...config,
      checkpoint: { ...config.checkpoint, stateFile },
    });
    const log: AuditRecord[] = [];
    const sink = new MemorySink();
    const run1 = new AuditEngine(cfg, [sink]);
    await calls(run1, 2);
    await run1.close();
    expect(statSync(stateFile).mode & 0o777).toBe(0o600);
    const run2 = new AuditEngine(cfg, [sink]);
    await calls(run2, 1, 10);
    await run2.close();
    log.push(...sink.records);

    const start2 = log.find(
      (r) =>
        (r as { recordType?: string; runId?: string }).recordType === "run-start" &&
        (r as { runId: string }).runId === run2.runId,
    );
    expect(start2).toMatchObject({ prevRunHead: { runId: run1.runId, seq: 2 } });
    expect(
      verifyAuditLog(log, { hmacKey: KEY, publicKeyPem: kp.publicKeyPem, witness: lines(witness) })
        .status,
    ).toBe("intact");

    const withoutRun1 = log.filter((r) => (r as { runId?: string }).runId !== run1.runId);
    const report = verifyAuditLog(withoutRun1, {
      hmacKey: KEY,
      publicKeyPem: kp.publicKeyPem,
      witness: lines(witness),
    });
    expect(report.status).toBe("tampered");
    expect(report.issues.map((i) => i.message).join("\n")).toMatch(/run deleted/);
  });

  it("refuses to start without a key, and refuses checkpoints without the hash chain", () => {
    expect(
      () =>
        new AuditEngine(
          AuditConfigSchema.parse({ enabled: true, tamperEvident: true, checkpoint: {} }),
          [],
        ),
    ).toThrow(/needs an Ed25519 private key/);
    expect(AuditConfigSchema.safeParse({ enabled: true, checkpoint: {} }).success).toBe(false);
  });

  it("maps run-start and checkpoint records to OTLP without errors", async () => {
    const { main, config } = setup();
    const engine = new AuditEngine(config, [main]);
    await calls(engine, 1);
    await engine.close();
    const otlp = JSON.stringify(toOtlpLogs(main.records));
    expect(otlp).toContain("audit.record_type");
  });
});

describe("audit CLI", () => {
  it("verify exits 0 intact, 1 tampered, 2 when checkpoints cannot be checked", async () => {
    const d = dir();
    const keys = join(d, "keys");
    expect(auditKeygen(keys).code).toBe(0);
    expect(auditKeygen(keys).code).toBe(1); // never overwrites
    process.env.MCP_BASTION_CHECKPOINT_KEY = readFileSync(
      join(keys, "checkpoint-private.pem"),
      "utf8",
    );
    const log = join(d, "audit.jsonl");
    const fileEngine = new AuditEngine(
      AuditConfigSchema.parse({
        enabled: true,
        tamperEvident: true,
        integrityKey: KEY,
        checkpoint: {},
      }),
      createSinks([{ type: "file", path: log }]),
    );
    await calls(fileEngine, 3);
    await fileEngine.close();
    const env = { K: KEY };
    const pub = join(keys, "checkpoint-public.pem");

    expect(auditVerify(log, { publicKey: pub, keyEnv: "K" }, env).code).toBe(0);
    expect(auditVerify(log, { keyEnv: "K" }, env).code).toBe(2);

    const text = readFileSync(log, "utf8").replace(
      '"decision":"allowed"',
      '"decision":"blocked_schema"',
    );
    writeFileSync(log, text);
    const res = auditVerify(log, { publicKey: pub, keyEnv: "K" }, env);
    expect(res.code).toBe(1);
    expect(res.output).toMatch(/^TAMPERED/);
  });
});
