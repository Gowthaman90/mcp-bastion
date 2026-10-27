/**
 * Offline verification of an audit log (backs `mcp-bastion audit verify`).
 *
 * Checks, per run: the hash chain (v1 and v2, keyed or not), `seq` continuity, signed checkpoints
 * (from the log and from a separate witness file) against the log, and the `run-start` link to the
 * previous run. Pure: takes parsed records, returns a report.
 *
 * What it can and cannot prove: a cut or deleted run is detected only back to the last checkpoint
 * that reached a witness the attacker could not rewrite. Without a witness, a log cut at a
 * checkpoint boundary still verifies.
 *
 * @packageDocumentation
 */
import { createPublicKey, type KeyObject } from "node:crypto";

import { argsDigest, verifyChain } from "./chain.js";
import { verifyCheckpoint } from "./checkpoint.js";
import type { AuditCheckpoint, AuditRecord, AuditRunStart } from "./types.js";

export type VerifyStatus = "intact" | "tampered" | "unverifiable";

export interface VerifyIssue {
  /** `tampered`: evidence of change; `unverifiable`: cannot check; `warning`: worth a look. */
  level: "tampered" | "unverifiable" | "warning";
  message: string;
}

export interface VerifyReport {
  status: VerifyStatus;
  runs: number;
  events: number;
  checkpoints: { valid: number; invalid: number };
  issues: VerifyIssue[];
}

export interface VerifyOptions {
  /** HMAC key of a keyed chain (`integrityKey`). */
  hmacKey?: string;
  /** Ed25519 public key (PEM) the checkpoints are signed with. */
  publicKeyPem?: string;
  /** Records from a witness sink (checkpoints are used; other records ignored). */
  witness?: readonly unknown[];
}

type Chained = AuditRecord & { seq: number; hash?: string; runId?: string };

const isCheckpoint = (r: unknown): r is AuditCheckpoint =>
  !!r && typeof r === "object" && (r as { recordType?: unknown }).recordType === "checkpoint";

/** Parse JSON lines. A bad final line (partial write at a crash) is a warning; elsewhere it is tampering. */
export function parseJsonl(text: string): { records: unknown[]; issues: VerifyIssue[] } {
  const lines = text.split("\n");
  while (lines.length > 0 && lines[lines.length - 1].trim() === "") lines.pop();
  const records: unknown[] = [];
  const issues: VerifyIssue[] = [];
  lines.forEach((line, i) => {
    if (line.trim() === "") return;
    try {
      records.push(JSON.parse(line));
    } catch {
      issues.push(
        i === lines.length - 1
          ? {
              level: "warning",
              message: `line ${i + 1} is not complete JSON (a partial write at shutdown?)`,
            }
          : { level: "tampered", message: `line ${i + 1} is not valid JSON` },
      );
    }
  });
  return { records, issues };
}

/** Group chained records into runs: by `runId`, or (older logs) by a `seq` that restarts. */
function groupRuns(records: readonly unknown[]): Map<string, Chained[]> {
  const runs = new Map<string, Chained[]>();
  let legacy = 0;
  let lastLegacySeq = Infinity;
  for (const r of records) {
    if (!r || typeof r !== "object" || isCheckpoint(r)) continue;
    const rec = r as Chained;
    let key = rec.runId;
    if (key === undefined) {
      if (typeof rec.seq === "number" && rec.seq <= lastLegacySeq) legacy++;
      lastLegacySeq = rec.seq;
      key = `(no runId) segment ${legacy}`;
    }
    const list = runs.get(key) ?? [];
    list.push(rec);
    runs.set(key, list);
  }
  return runs;
}

export function verifyAuditLog(
  records: readonly unknown[],
  opts: VerifyOptions = {},
): VerifyReport {
  const issues: VerifyIssue[] = [];
  const runs = groupRuns(records);
  let events = 0;

  for (const [runId, list] of runs) {
    events += list.filter((r) => !("recordType" in r)).length;
    // seq continuity
    for (let i = 1; i < list.length; i++) {
      if (list[i].seq !== list[i - 1].seq + 1) {
        issues.push({
          level: "tampered",
          message: `run ${runId}: records missing or reordered between seq ${list[i - 1].seq} and ${list[i].seq}`,
        });
      }
    }
    // hash chain
    if (!list.some((r) => typeof r.hash === "string")) {
      issues.push({
        level: "unverifiable",
        message: `run ${runId}: no hash chain (audit.tamperEvident was off)`,
      });
      continue;
    }
    // Chain v2 covers argsDigest, not the per-sink args view: check a full view against the digest.
    if (opts.hmacKey) {
      for (const r of list as Array<
        Chained & { args?: unknown; argsDigest?: string; chainVersion?: number }
      >) {
        if (
          r.chainVersion === 2 &&
          r.argsDigest &&
          r.args !== undefined &&
          argsDigest(r.args, opts.hmacKey) !== r.argsDigest
        ) {
          issues.push({
            level: "warning",
            message: `run ${runId}: seq ${r.seq} args do not match argsDigest (expected for a redacted view; tampering if this sink records full arguments)`,
          });
        }
      }
    }
    const broken = verifyChain(list, opts.hmacKey);
    if (broken !== -1) {
      if (!opts.hmacKey && broken === 0) {
        issues.push({
          level: "unverifiable",
          message: `run ${runId}: the chain does not verify without a key; if it is keyed, pass the integrity key`,
        });
      } else {
        issues.push({
          level: "tampered",
          message: `run ${runId}: hash chain breaks at seq ${list[broken].seq}`,
        });
      }
    }
  }

  // signed checkpoints, from the log and the witness
  const cps = [...records, ...(opts.witness ?? [])].filter(isCheckpoint);
  const seen = new Set<string>();
  let valid = 0;
  let invalid = 0;
  let publicKey: KeyObject | undefined;
  if (cps.length > 0) {
    if (!opts.publicKeyPem) {
      issues.push({
        level: "unverifiable",
        message: `${cps.length} checkpoint(s) present but no public key to verify them`,
      });
    } else {
      try {
        publicKey = createPublicKey(opts.publicKeyPem);
      } catch {
        issues.push({
          level: "unverifiable",
          message: "the public key is not a valid PEM public key",
        });
      }
    }
  }
  if (publicKey) {
    for (const cp of cps) {
      const id = `${cp.runId}#${cp.seq}#${cp.head}`;
      if (seen.has(id)) continue;
      seen.add(id);
      if (!verifyCheckpoint(cp, publicKey)) {
        invalid++;
        issues.push({
          level: "tampered",
          message: `run ${cp.runId}: checkpoint at seq ${cp.seq} has an invalid signature`,
        });
        continue;
      }
      valid++;
      const list = runs.get(cp.runId);
      if (!list) {
        issues.push({
          level: "tampered",
          message: `run ${cp.runId}: a signed checkpoint exists but the log has no records of this run (run deleted)`,
        });
        continue;
      }
      const at = list.find((r) => r.seq === cp.seq);
      const last = list[list.length - 1].seq;
      if (!at) {
        issues.push(
          cp.seq > last
            ? {
                level: "tampered",
                message: `run ${cp.runId}: the log ends at seq ${last} but a signed checkpoint covers seq ${cp.seq} (records cut)`,
              }
            : {
                level: "tampered",
                message: `run ${cp.runId}: record seq ${cp.seq} named by a signed checkpoint is missing`,
              },
        );
      } else if (at.hash !== cp.head) {
        issues.push({
          level: "tampered",
          message: `run ${cp.runId}: record seq ${cp.seq} does not match its signed checkpoint`,
        });
      }
    }
  }

  // run-start links to the previous run
  for (const list of runs.values()) {
    const start = list.find((r) => (r as AuditRunStart).recordType === "run-start") as
      AuditRunStart | undefined;
    const prev = start?.prevRunHead;
    if (!prev) continue;
    const prevList = runs.get(prev.runId);
    if (!prevList) {
      issues.push({
        level: "warning",
        message: `run ${start.runId} follows run ${prev.runId}, which is not in this log (rotated, or deleted)`,
      });
      continue;
    }
    const at = prevList.find((r) => r.seq === prev.seq);
    if (!at || at.hash !== prev.hash) {
      issues.push({
        level: "tampered",
        message: `run ${start.runId}: its link to run ${prev.runId} at seq ${prev.seq} does not match the log`,
      });
    }
  }

  const status: VerifyStatus = issues.some((i) => i.level === "tampered")
    ? "tampered"
    : issues.some((i) => i.level === "unverifiable")
      ? "unverifiable"
      : "intact";
  return { status, runs: runs.size, events, checkpoints: { valid, invalid }, issues };
}
