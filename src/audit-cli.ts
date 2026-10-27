/**
 * `mcp-bastion audit …` subcommands: offline log verification and checkpoint key generation.
 * Kept out of `cli.ts` so the proxy entrypoint stays thin and these stay testable.
 *
 * @packageDocumentation
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  generateCheckpointKeyPair,
  parseJsonl,
  verifyAuditLog,
  type VerifyReport,
} from "./audit/index.js";

/** Exit codes: 0 intact, 1 tampered, 2 cannot verify. */
export const VERIFY_EXIT = { intact: 0, tampered: 1, unverifiable: 2 } as const;

export interface VerifyCliOptions {
  checkpoints?: string;
  publicKey?: string;
  keyEnv?: string;
  json?: boolean;
}

/** Run `audit verify`; returns the exit code and the text to print. */
export function auditVerify(
  logPath: string,
  opts: VerifyCliOptions,
  env: NodeJS.ProcessEnv = process.env,
): { code: number; output: string } {
  let text: string;
  try {
    text = readFileSync(logPath, "utf8");
  } catch (err) {
    return {
      code: VERIFY_EXIT.unverifiable,
      output: `cannot read ${logPath}: ${(err as Error).message}`,
    };
  }
  const parsed = parseJsonl(text);
  let witness: unknown[] | undefined;
  if (opts.checkpoints) {
    try {
      witness = parseJsonl(readFileSync(opts.checkpoints, "utf8")).records;
    } catch (err) {
      return {
        code: VERIFY_EXIT.unverifiable,
        output: `cannot read ${opts.checkpoints}: ${(err as Error).message}`,
      };
    }
  }
  let publicKeyPem: string | undefined;
  if (opts.publicKey) {
    try {
      publicKeyPem = readFileSync(opts.publicKey, "utf8");
    } catch (err) {
      return {
        code: VERIFY_EXIT.unverifiable,
        output: `cannot read ${opts.publicKey}: ${(err as Error).message}`,
      };
    }
  }
  const hmacKey = env[opts.keyEnv ?? "MCP_BASTION_AUDIT_KEY"] || undefined;
  const report = verifyAuditLog(parsed.records, { hmacKey, publicKeyPem, witness });
  report.issues.unshift(...parsed.issues);
  if (parsed.issues.some((i) => i.level === "tampered")) report.status = "tampered";
  return {
    code: VERIFY_EXIT[report.status],
    output: opts.json ? JSON.stringify(report, null, 2) : formatReport(report),
  };
}

function formatReport(r: VerifyReport): string {
  const head = {
    intact: "INTACT: no sign of tampering",
    tampered: "TAMPERED: the log does not match its chain or checkpoints",
    unverifiable: "CANNOT VERIFY: see the reasons below",
  }[r.status];
  const lines = [
    head,
    `runs ${r.runs} · call events ${r.events} · checkpoints valid ${r.checkpoints.valid}, invalid ${r.checkpoints.invalid}`,
    ...r.issues.map((i) => `  [${i.level}] ${i.message}`),
  ];
  return lines.join("\n");
}

/** Run `audit keygen`: write an Ed25519 key pair into `dir`, never overwriting. */
export function auditKeygen(dir: string): { code: number; output: string } {
  const priv = join(dir, "checkpoint-private.pem");
  const pub = join(dir, "checkpoint-public.pem");
  if (existsSync(priv) || existsSync(pub)) {
    return { code: 1, output: `refusing to overwrite an existing key in ${dir}` };
  }
  mkdirSync(dir, { recursive: true });
  const kp = generateCheckpointKeyPair();
  writeFileSync(priv, kp.privateKeyPem, { mode: 0o600 });
  writeFileSync(pub, kp.publicKeyPem, { mode: 0o644 });
  return {
    code: 0,
    output: [
      `wrote ${priv} (keep secret, mode 600) and ${pub} (give to auditors)`,
      `key id ${kp.keyId}`,
      `config: "audit": { "tamperEvident": true, "checkpoint": { "privateKeyFile": "${priv}" } }`,
      "Keep the private key off the host that stores the log in production.",
    ].join("\n"),
  };
}
