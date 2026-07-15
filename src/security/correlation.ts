/**
 * Cross-tool correlation — catches poisoning payloads that are *split across multiple tools* so that
 * each individual tool passes single-tool scanning (e.g. the "ShareLock" threshold-poisoning attack,
 * arXiv:2606.27027, which disguises shares of a payload as per-tool `tool_id`/`checksum` metadata).
 *
 * A single-tool scanner is blind to this by construction. Because bastion observes a server's *entire*
 * tool set at once, it can look across tools for two signals:
 *   1. the **concatenation** of the tool set's names/descriptions trips a poisoning heuristic (a plainly
 *      readable payload split across tools); and
 *   2. **coordinated staging metadata** — two or more tools from the same set carry opaque
 *      `share`/`shard`/`fragment`/`checksum`/`tool_id`-style key/value metadata, the pattern such
 *      split-poisoning attacks use to stage a payload for later reassembly.
 *
 * This is a heuristic for the staging pattern and readable splits — not a cryptographic defeat of
 * threshold secret-sharing; a sufficiently disguised variant can still evade it.
 *
 * @packageDocumentation
 */
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

import { scanText } from "./poisoning.js";
import type { SecurityFinding } from "./types.js";

/** Opaque `key=value` / `key: value` metadata used to stage split payloads across tools. */
const STAGING = /\b(share|shard|fragment|part|checksum|tool[_-]?id)\s*[:=]\s*\S+/i;

/** Scan a set of tools (from one server) for split / coordinated poisoning across tools. */
export function scanToolSet(tools: readonly Tool[]): SecurityFinding[] {
  if (!Array.isArray(tools) || tools.length < 2) return [];
  const findings: SecurityFinding[] = [];

  // 1) Payload readable only when the tool descriptions are combined.
  const combined = tools.map((t) => `${t.name ?? ""} ${t.description ?? ""}`).join("\n");
  for (const f of scanText(combined)) {
    findings.push({ ...f, rule: `cross-tool-${f.rule}` });
  }

  // 2) Coordinated staging metadata across two or more tools.
  const staged = tools.filter((t) => STAGING.test(`${t.name ?? ""} ${t.description ?? ""}`));
  if (staged.length >= 2) {
    findings.push({
      rule: "split-payload-staging",
      severity: "high",
      excerpt: `${staged.length} tools carry opaque share/checksum-style metadata (possible split poisoning)`,
    });
  }

  return findings;
}
