/**
 * Detection of security-relevant **configuration drift**: a server's effective configuration
 * moving from a reviewed baseline to a weaker posture *without* any tool-schema change — e.g. TLS
 * downgraded from required to optional, or a host allowlist widened with a wildcard.
 *
 * The check reports **weakening only**, not any diff. Tightening a control, or an unrelated change,
 * does not fire — so a legitimate re-configuration is not flagged. Like the other heuristics it is
 * advisory (detect); enforcement is a policy choice.
 *
 * @packageDocumentation
 */
import type { SecurityFinding } from "./types.js";

type Snapshot = Record<string, unknown>;

/** Ordinal strength of a TLS/transport setting; higher = stronger. */
const TLS_RANK: Record<string, number> = {
  mutual: 3,
  required: 2,
  optional: 1,
  preferred: 1,
  none: 0,
  disabled: 0,
  off: 0,
  plaintext: 0,
};

function tlsRank(value: unknown): number | null {
  const r = TLS_RANK[String(value).toLowerCase()];
  return r === undefined ? null : r;
}

/** Whether an allowlist entry is dangerously broad. */
function isBroad(entry: unknown): boolean {
  return (
    entry === "*" ||
    entry === "0.0.0.0" ||
    entry === "0.0.0.0/0" ||
    entry === "::/0" ||
    (typeof entry === "string" && entry.includes("*"))
  );
}

const TLS_KEYS = ["tls", "transport", "tlsMode", "encryption", "scheme"];
const ALLOWLIST_KEYS = ["allowedHosts", "allowlist", "allowedOrigins", "hosts", "cors", "origins"];
/** Config keys whose truthiness represents a protection being on. */
const PROTECTIVE =
  /auth|verify|tls|secure|sandbox|encrypt|require|strict|signature|pinning|redact/i;

/**
 * Compare a reviewed `baseline` config snapshot with the `current` one and report security-relevant
 * weakening. Returns findings (empty if the posture is unchanged or strengthened).
 */
export function checkConfigDrift(baseline: Snapshot, current: Snapshot): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  if (!baseline || !current || typeof baseline !== "object" || typeof current !== "object") {
    return findings;
  }

  // TLS / transport downgrade.
  for (const key of TLS_KEYS) {
    if (key in baseline && key in current) {
      const rb = tlsRank(baseline[key]);
      const rc = tlsRank(current[key]);
      if (rb !== null && rc !== null && rc < rb) {
        findings.push({
          rule: "config-drift",
          severity: "high",
          excerpt: `${key} weakened: ${String(baseline[key])} → ${String(current[key])}`,
        });
      }
    }
  }

  // Allowlist widened with a wildcard / broad entry that was not present before.
  for (const key of ALLOWLIST_KEYS) {
    const bv = baseline[key];
    const cv = current[key];
    if (Array.isArray(bv) && Array.isArray(cv)) {
      const addedBroad = cv.some((x) => isBroad(x) && !bv.includes(x));
      if (addedBroad) {
        findings.push({
          rule: "config-drift",
          severity: "high",
          excerpt: `${key} widened with a wildcard entry: [${cv.map(String).join(", ")}]`,
        });
      }
    }
  }

  // A protective flag flipped from on to off.
  for (const key of Object.keys(baseline)) {
    if (PROTECTIVE.test(key) && baseline[key] === true && current[key] === false) {
      findings.push({
        rule: "config-drift",
        severity: "high",
        excerpt: `${key} disabled: true → false`,
      });
    }
  }

  return findings;
}
