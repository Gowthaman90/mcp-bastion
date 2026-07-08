/**
 * Maps audit decisions to governance frameworks (NIST AI RMF, OWASP LLM Top 10)
 * and aggregates events into a compliance report.
 *
 * The mappings are indicative, intended to evidence that specific controls are
 * being exercised at runtime — not a certification. They are centralized here so
 * they can be reviewed and refined in one place.
 *
 * @packageDocumentation
 */
import type { SecurityFinding } from "../security/index.js";
import type { AuditDecision, AuditEvent, FrameworkMapping } from "./types.js";

/** Derive the framework controls exercised by a decision + findings. */
export function frameworksFor(
  decision: AuditDecision,
  findings: readonly SecurityFinding[] = [],
): FrameworkMapping {
  const nist = new Set<string>();
  const owasp = new Set<string>();

  // Observing and recording every tool call is itself a MEASURE activity.
  nist.add("MEASURE");

  if (decision === "blocked_rug_pull") {
    nist.add("MANAGE");
    owasp.add("LLM03: Training Data / Supply Chain");
    owasp.add("LLM06: Excessive Agency");
  }
  if (decision === "blocked_poisoning" || findings.length > 0) {
    nist.add("MANAGE");
    owasp.add("LLM01: Prompt Injection");
  }

  return { nistAiRmf: [...nist], owaspLlm: [...owasp] };
}

/** Aggregate compliance view over a set of audit events. */
export interface ComplianceReport {
  totalEvents: number;
  byDecision: Record<string, number>;
  byOutcome: Record<string, number>;
  controls: {
    nistAiRmf: Record<string, number>;
    owaspLlm: Record<string, number>;
  };
}

/** Build a {@link ComplianceReport} from recorded events. */
export function buildComplianceReport(events: readonly AuditEvent[]): ComplianceReport {
  const byDecision: Record<string, number> = {};
  const byOutcome: Record<string, number> = {};
  const nist: Record<string, number> = {};
  const owasp: Record<string, number> = {};

  for (const event of events) {
    byDecision[event.decision] = (byDecision[event.decision] ?? 0) + 1;
    byOutcome[event.outcome] = (byOutcome[event.outcome] ?? 0) + 1;
    for (const control of event.frameworks.nistAiRmf) nist[control] = (nist[control] ?? 0) + 1;
    for (const control of event.frameworks.owaspLlm) owasp[control] = (owasp[control] ?? 0) + 1;
  }

  return {
    totalEvents: events.length,
    byDecision,
    byOutcome,
    controls: { nistAiRmf: nist, owaspLlm: owasp },
  };
}
