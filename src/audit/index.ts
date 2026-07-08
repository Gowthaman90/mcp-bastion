/**
 * Public surface of the audit layer.
 *
 * @packageDocumentation
 */
export { AuditEngine } from "./engine.js";
export { createSinks, ConsoleSink, FileSink, WebhookSink } from "./sinks/index.js";
export { frameworksFor, buildComplianceReport } from "./compliance.js";
export type { ComplianceReport } from "./compliance.js";
export { chainHash, verifyChain } from "./chain.js";
export { prepareArgs } from "./redaction.js";
export type { IncludeArgs } from "./redaction.js";
export { AUDIT_SCHEMA_VERSION } from "./types.js";
export type {
  AuditEvent,
  AuditSink,
  AuditDecision,
  AuditOutcome,
  FrameworkMapping,
} from "./types.js";
