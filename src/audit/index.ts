/**
 * Public surface of the audit layer.
 *
 * @packageDocumentation
 */
export { AuditEngine } from "./engine.js";
export { createSinks, ConsoleSink, FileSink, WebhookSink, OtlpSink } from "./sinks/index.js";
export { frameworksFor, buildComplianceReport } from "./compliance.js";
export type { ComplianceReport } from "./compliance.js";
export { chainHash, verifyChain, argsDigest } from "./chain.js";
export {
  CheckpointSigner,
  generateCheckpointKeyPair,
  verifyCheckpoint,
  keyIdOf,
} from "./checkpoint.js";
export { verifyAuditLog, parseJsonl } from "./verify.js";
export type { VerifyReport, VerifyIssue, VerifyOptions, VerifyStatus } from "./verify.js";
export { prepareArgs } from "./redaction.js";
export type { IncludeArgs } from "./redaction.js";
export { AUDIT_SCHEMA_VERSION } from "./types.js";
export type {
  AuditEvent,
  AuditSink,
  AuditDecision,
  AuditOutcome,
  FrameworkMapping,
  AuditDelegationRecord,
  AuditAuthorizationRecord,
  AuditFinding,
  SinkHealth,
  AuditRecord,
  AuditRunStart,
  AuditCheckpoint,
} from "./types.js";
