/**
 * Public surface of the security layer.
 *
 * @packageDocumentation
 */
export { SecurityEngine } from "./engine.js";
export { runPipeline } from "./pipeline.js";
export { hashToolDefinition } from "./hashing.js";
export { scanText, scanTool, hasSeverityAtLeast } from "./poisoning.js";
export { validateArguments } from "./schema.js";
export { scanToolSet } from "./correlation.js";
export { checkCommandInjection } from "./command-injection.js";
export { checkConfigDrift } from "./config-drift.js";
export { checkServerIdentity, hashServerIdentity } from "./identity.js";
export type { ServerIdentity } from "./identity.js";
export { scanCallSequence, extractSensitiveTokens, TaintTracker } from "./taint.js";
export type { SequencedCall } from "./taint.js";
export { checkRequestedScopes } from "./scopes.js";
export { checkTransportSecurity, checkRequestOrigin } from "./transport.js";
export { ToolRegistry } from "./tool-registry.js";
export type { ObserveOptions } from "./tool-registry.js";
export type {
  Severity,
  SecurityFinding,
  PinStatus,
  ToolSecurityReport,
  ToolCallContext,
  Interceptor,
  NextFn,
} from "./types.js";
