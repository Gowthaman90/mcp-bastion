/**
 * Public surface of the security layer.
 *
 * @packageDocumentation
 */
export { SecurityEngine } from "./engine.js";
export { runPipeline } from "./pipeline.js";
export { hashToolDefinition } from "./hashing.js";
export { scanText, scanTool, hasSeverityAtLeast } from "./poisoning.js";
export { normalizedViews, foldHomoglyphs, decodeBase64Segments } from "./normalize.js";
export { validateArguments } from "./schema.js";
export { scanToolSet } from "./correlation.js";
export { checkCommandInjection } from "./command-injection.js";
export { checkConfigDrift } from "./config-drift.js";
export { checkServerIdentity, hashServerIdentity } from "./identity.js";
export type { ServerIdentity } from "./identity.js";
export { scanCallSequence, extractSensitiveTokens, TaintTracker } from "./taint.js";
export type { SequencedCall } from "./taint.js";
export { redactSecrets } from "./dlp.js";
export { checkRequestedScopes } from "./scopes.js";
export { checkTransportSecurity, checkRequestOrigin } from "./transport.js";
export {
  checkHeaderBodyCoherence,
  decodeHeaderValue,
  requiresHeaderValidation,
  HEADER_VALIDATION_REVISION,
} from "./headers.js";
export type { HeaderBag, HeaderCheckContext } from "./headers.js";
export {
  checkCachePolicy,
  clampCacheHints,
  readCacheHints,
  DEFAULT_MAX_TTL_MS,
} from "./cache-policy.js";
export type {
  CacheScope,
  CacheHints,
  CachePolicyContext,
  ClampedCacheHints,
} from "./cache-policy.js";
export { checkInputRequests, isInputRequired, stripFlaggedInputRequests } from "./mrtr.js";
export {
  sealRequestState,
  openRequestState,
  isSealedRequestState,
  generateRequestStateKey,
  DEFAULT_REQUEST_STATE_TTL_SECONDS,
} from "./request-state.js";
export type {
  OpenResult,
  SealOptions,
  OpenOptions,
  RequestStateBinding,
  SealedPayload,
} from "./request-state.js";
export type { ToolCallOutcome } from "./types.js";
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
