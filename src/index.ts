/**
 * Public library API for embedding mcp-bastion programmatically.
 *
 * The CLI is the primary interface; these exports let advanced users compose the
 * pieces themselves (e.g. building the proxy inside another process, or reusing
 * the config loader). Everything re-exported here is considered semver-stable.
 *
 * @packageDocumentation
 */

// Configuration
export { loadConfig, BastionConfigSchema } from "./config/index.js";
export type {
  BastionConfig,
  ServerConfig,
  StdioServerConfig,
  HttpServerConfig,
  ReconnectConfig,
  HealthCheckConfig,
  NamespaceConfig,
  SecurityConfig,
  ListenConfig,
  DelegationConfig,
  DelegationServerConfig,
} from "./config/index.js";

// Core domain
export {
  UpstreamManager,
  UpstreamConnection,
  BASTION_NAME,
  BASTION_VERSION,
} from "./core/index.js";
export type { ConnectionState, ServerStatus, ReconnectResult } from "./core/index.js";

// Proxy (client-facing server + Streamable HTTP listener)
export { buildBastionServer, startHttpServer } from "./proxy/index.js";
export type { HttpListener, HttpListenOptions } from "./proxy/index.js";

// Security (runtime tool pinning + poisoning inspection)
export {
  SecurityEngine,
  scanTool,
  scanText,
  scanToolSet,
  checkCommandInjection,
  checkConfigDrift,
  checkServerIdentity,
  hashServerIdentity,
  scanCallSequence,
  redactSecrets,
  normalizedViews,
  foldHomoglyphs,
  decodeBase64Segments,
  validateArguments,
  checkRequestedScopes,
  checkTransportSecurity,
  checkRequestOrigin,
  hashToolDefinition,
  // MCP 2026-07-28 (stateless-era) checks
  checkHeaderBodyCoherence,
  decodeHeaderValue,
  requiresHeaderValidation,
  HEADER_VALIDATION_REVISION,
  checkCachePolicy,
  clampCacheHints,
  readCacheHints,
  DEFAULT_MAX_TTL_MS,
  // v1.0 (MCP 2026-07-28, stateless era): MRTR gate + requestState custody
  checkInputRequests,
  isInputRequired,
  stripFlaggedInputRequests,
  sealRequestState,
  openRequestState,
  isSealedRequestState,
  generateRequestStateKey,
  DEFAULT_REQUEST_STATE_TTL_SECONDS,
  // v1.1: human-oversight gaps (false-error escalation; standing-grant check is inside checkInputRequests)
  checkErrorSteering,
  // Keyless delegation checks (structural mode)
  checkDelegation,
  checkDelegationAsync,
  delegationKeySet,
  decodeJwsCompact,
  subjectPseudonym,
} from "./security/index.js";
export type { OpenResult, SealOptions, OpenOptions, ToolCallOutcome } from "./security/index.js";
export type {
  CarriedHeaders,
  DelegationFinding,
  DelegationKeySet,
  DelegationKeySource,
  DelegationSignatureTrust,
  DelegationPolicy,
  DelegationResult,
  DelegationRule,
  DelegationTokenInfo,
  DelegationUpstreamPolicy,
} from "./security/index.js";
export type {
  HeaderBag,
  HeaderCheckContext,
  CacheScope,
  CacheHints,
  CachePolicyContext,
  ClampedCacheHints,
} from "./security/index.js";
export type { Severity, SecurityFinding, PinStatus, ToolSecurityReport } from "./security/index.js";

// Audit & compliance
export {
  AuditEngine,
  createSinks,
  ConsoleSink,
  FileSink,
  WebhookSink,
  OtlpSink,
  frameworksFor,
  buildComplianceReport,
  chainHash,
  verifyChain,
  AUDIT_SCHEMA_VERSION,
} from "./audit/index.js";
export type {
  AuditEvent,
  AuditSink,
  AuditDecision,
  AuditOutcome,
  FrameworkMapping,
  ComplianceReport,
  AuditDelegationRecord,
} from "./audit/index.js";
export type { AuditConfig, SinkConfig } from "./config/index.js";

// Errors
export {
  BastionError,
  ConfigError,
  UpstreamDisconnectedError,
  MissingForwardedHeaderError,
  DelegationBlockedError,
} from "./errors.js";

// Observability
export { logger } from "./observability/index.js";
