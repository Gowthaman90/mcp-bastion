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
export { SecurityEngine, scanTool, hashToolDefinition } from "./security/index.js";
export type { Severity, SecurityFinding, PinStatus, ToolSecurityReport } from "./security/index.js";

// Audit & compliance
export {
  AuditEngine,
  createSinks,
  ConsoleSink,
  FileSink,
  WebhookSink,
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
} from "./audit/index.js";
export type { AuditConfig, SinkConfig } from "./config/index.js";

// Errors
export { BastionError, ConfigError, UpstreamDisconnectedError } from "./errors.js";

// Observability
export { logger } from "./observability/index.js";
