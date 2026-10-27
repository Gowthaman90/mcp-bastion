/**
 * Public surface of the configuration layer.
 *
 * @packageDocumentation
 */
export { loadConfig, defaultConfig } from "./loader.js";
export {
  BastionConfigSchema,
  ServerConfigSchema,
  StdioServerConfigSchema,
  HttpServerConfigSchema,
  ReconnectConfigSchema,
  HealthCheckConfigSchema,
  NamespaceConfigSchema,
  SecurityConfigSchema,
  AuditConfigSchema,
  SinkConfigSchema,
  ListenConfigSchema,
  DelegationConfigSchema,
  DelegationServerConfigSchema,
  AuthorizationConfigSchema,
  RESERVED_CLIENT_NAMES,
} from "./schema.js";
export type {
  BastionConfig,
  ServerConfig,
  StdioServerConfig,
  HttpServerConfig,
  ReconnectConfig,
  HealthCheckConfig,
  NamespaceConfig,
  SecurityConfig,
  AuditConfig,
  SinkConfig,
  ListenConfig,
  DelegationConfig,
  DelegationServerConfig,
  AuthorizationConfig,
} from "./schema.js";
