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
} from "./schema.js";
