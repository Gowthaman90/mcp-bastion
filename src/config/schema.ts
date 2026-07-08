/**
 * Configuration schema for mcp-bastion, expressed as Zod schemas so that both
 * runtime validation and the static TypeScript types derive from a single source
 * of truth.
 *
 * @packageDocumentation
 */
import { z } from "zod";

/** A local upstream launched as a subprocess and reached over stdio. */
export const StdioServerConfigSchema = z.object({
  /** Transport discriminator. Defaults to `stdio` so it may be omitted. */
  transport: z.literal("stdio").default("stdio"),
  /** Executable to launch (e.g. `npx`, `node`, an absolute path). */
  command: z.string().min(1),
  /** Arguments passed to `command`. */
  args: z.array(z.string()).default([]),
  /** Optional environment overrides, merged over the current process env. */
  env: z.record(z.string(), z.string()).optional(),
  /** Optional working directory for the spawned process. */
  cwd: z.string().optional(),
});
export type StdioServerConfig = z.infer<typeof StdioServerConfigSchema>;

/** A remote upstream reached over Streamable HTTP. */
export const HttpServerConfigSchema = z.object({
  transport: z.literal("http"),
  /** Base URL of the remote MCP endpoint. */
  url: z.string().url(),
  /** Optional headers sent on every request (e.g. `Authorization`). */
  headers: z.record(z.string(), z.string()).optional(),
});
export type HttpServerConfig = z.infer<typeof HttpServerConfigSchema>;

/**
 * A single upstream MCP server that Bastion proxies — either a local `stdio`
 * subprocess or a remote `http` endpoint. `transport` may be omitted for stdio.
 */
export const ServerConfigSchema = z.union([StdioServerConfigSchema, HttpServerConfigSchema]);
export type ServerConfig = z.infer<typeof ServerConfigSchema>;

/** Auto-reconnect behaviour applied to every upstream. */
export const ReconnectConfigSchema = z
  .object({
    /** Whether to automatically reconnect after an unexpected disconnect. */
    auto: z.boolean().default(true),
    /** Maximum reconnect attempts before giving up. Use `-1` for unlimited. */
    maxRetries: z.number().int().default(10),
    /** Initial backoff delay, in milliseconds (doubled each attempt). */
    initialBackoffMs: z.number().int().positive().default(500),
    /** Upper bound on the backoff delay, in milliseconds. */
    maxBackoffMs: z.number().int().positive().default(30_000),
  })
  .default({});
export type ReconnectConfig = z.infer<typeof ReconnectConfigSchema>;

/** Periodic liveness probing used to detect silent disconnects. */
export const HealthCheckConfigSchema = z
  .object({
    /** Whether periodic health checks are enabled. */
    enabled: z.boolean().default(true),
    /** Interval between health checks, in milliseconds. */
    intervalMs: z.number().int().positive().default(30_000),
    /** Per-probe timeout, in milliseconds. */
    timeoutMs: z.number().int().positive().default(5_000),
  })
  .default({});
export type HealthCheckConfig = z.infer<typeof HealthCheckConfigSchema>;

/** How upstream tool names are exposed to the client. */
export const NamespaceConfigSchema = z
  .object({
    /**
     * `prefix` (default) namespaces each tool as `<server><separator><tool>` to
     * prevent collisions and tool-shadowing. `passthrough` exposes tool names
     * unchanged (use only when servers are known not to collide).
     */
    strategy: z.enum(["prefix", "passthrough"]).default("prefix"),
    /** Separator used by the `prefix` strategy. */
    separator: z.string().min(1).default("__"),
  })
  .default({});
export type NamespaceConfig = z.infer<typeof NamespaceConfigSchema>;

/** Runtime security policy (v0.2). */
export const SecurityConfigSchema = z
  .object({
    /** Pin each tool's definition on first use and detect later changes ("rug pulls"). */
    pinTools: z.boolean().default(true),
    /** What to do when a tool's definition changed after approval. */
    onRugPull: z.enum(["block", "warn"]).default("block"),
    /** Run heuristic poisoning inspection on tool descriptions. */
    inspectDescriptions: z.boolean().default(true),
    /**
     * What to do when a description trips a high-severity poisoning heuristic.
     * Defaults to `warn` because heuristics can produce false positives.
     */
    onPoisoning: z.enum(["block", "warn"]).default("warn"),
  })
  .default({});
export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;

/** Where audit events are delivered. */
export const SinkConfigSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("console") }),
  z.object({ type: z.literal("file"), path: z.string().min(1) }),
  z.object({
    type: z.literal("webhook"),
    url: z.string().url(),
    batchSize: z.number().int().positive().default(20),
    timeoutMs: z.number().int().positive().default(5_000),
  }),
]);
export type SinkConfig = z.infer<typeof SinkConfigSchema>;

/** Audit & compliance policy (v0.3). Disabled by default. */
export const AuditConfigSchema = z
  .object({
    /** Emit an audit event for every tool call. */
    enabled: z.boolean().default(false),
    /** How tool arguments are recorded: not at all, redacted, or verbatim. */
    includeArgs: z.enum(["none", "redacted", "full"]).default("none"),
    /** Key names redacted when `includeArgs` is `redacted`. */
    redactKeys: z
      .array(z.string())
      .default(["password", "token", "secret", "apikey", "api_key", "authorization", "auth"]),
    /** Hash-chain events so tampering is detectable. */
    tamperEvident: z.boolean().default(false),
    /** Destinations for audit events. */
    sinks: z.array(SinkConfigSchema).default([{ type: "console" }]),
  })
  .default({});
export type AuditConfig = z.infer<typeof AuditConfigSchema>;

/** How Bastion exposes itself to clients: as a stdio subprocess or an HTTP server. */
export const ListenConfigSchema = z
  .object({
    /** `stdio` (default, spawned by the client) or `http` (Streamable HTTP server). */
    mode: z.enum(["stdio", "http"]).default("stdio"),
    /** Bind host for `http` mode. */
    host: z.string().default("127.0.0.1"),
    /** Bind port for `http` mode. */
    port: z.number().int().positive().default(3000),
    /** URL path the MCP endpoint is served at, for `http` mode. */
    path: z.string().default("/mcp"),
  })
  .default({});
export type ListenConfig = z.infer<typeof ListenConfigSchema>;

/** The complete, validated Bastion configuration. */
export const BastionConfigSchema = z.object({
  /** Map of upstream server name → server configuration. */
  servers: z.record(z.string(), ServerConfigSchema),
  reconnect: ReconnectConfigSchema,
  healthCheck: HealthCheckConfigSchema,
  namespace: NamespaceConfigSchema,
  security: SecurityConfigSchema,
  audit: AuditConfigSchema,
  listen: ListenConfigSchema,
});
export type BastionConfig = z.infer<typeof BastionConfigSchema>;
