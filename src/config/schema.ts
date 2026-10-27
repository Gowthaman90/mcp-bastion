/**
 * Configuration schema for mcp-bastion, expressed as Zod schemas so that both
 * runtime validation and the static TypeScript types derive from a single source
 * of truth.
 *
 * @packageDocumentation
 */
import { z } from "zod";

import { isValidToolPattern, patternReachesPrefix } from "../security/authorization.js";
import { checkTransportSecurity } from "../security/transport.js";

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
  /**
   * Protocol era negotiation with this upstream: `auto` probes `server/discover` (MCP 2026-07-28)
   * and falls back to the legacy `initialize` handshake; `legacy` skips the probe; `2026-07-28`
   * pins the modern era and never falls back.
   */
  protocol: z.enum(["auto", "legacy", "2026-07-28"]).default("auto"),
});
export type StdioServerConfig = z.infer<typeof StdioServerConfigSchema>;

/** An HTTP field name (RFC 9110 `token`). */
const HeaderNameSchema = z
  .string()
  .regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/, { message: "must be a valid HTTP header name" });

/**
 * Hop-by-hop headers (RFC 9110 §7.6.1) and connection-level fields. They describe one connection,
 * not the request, so they are never forwarded in either direction.
 */
export const HOP_BY_HOP_HEADERS: ReadonlySet<string> = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

/**
 * Upstream header names the MCP transport itself sets. Forwarding a caller's value onto one of these
 * would let a downstream request rewrite the protocol framing, so they cannot be forward targets.
 */
const TRANSPORT_OWNED_HEADERS: ReadonlySet<string> = new Set([
  "content-type",
  "accept",
  "last-event-id",
  "mcp-session-id",
  "mcp-protocol-version",
  "mcp-method",
  "mcp-name",
]);

/**
 * Keyless delegation checks for one upstream (gateway mode): which forwarded header carries the
 * caller's delegate JWT, and the claims policy Bastion applies to it before anything is sent.
 * Bastion holds no secret: in `structural` mode it decodes and checks the claims, it does not
 * verify the signature (the upstream remains the authenticator).
 */
/** Asymmetric JWS algorithms accepted in signature mode (exact, case-sensitive names). */
export const DELEGATION_SIGNATURE_ALGORITHMS = [
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
  "Ed25519",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
] as const;

/** JWK members that only a private or symmetric key carries. A trusted key set must hold none. */
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/** A public JWK set (RFC 7517 §5), as embedded in config. */
const PublicJwksSchema = z.object({
  keys: z
    .array(z.looseObject({ kty: z.string().min(1) }))
    .nonempty()
    .superRefine((keys, ctx) => {
      keys.forEach((key, i) => {
        const secret = PRIVATE_JWK_MEMBERS.filter((m) => m in key);
        if (secret.length > 0) {
          ctx.addIssue({
            code: "custom",
            path: [i],
            message: `JWK carries private or secret member(s) ${secret.join(", ")}: only public keys may be configured`,
          });
        }
      });
    }),
});

export const DelegationServerConfigSchema = z
  .strictObject({
    /**
     * The `forwardHeaders` key (upstream header name) whose value is the delegate token. Defaults to
     * the only `forwardHeaders` key; required when there are several.
     */
    header: HeaderNameSchema.optional(),
    /** The audience this upstream's tokens must carry (exact, case-sensitive). Required. */
    audience: z.string().min(1),
    /**
     * `structural` (the default) checks claims without verifying the signature. `signature` also
     * verifies the signature against a public key set (`jwksUrl` or inline `jwks`), with an
     * algorithm allow-list and an expected issuer. Either way Bastion holds no secret.
     */
    verify: z.enum(["structural", "signature"]).default("structural"),
    /** Signature mode: the expected `iss` (exact). */
    issuer: z.string().min(1).optional(),
    /**
     * Signature mode: accepted `alg` values (case-sensitive). HMAC (`HS256/384/512`) and `none` are
     * never accepted: they would need a shared secret, or no key at all.
     */
    algorithms: z
      .array(
        z.string().superRefine((alg, ctx) => {
          if (/^(hs(256|384|512)|none)$/i.test(alg)) {
            ctx.addIssue({
              code: "custom",
              message: `algorithm "${alg}" is never accepted: signature mode verifies with public keys only`,
            });
          } else if (!(DELEGATION_SIGNATURE_ALGORITHMS as readonly string[]).includes(alg)) {
            ctx.addIssue({
              code: "custom",
              message: `unsupported algorithm "${alg}" (use one of ${DELEGATION_SIGNATURE_ALGORITHMS.join(", ")})`,
            });
          }
        }),
      )
      .nonempty()
      .optional(),
    /** Signature mode: where to fetch the issuer's public JWK set (HTTPS, except loopback). */
    jwksUrl: z.string().url().optional(),
    /** Signature mode: the issuer's public JWK set, inline (no private members allowed). */
    jwks: PublicJwksSchema.optional(),
    /** Longest accepted token lifetime (`exp` − `iat`), in seconds. */
    maxLifetimeSeconds: z.number().int().positive().default(3600),
    /** Clock tolerance applied to `exp` and `nbf`, in seconds. */
    clockSkewSeconds: z.number().int().nonnegative().max(300).default(30),
    /**
     * Agents allowed to act for the user: the current actor (`act.sub`, else `act.client_id`) must be
     * one of these. Unset = any actor.
     */
    allowedActors: z.array(z.string().min(1)).nonempty().optional(),
    /** Require an `act` claim (a token the user's own client presents directly is then refused). */
    requireActor: z.boolean().default(false),
    /** Longest accepted actor chain (current actor plus nested prior actors). Unset = no limit. */
    maxChainDepth: z.number().int().positive().optional(),
  })
  .superRefine((cfg, ctx) => {
    const signatureOnly = (["issuer", "algorithms", "jwksUrl", "jwks"] as const).filter(
      (k) => cfg[k] !== undefined,
    );
    if (cfg.verify !== "signature") {
      for (const key of signatureOnly) {
        ctx.addIssue({
          code: "custom",
          path: [key],
          message: `"${key}" is only valid with verify: "signature"`,
        });
      }
      return;
    }
    if (cfg.issuer === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["issuer"],
        message: 'verify "signature" needs issuer',
      });
    }
    if (cfg.algorithms === undefined) {
      ctx.addIssue({
        code: "custom",
        path: ["algorithms"],
        message: 'verify "signature" needs a non-empty algorithms list',
      });
    }
    if ((cfg.jwksUrl === undefined) === (cfg.jwks === undefined)) {
      ctx.addIssue({
        code: "custom",
        path: ["jwksUrl"],
        message: 'verify "signature" needs exactly one key source: jwksUrl or jwks',
      });
    }
    if (cfg.jwksUrl !== undefined) {
      if (!/^https?:\/\//i.test(cfg.jwksUrl)) {
        ctx.addIssue({ code: "custom", path: ["jwksUrl"], message: "jwksUrl must be http(s)" });
      } else if (checkTransportSecurity(cfg.jwksUrl).length > 0) {
        ctx.addIssue({
          code: "custom",
          path: ["jwksUrl"],
          message: "jwksUrl must use HTTPS (plaintext HTTP is allowed only to a loopback host)",
        });
      }
    }
  });
export type DelegationServerConfig = z.infer<typeof DelegationServerConfigSchema>;

/** A remote upstream reached over Streamable HTTP. */
export const HttpServerConfigSchema = z
  .object({
    transport: z.literal("http"),
    /** Base URL of the remote MCP endpoint. */
    url: z.string().url(),
    /** Optional headers sent on every request (e.g. `Authorization`). */
    headers: z.record(z.string(), z.string()).optional(),
    /** Protocol era negotiation (see the stdio variant). */
    protocol: z.enum(["auto", "legacy", "2026-07-28"]).default("auto"),
    /**
     * Per-request header forwarding (gateway mode): upstream header name → incoming (downstream)
     * header name. On every upstream request made while serving a downstream HTTP request, the
     * incoming header's value is sent under the upstream name. Only listed headers are forwarded;
     * a forwarded header overrides a static `headers` entry of the same name. Requires
     * `listen.mode: "http"`.
     */
    forwardHeaders: z.record(HeaderNameSchema, HeaderNameSchema).optional(),
    /**
     * What to do when a downstream request lacks a header named in `forwardHeaders`: `error` (the
     * default) answers with a tool error and never calls the upstream; `omit` calls it without.
     */
    onMissingForwardedHeader: z.enum(["error", "omit"]).default("error"),
    /**
     * `startup` (the default) connects at boot. `onDemand` connects on the first downstream request
     * that needs this upstream, carrying that request's forwarded headers — for upstreams that
     * authenticate every request, including `initialize`, as the calling user.
     */
    connect: z.enum(["startup", "onDemand"]).default("startup"),
    /**
     * Extra header names that count as authentication for `bastion__status` and cache policy, on top
     * of the standard ones (`Authorization`, `X-API-Key`, …). `forwardHeaders` keys always count.
     */
    authHeaders: z.array(HeaderNameSchema).optional(),
    /**
     * Keyless delegation checks on the delegate JWT carried in one of this upstream's
     * `forwardHeaders` (see {@link DelegationServerConfigSchema}). Requires `forwardHeaders`.
     */
    delegation: DelegationServerConfigSchema.optional(),
  })
  .superRefine((cfg, ctx) => {
    for (const [upstream, incoming] of Object.entries(cfg.forwardHeaders ?? {})) {
      const up = upstream.toLowerCase();
      if (HOP_BY_HOP_HEADERS.has(up) || TRANSPORT_OWNED_HEADERS.has(up)) {
        ctx.addIssue({
          code: "custom",
          path: ["forwardHeaders", upstream],
          message: `"${upstream}" cannot be a forwarded header: it is a hop-by-hop or transport-owned header`,
        });
      }
      if (HOP_BY_HOP_HEADERS.has(incoming.toLowerCase())) {
        ctx.addIssue({
          code: "custom",
          path: ["forwardHeaders", upstream],
          message: `"${incoming}" is a hop-by-hop header and is never forwarded`,
        });
      }
    }
    if (cfg.delegation) {
      const keys = Object.keys(cfg.forwardHeaders ?? {});
      if (keys.length === 0) {
        ctx.addIssue({
          code: "custom",
          path: ["delegation"],
          message:
            "delegation needs forwardHeaders: the delegate token is read from a forwarded header",
        });
      } else if (cfg.delegation.header === undefined && keys.length > 1) {
        ctx.addIssue({
          code: "custom",
          path: ["delegation", "header"],
          message: `delegation.header is required when forwardHeaders has several keys (${keys.join(", ")})`,
        });
      } else if (
        cfg.delegation.header !== undefined &&
        !keys.some((k) => k.toLowerCase() === cfg.delegation!.header!.toLowerCase())
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["delegation", "header"],
          message: `delegation.header "${cfg.delegation.header}" must be a forwardHeaders key (${keys.join(", ")})`,
        });
      }
    }
  });
export type HttpServerConfig = z.infer<typeof HttpServerConfigSchema>;

/** Keys that only make sense on an HTTP upstream (they act on per-request HTTP headers). */
const HTTP_ONLY_KEYS = [
  "forwardHeaders",
  "onMissingForwardedHeader",
  "connect",
  "authHeaders",
  "delegation",
];

/**
 * A single upstream MCP server that Bastion proxies — either a local `stdio`
 * subprocess or a remote `http` endpoint. `transport` may be omitted for stdio.
 *
 * The stdio variant would silently strip HTTP-only keys, so they are rejected up front with a
 * readable message instead.
 */
export const ServerConfigSchema = z.preprocess(
  (raw, ctx) => {
    if (raw && typeof raw === "object" && (raw as { transport?: unknown }).transport !== "http") {
      for (const key of HTTP_ONLY_KEYS) {
        if (key in raw) {
          ctx.addIssue({
            code: "custom",
            path: [key],
            message: `"${key}" is only valid on an HTTP upstream (transport: "http"); a stdio upstream has no per-request HTTP headers`,
            fatal: true,
          });
          return z.NEVER;
        }
      }
    }
    return raw;
  },
  z.union([StdioServerConfigSchema, HttpServerConfigSchema]),
);
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
  .prefault({});
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
  .prefault({});
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
  .prefault({});
export type NamespaceConfig = z.infer<typeof NamespaceConfigSchema>;

/** An on-detection action: block the call or warn only. */
const OnAction = z.enum(["block", "warn"]);

/**
 * Enforcement profiles resolve the individual `on*` actions as a group. `balanced` (the default)
 * blocks the deterministic, near-zero-false-positive checks (rug-pull, identity change, argument/
 * schema + command-injection, cross-server exfiltration) while only warning on the heuristic ones
 * (description poisoning, response-content heuristics). An explicit `on*` value always overrides the
 * profile.
 */
export const ENFORCEMENT_PROFILES = {
  observe: {
    onInputRequired: "warn",
    onRugPull: "warn",
    onPoisoning: "warn",
    onResponse: "warn",
    onSchemaViolation: "warn",
    onIdentityChange: "warn",
    onDataFlow: "warn",
    onDelegation: "warn",
    onDelegationChain: "warn",
    onAuthorization: "warn",
  },
  balanced: {
    onInputRequired: "block",
    onRugPull: "block",
    onPoisoning: "warn",
    onResponse: "warn",
    onSchemaViolation: "block",
    onIdentityChange: "block",
    onDataFlow: "block",
    onDelegation: "block",
    onDelegationChain: "warn",
    onAuthorization: "block",
  },
  strict: {
    onInputRequired: "block",
    onRugPull: "block",
    onPoisoning: "block",
    onResponse: "block",
    onSchemaViolation: "block",
    onIdentityChange: "block",
    onDataFlow: "block",
    onDelegation: "block",
    onDelegationChain: "block",
    onAuthorization: "block",
  },
} as const;

/** Runtime security policy (v0.2). */
export const SecurityConfigSchema = z
  .object({
    /** Pin each tool's definition on first use and detect later changes ("rug pulls"). */
    pinTools: z.boolean().default(true),
    /**
     * Enforcement posture: `observe` (warn on everything), `balanced` (block deterministic checks,
     * warn on heuristics — the default), or `strict` (block on any finding). Individual `on*` settings
     * override the profile.
     */
    enforcementProfile: z.enum(["observe", "balanced", "strict"]).default("balanced"),
    /** What to do when a tool's definition changed after approval. Defaults from the profile. */
    onRugPull: OnAction.optional(),
    /** Run heuristic poisoning inspection on tool descriptions. */
    inspectDescriptions: z.boolean().default(true),
    /**
     * Also run the heuristics over evasion-normalized views of scanned text (NFKC, homoglyph-folded,
     * base64-decoded), so a payload hidden behind Unicode look-alikes or base64 is still caught.
     */
    normalizeEvasion: z.boolean().default(true),
    /**
     * What to do when a description trips a high-severity poisoning heuristic. Defaults from the
     * profile (`warn` under `balanced`, since heuristics can produce false positives).
     */
    onPoisoning: OnAction.optional(),
    /**
     * Scan tool *results* (not just definitions) for injected instructions and
     * exfiltration signals — defends the response-handling stage, where a server can
     * smuggle a payload back through an otherwise-benign tool.
     */
    scanResponses: z.boolean().default(true),
    /**
     * What to do when a tool result trips a high-severity heuristic. Defaults from the profile
     * (`warn` under `balanced`), mirroring `onPoisoning`, since the same heuristics apply.
     */
    onResponse: OnAction.optional(),
    /**
     * Redact credential-shaped secret *values* (cloud keys, provider tokens, private-key blocks,
     * `NAME=secret` assignments) out of tool results inline — an enforcing mitigation that strips the
     * secret before the agent or any downstream log can see it. Independent of `onResponse`.
     */
    redactResponseSecrets: z.boolean().default(true),
    /**
     * Correlate a server's tools with each other to catch poisoning payloads split across
     * multiple tools to evade single-tool scanning (e.g. threshold "split-payload" poisoning).
     */
    correlateTools: z.boolean().default(true),
    /**
     * Validate each tool call's arguments against the tool's declared `inputSchema`
     * — flags undeclared parameters (smuggling) and type/enum violations (validation bypass).
     */
    validateArguments: z.boolean().default(true),
    /**
     * What to do on an argument/schema violation (also governs command-injection). Deterministic and
     * low-false-positive; defaults from the profile (`block` under `balanced`).
     */
    onSchemaViolation: OnAction.optional(),
    /**
     * Scan tool-call argument *values* for OS command-injection payloads (command substitution,
     * `; rm …`-style chaining, `/etc/passwd` reads) bound for exec-style tools. Surfaced through
     * the same argument-inspection path as schema validation and governed by `onSchemaViolation`.
     */
    detectCommandInjection: z.boolean().default(true),
    /**
     * Pin each server's effective configuration snapshot on first observation and flag
     * security-relevant *weakening* on later observations (TLS downgrade, host allowlist widened
     * with a wildcard, a protective flag disabled) — configuration drift.
     *
     * RESERVED — not yet enforced: the config snapshot is not wired into the connect path yet, so this
     * defaults OFF rather than imply a guarantee that is not active. Tracked for a future release.
     */
    detectConfigDrift: z.boolean().default(false),
    /**
     * Verify server identity and pin it (trust-on-first-use): flag a claimed identity with no
     * verified binding, and detect an endpoint/name/TLS-fingerprint change on a later connect
     * (server impersonation). Version/protocol changes do not trip the pin.
     *
     * RESERVED — not yet enforced: identity observation (incl. TLS fingerprinting) is not wired into
     * the connect path yet, so this defaults OFF rather than imply a guarantee that is not active.
     * Tracked for a future release.
     */
    pinServerIdentity: z.boolean().default(false),
    /**
     * What to do when a server's *pinned* identity changes mid-session. Defaults from the profile
     * (`block` under `balanced`), since a mid-session identity change is a strong impersonation signal.
     */
    onIdentityChange: OnAction.optional(),
    /**
     * Track sensitive data across servers: a credential-shaped token returned by one server and then
     * sent in an argument to a *different* server is flagged as a cross-server exfiltration — the leg
     * of a tool-transfer attack that only an aggregating proxy can see.
     */
    trackDataFlow: z.boolean().default(true),
    /**
     * What to do when cross-server data flow is detected. Defaults from the profile (`block` under
     * `balanced`), denying the outgoing call that would carry another server's data across the boundary.
     */
    onDataFlow: OnAction.optional(),
    /**
     * Ceiling (ms) applied to the `ttlMs` caching hint on upstream list results (MCP 2026-07-28).
     * The spec sets a floor of 0 but no ceiling, so a poisoned `tools/list` could otherwise be
     * pinned in caches indefinitely. Bastion never advertises a longer TTL than this downstream.
     */
    maxCacheTtlMs: z.number().int().nonnegative().default(3_600_000),
    /**
     * Inspect the embedded requests of an `input_required` (MRTR) result before relaying them to the
     * client: credential-shaped elicitations and server-supplied `systemPrompt`s are flagged.
     */
    inspectInputRequests: z.boolean().default(true),
    /** What to do on a high-severity MRTR finding. Defaults from the profile (`block` under `balanced`). */
    onInputRequired: OnAction.optional(),
    /**
     * Key for sealing `requestState` envelopes (HMAC-SHA256). Falls back to the
     * `MCP_BASTION_REQUEST_STATE_KEY` env var, then to a random per-process key (which is fine for a
     * single process; set it explicitly when running more than one replica).
     */
    requestStateKey: z.string().min(16).optional(),
    /** Lifetime of a sealed `requestState` envelope, in seconds. */
    requestStateTtlSeconds: z.number().int().positive().default(300),
    /**
     * What to do on a delegation finding (malformed token, wrong audience, passthrough, user mixing,
     * validity window, actor). Defaults from the profile (`block` under `balanced`).
     */
    onDelegation: OnAction.optional(),
    /**
     * What to do when a delegate token's prior-actor chain is too deep or cyclic. Prior actors are
     * informational (RFC 8693 §4.1), so this defaults to `warn` except under `strict`.
     */
    onDelegationChain: OnAction.optional(),
    /**
     * What to do when the `authorization` policy refuses a call. Deterministic, so it defaults to
     * `block` under `balanced` and `strict`; `observe` warns and records `wouldBlock`.
     */
    onAuthorization: OnAction.optional(),
  })
  .transform((cfg) => {
    const p = ENFORCEMENT_PROFILES[cfg.enforcementProfile];
    return {
      ...cfg,
      onRugPull: cfg.onRugPull ?? p.onRugPull,
      onPoisoning: cfg.onPoisoning ?? p.onPoisoning,
      onResponse: cfg.onResponse ?? p.onResponse,
      onSchemaViolation: cfg.onSchemaViolation ?? p.onSchemaViolation,
      onIdentityChange: cfg.onIdentityChange ?? p.onIdentityChange,
      onDataFlow: cfg.onDataFlow ?? p.onDataFlow,
      onInputRequired: cfg.onInputRequired ?? p.onInputRequired,
      onDelegation: cfg.onDelegation ?? p.onDelegation,
      onDelegationChain: cfg.onDelegationChain ?? p.onDelegationChain,
      onAuthorization: cfg.onAuthorization ?? p.onAuthorization,
    };
  })
  .prefault({});
export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;

/** Loopback hosts, to which plain-HTTP audit delivery is allowed. */
function isLoopbackUrlHost(url: string): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  return (
    host === "localhost" || host === "[::1]" || host === "::1" || /^127(\.\d{1,3}){3}$/.test(host)
  );
}

/** Options shared by the HTTP audit sinks (webhook, OTLP). */
const httpSinkFields = {
  /** Extra headers sent with each request, e.g. a static routing header. */
  headers: z.record(z.string(), z.string()).optional(),
  /**
   * Header name → environment variable holding its value, e.g.
   * `{ "authorization": "AUDIT_WEBHOOK_TOKEN" }`, so secrets stay out of the config file. A missing
   * variable stops Bastion at startup.
   */
  headersEnv: z.record(z.string(), z.string().min(1)).optional(),
  batchSize: z.number().int().positive().default(20),
  timeoutMs: z.number().int().positive().default(5_000),
  /** Most events held while the receiver is unreachable; the oldest are dropped (and counted) beyond it. */
  maxQueue: z.number().int().positive().default(10_000),
  /**
   * Allow plain `http://` to a non-loopback host. Off by default: audit events carry tool names,
   * decisions and possibly arguments, and travel to a SIEM in clear text otherwise. Logs a warning.
   */
  allowInsecureTransport: z.boolean().default(false),
};

/** Remote audit delivery must be HTTPS unless the host is loopback or the sink opts out. */
function requireHttps(field: "url" | "endpoint") {
  return (cfg: Record<string, unknown>, ctx: z.RefinementCtx) => {
    const target = String(cfg[field]);
    if (
      /^http:/i.test(target) &&
      !isLoopbackUrlHost(target) &&
      cfg.allowInsecureTransport !== true
    ) {
      ctx.addIssue({
        code: "custom",
        path: [field],
        message: `${field} must use HTTPS for a non-loopback host (audit events would travel in clear text); set allowInsecureTransport: true on this sink to accept that`,
      });
    }
  };
}

/** Where audit events are delivered. */
export const SinkConfigSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("console") }),
  z.object({ type: z.literal("file"), path: z.string().min(1) }),
  z
    .object({ type: z.literal("webhook"), url: z.string().url(), ...httpSinkFields })
    .superRefine(requireHttps("url")),
  z
    .object({
      type: z.literal("otlp"),
      /** Base OTLP/HTTP endpoint, e.g. `http://localhost:4318` (the `/v1/logs` path is appended). */
      endpoint: z.string().url(),
      ...httpSinkFields,
      batchSize: z.number().int().positive().default(50),
    })
    .superRefine(requireHttps("endpoint")),
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
    /**
     * Optional secret that keys the integrity hash chain (HMAC-SHA256). Provide it
     * out-of-band (e.g. an env var) so a party who can rewrite the log file cannot
     * forge a valid chain. Falls back to the `MCP_BASTION_AUDIT_KEY` env var.
     * Unset → an unkeyed SHA-256 chain (detects only naive corruption).
     */
    integrityKey: z.string().optional(),
    /** Destinations for audit events. */
    sinks: z.array(SinkConfigSchema).default([{ type: "console" }]),
    /**
     * What happens to tool calls when NO configured sink can deliver (every sink unhealthy):
     * `continue` (default) keeps serving; `block` refuses calls (`blocked_audit_unavailable`) until a
     * sink recovers, for deployments where an unaudited call is not acceptable.
     */
    onSinkFailure: z.enum(["continue", "block"]).default("continue"),
  })
  .prefault({});
export type AuditConfig = z.infer<typeof AuditConfigSchema>;

/**
 * Client names Bastion assigns itself: `default` (the `listen.authToken` bearer), `stdio` (a local
 * stdio client) and `anonymous` (an unauthenticated loopback HTTP request).
 */
export const RESERVED_CLIENT_NAMES: ReadonlySet<string> = new Set([
  "default",
  "stdio",
  "anonymous",
]);

/** A named HTTP client (`listen.clients` key). */
const ClientNameSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*$/, {
    message: "client names use letters, digits, '.', '_' and '-' (starting with a letter or digit)",
  })
  .refine((name) => !RESERVED_CLIENT_NAMES.has(name), {
    message: 'client names "default", "stdio" and "anonymous" are reserved',
  });

/** One named HTTP client. The token itself never appears in the config file. */
const ListenClientSchema = z.strictObject({
  /** Environment variable holding this client's bearer token (read once at startup). */
  tokenEnv: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/, {
    message: "tokenEnv must be an environment variable name",
  }),
});

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
    /**
     * Bearer token required on every HTTP request (constant-time compared). Strongly
     * recommended, and REQUIRED when `host` is not loopback — the server refuses to
     * start on a non-loopback bind without it.
     */
    authToken: z.string().optional(),
    /** Max concurrent HTTP sessions before new `initialize` requests are refused. */
    maxSessions: z.number().int().positive().default(256),
    /** Max request body size in bytes before a 413. */
    maxBodyBytes: z.number().int().positive().default(1_048_576),
    /**
     * Validate the mirrored routing headers (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`,
     * `Mcp-Param-*`) against the JSON-RPC body and reject a disagreement with `-32020`
     * (HeaderMismatch), as the 2026-07-28 revision requires. Pre-revision clients that send no
     * routing headers are never affected.
     */
    validateRoutingHeaders: z.boolean().default(true),
    /**
     * How pre-2026-07-28 clients are treated: `stateless` serves them (the default: every request is
     * independent, no `Mcp-Session-Id`, GET/DELETE answered 405); `reject` refuses the older era
     * outright (`-32022`), which is the downgrade-prevention posture.
     */
    legacy: z.enum(["stateless", "reject"]).default("stateless"),
    /**
     * Named HTTP clients, each with its own bearer token read from an environment variable at
     * startup: `{ "cs-spire": { "tokenEnv": "BASTION_TOKEN_CS_SPIRE" } }`. A request presenting a
     * client's token acts as `client:<name>`, which `authorization` rules can name. May be combined
     * with `authToken` (that token is the client `default`).
     */
    clients: z.record(ClientNameSchema, ListenClientSchema).optional(),
  })
  .prefault({});
export type ListenConfig = z.infer<typeof ListenConfigSchema>;

/** Request-wide delegation settings, shared by every upstream with a `delegation` block. */
export const DelegationConfigSchema = z
  .strictObject({
    /**
     * Audiences that identify Bastion itself. A delegate token for one of these (or with no `aud`)
     * must never be relayed upstream: that is token passthrough.
     */
    gatewayAudiences: z.array(z.string().min(1)).default([]),
    /** All delegate tokens in one request must name the same user (`iss` + `sub`). */
    oneUserPerRequest: z.boolean().default(true),
    /**
     * How the audit record names the user: `hash` (default) records an HMAC-SHA256 pseudonym of
     * `iss|sub`; `plain` records `sub` as is.
     */
    recordSubject: z.enum(["hash", "plain"]).default("hash"),
    /**
     * Key for the subject pseudonym. Falls back to `MCP_BASTION_SUBJECT_KEY`, then the audit
     * integrity key, then a random per-process key (pseudonyms then do not link across restarts).
     */
    subjectKey: z.string().min(16).optional(),
  })
  .prefault({});
export type DelegationConfig = z.infer<typeof DelegationConfigSchema>;

/** A JSON scalar an `equals` / `in` constraint compares against. */
const AuthorizationScalarSchema = z.union([z.string(), z.number(), z.boolean()]);

/** Constraints on one top-level argument (all listed constraints must hold). */
const ArgumentConstraintSchema = z
  .strictObject({
    /** Exactly equal (no case folding, no Unicode normalisation, no type coercion). */
    equals: AuthorizationScalarSchema.optional(),
    /** Exactly equal to one of these. */
    in: z.array(AuthorizationScalarSchema).nonempty().optional(),
    /** A JSON number no greater than this (a numeric string fails). */
    max: z.number().optional(),
    /** A JSON number no smaller than this (a numeric string fails). */
    min: z.number().optional(),
    /**
     * An absolute POSIX path that, after resolving `.` and `..`, is this base or lies below it at a
     * `/` boundary.
     */
    pathWithin: z.string().optional(),
  })
  .superRefine((c, ctx) => {
    if (Object.values(c).every((v) => v === undefined)) {
      ctx.addIssue({
        code: "custom",
        message: "an argument constraint needs at least one of equals, in, max, min, pathWithin",
      });
    }
    if (c.min !== undefined && c.max !== undefined && c.min > c.max) {
      ctx.addIssue({ code: "custom", path: ["min"], message: "min is greater than max" });
    }
    if (
      c.pathWithin !== undefined &&
      (!c.pathWithin.startsWith("/") || c.pathWithin.includes("\0"))
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["pathWithin"],
        message: "pathWithin must be an absolute POSIX path without NUL",
      });
    }
  });

/** One identity name, or several (any of them). */
const PrincipalNamesSchema = z.union([z.string().min(1), z.array(z.string().min(1)).nonempty()]);

/**
 * Who a rule applies to: `"*"` (every identity) or exactly one identity kind: `client` (a
 * `listen.clients` name, or `default` / `stdio` / `anonymous`), `user` (a trusted delegate token's
 * `sub`) or `agent` (that token's current actor, `act.sub` else `act.client_id`).
 */
const RulePrincipalSchema = z.union([
  z.literal("*"),
  z
    .strictObject({
      client: PrincipalNamesSchema.optional(),
      user: PrincipalNamesSchema.optional(),
      agent: PrincipalNamesSchema.optional(),
    })
    .refine((p) => Object.values(p).filter((v) => v !== undefined).length === 1, {
      message: 'a principal names exactly one of client, user, agent (or is "*")',
    }),
]);

/** One authorization rule. */
const AuthorizationRuleSchema = z.strictObject({
  /** Stable id for audit events and refusal messages. Defaults to `rule-<n>` (1-based). */
  id: z.string().min(1).optional(),
  effect: z.enum(["allow", "deny"]),
  principal: RulePrincipalSchema,
  /** Namespaced tool names: exact, or one trailing `*` as a prefix match (`"ci__*"`, `"*"`). */
  tools: z
    .array(
      z.string().refine(isValidToolPattern, {
        message: 'tool patterns are exact names or end in a single "*" (no other wildcard)',
      }),
    )
    .nonempty(),
  /** Constraints on top-level arguments; all must hold for the rule to match. */
  args: z.record(z.string().min(1), ArgumentConstraintSchema).optional(),
});

/**
 * Runtime authorization (inactive unless `enabled`). Every authenticated identity a call carries
 * (client, user, agent) must be permitted; a matching deny overrides any allow.
 */
export const AuthorizationConfigSchema = z
  .strictObject({
    enabled: z.boolean().default(false),
    /** For an identity with no allow rule for the tool: `deny` (default) or `allow`. */
    default: z.enum(["deny", "allow"]).default("deny"),
    /**
     * Let `user` / `agent` rules use claims from upstreams in structural delegation mode, whose
     * signatures Bastion does not verify. Safe only when the upstream verifies the same token.
     */
    trustStructuralClaims: z.boolean().default(false),
    rules: z.array(AuthorizationRuleSchema).default([]),
  })
  .superRefine((cfg, ctx) => {
    const seen = new Set<string>();
    cfg.rules.forEach((rule, i) => {
      const id = rule.id ?? `rule-${i + 1}`;
      if (seen.has(id)) {
        ctx.addIssue({
          code: "custom",
          path: ["rules", i, "id"],
          message: `duplicate rule id "${id}"`,
        });
      }
      seen.add(id);
    });
  })
  .transform((cfg) => ({
    ...cfg,
    rules: cfg.rules.map((rule, i) => ({ ...rule, id: rule.id ?? `rule-${i + 1}` })),
  }))
  .prefault({});
export type AuthorizationConfig = z.infer<typeof AuthorizationConfigSchema>;

/** The complete, validated Bastion configuration. */
export const BastionConfigSchema = z
  .object({
    /** Map of upstream server name → server configuration. */
    servers: z.record(z.string(), ServerConfigSchema),
    reconnect: ReconnectConfigSchema,
    healthCheck: HealthCheckConfigSchema,
    namespace: NamespaceConfigSchema,
    security: SecurityConfigSchema,
    audit: AuditConfigSchema,
    listen: ListenConfigSchema,
    delegation: DelegationConfigSchema,
    authorization: AuthorizationConfigSchema,
  })
  .superRefine((cfg, ctx) => {
    for (const [name, server] of Object.entries(cfg.servers)) {
      if (server.transport !== "http" || !server.forwardHeaders) continue;
      if (Object.keys(server.forwardHeaders).length === 0) continue;
      if (cfg.listen.mode !== "http") {
        ctx.addIssue({
          code: "custom",
          path: ["servers", name, "forwardHeaders"],
          message: `forwardHeaders needs listen.mode "http": Bastion can only forward headers that arrive on a downstream HTTP request`,
        });
      }
      // The front-door bearer is Bastion's own credential, not the caller's; never pass it on.
      const incoming = Object.values(server.forwardHeaders).map((h) => h.toLowerCase());
      if ((cfg.listen.authToken || cfg.listen.clients) && incoming.includes("authorization")) {
        ctx.addIssue({
          code: "custom",
          path: ["servers", name, "forwardHeaders"],
          message: `cannot forward the incoming "authorization" header while listen.authToken or listen.clients is set: it carries Bastion's own bearer token`,
        });
      }
    }
    // Each upstream's audience must be its own: a shared audience would let one upstream's token be
    // routed to the other undetected, and a gateway audience would make passthrough look legitimate.
    const audienceOwner = new Map<string, string>();
    for (const [name, server] of Object.entries(cfg.servers)) {
      if (server.transport !== "http" || !server.delegation) continue;
      const { audience } = server.delegation;
      const owner = audienceOwner.get(audience);
      if (owner !== undefined) {
        ctx.addIssue({
          code: "custom",
          path: ["servers", name, "delegation", "audience"],
          message: `delegation audience "${audience}" is already used by "${owner}": each upstream needs its own audience`,
        });
      } else {
        audienceOwner.set(audience, name);
      }
      if (cfg.delegation.gatewayAudiences.includes(audience)) {
        ctx.addIssue({
          code: "custom",
          path: ["servers", name, "delegation", "audience"],
          message: `delegation audience "${audience}" is listed in delegation.gatewayAudiences: an upstream audience cannot also identify Bastion`,
        });
      }
    }
    checkAuthorizationReferences(cfg, ctx);
  });
export type BastionConfig = z.infer<typeof BastionConfigSchema>;

/**
 * Cross-section checks on `authorization`: every `client` a rule names exists, and no `user` /
 * `agent` rule can act on an upstream whose delegation claims are unverified (structural mode)
 * unless `trustStructuralClaims` says so.
 */
function checkAuthorizationReferences(
  cfg: {
    servers: Record<string, ServerConfig>;
    namespace: NamespaceConfig;
    listen: ListenConfig;
    authorization: AuthorizationConfig;
  },
  ctx: z.RefinementCtx,
): void {
  const authz = cfg.authorization;
  if (authz.enabled && "bastion" in cfg.servers) {
    ctx.addIssue({
      code: "custom",
      path: ["servers", "bastion"],
      message:
        'the server name "bastion" is reserved while authorization is enabled: control tools are authorized under it',
    });
  }
  const clients = new Set<string>([
    "stdio",
    "anonymous",
    ...(cfg.listen.authToken ? ["default"] : []),
    ...Object.keys(cfg.listen.clients ?? {}),
  ]);
  const structural = Object.entries(cfg.servers)
    .filter(([, s]) => s.transport === "http" && s.delegation?.verify === "structural")
    .map(([name]) => name);
  authz.rules.forEach((rule, i) => {
    if (rule.principal === "*") return;
    const named = rule.principal.client;
    for (const client of named === undefined ? [] : typeof named === "string" ? [named] : named) {
      if (!clients.has(client)) {
        ctx.addIssue({
          code: "custom",
          path: ["authorization", "rules", i, "principal", "client"],
          message: `unknown client "${client}": define it in listen.clients (or use default, stdio, anonymous)`,
        });
      }
    }
    if (authz.trustStructuralClaims) return;
    if (rule.principal.user === undefined && rule.principal.agent === undefined) return;
    for (const server of structural) {
      const prefix = server + cfg.namespace.separator;
      if (!rule.tools.some((p) => patternReachesPrefix(p, prefix))) continue;
      ctx.addIssue({
        code: "custom",
        path: ["authorization", "rules", i, "principal"],
        message:
          `rule "${rule.id}" names a user or agent and can match tools of "${server}", whose ` +
          `delegation tokens are not signature-verified (verify: "structural"). Use verify: ` +
          `"signature" there, or set authorization.trustStructuralClaims: true if "${server}" ` +
          `verifies the same token itself.`,
      });
    }
  });
}
