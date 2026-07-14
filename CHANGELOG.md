# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-07-13

### Fixed

- **Reported version** — the CLI and MCP handshake now report the correct version (was pinned at an
  older value via a hardcoded constant). A test now asserts `BASTION_VERSION` matches `package.json`
  so it can't drift again.

## [0.3.0] - 2026-07-13

### Added

- **Response scanning** — tool _results_ (not just definitions) are scanned for injected instructions
  and exfiltration signals. Config: `security.scanResponses` (default true), `security.onResponse`
  (`warn`|`block`, default `warn`). Blocks/flags response-borne prompt injection, retrieval injection,
  and credential leakage.
- **Argument/schema validation** — each tool call's arguments are validated against the tool's declared
  `inputSchema`, flagging undeclared parameters (smuggling) and type/enum violations (validation
  bypass). Config: `security.validateArguments` (default true), `security.onSchemaViolation`
  (`warn`|`block`, default `warn`).
- **Transport hardening** — remote upstreams over plaintext HTTP are flagged (MITM exposure), and the
  client-facing HTTP listener rejects (403) a foreign `Origin` targeting a loopback bind (DNS-rebinding
  defense). New exported helpers `checkTransportSecurity` / `checkRequestOrigin`.
- **Argument content scanning** — tool-call argument _values_ are scanned for sensitive-source access
  (e.g. `~/.ssh/id_rsa`, `.env`) and exfiltration signals, catching the read leg of a cross-tool
  exfiltration.
- **Least-privilege scope check** — a tool advertising over-broad scopes (destructive/admin scopes, or
  mutating scopes on a read-only tool) is flagged. New exported helper `checkRequestedScopes`.
- New audit decisions `blocked_response` / `blocked_schema`, mapped to OWASP LLM05/LLM06.

_Measured coverage on the mcp-defense-bench 22-vector rubric rose from 18% to 34% (13/22 vectors), at
zero false positives — the realistic ceiling for a runtime proxy._

## [0.2.0] - 2026-07-08

### Added

- **OTLP audit sink** — export audit events as OpenTelemetry logs (OTLP/HTTP JSON) to an OpenTelemetry
  Collector, unlocking any downstream backend (SIEM, cloud logging, object storage). Configure with a
  sink of `{ "type": "otlp", "endpoint": "http://localhost:4318" }`.

## [0.1.0] - 2026-07-07

Initial public release. A client-agnostic reliability + security proxy for the Model Context Protocol,
spanning three layers plus dual transports.

### Reliability

- Client-agnostic proxy that aggregates multiple upstream MCP servers behind one endpoint, with
  per-server tool namespacing (`server__tool`) to prevent collisions and shadowing.
- Per-server health checks and capped exponential-backoff auto-reconnect.
- Control tools `bastion__status` and `bastion__reconnect`, letting the agent inspect connection
  health and recover a dropped server without human intervention.
- Legible, actionable error results when an upstream is unavailable (instead of opaque failures).

### Runtime security

- **Interceptor pipeline** — composable middleware around every tool call.
- **Tool-definition pinning / rug-pull detection** — pins each tool (trust-on-first-use) and flags any
  later change; `block` (default) or `warn`. `bastion__approve` clears a block after review.
- **Poisoning inspection** — heuristics over tool names/descriptions (instruction-override,
  secret-access, data-exfiltration, covert-instruction, embedded-directive, hidden/zero-width chars);
  `warn` (default) or `block`.
- **Cross-server shadowing** detection, surfaced via `bastion__security`.

### Audit & compliance

- Structured, versioned `AuditEvent` (schema v1) for every tool call — including blocked calls.
- **Pluggable sinks**: `console` (stderr JSONL), `file` (JSONL append), `webhook` (batched POST).
- **Compliance mapping** to NIST AI RMF functions and OWASP LLM Top 10, via `bastion__compliance`.
- **Tamper-evidence** (optional hash-chaining + offline `verifyChain`) and **redaction** of arguments.

### Transports

- **stdio** (default) and **Streamable HTTP** on both faces: proxy remote HTTP upstreams
  (`transport: "http"`), and/or serve Bastion over HTTP (`listen.mode: "http"` or `--http <port>`).
- HTTP upstreams without an auth header are flagged (`authenticated: false`) in `bastion__status`.

### Project

- Strict TypeScript, layered architecture (`config` / `core` / `security` / `audit` / `proxy` /
  `observability` / `internal`), ESLint + Prettier, unit + end-to-end tests, and CI.

[Unreleased]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Gowthaman90/mcp-bastion/releases/tag/v0.1.0
