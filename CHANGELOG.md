# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/mcp-bastion/mcp-bastion/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mcp-bastion/mcp-bastion/releases/tag/v0.1.0
