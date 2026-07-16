# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-07-15

A "depth" release: not more vectors, but stronger defense of the ones already covered — surviving
evasion, blocking (not just warning) the high-confidence attacks, and stripping leaked secrets.
Measured coverage rises from 38%/48% to **63% (15.0/24)** at zero false positives, and evasion
robustness from 1/3 to **3/3**.

### Changed

- **BREAKING (default posture): new `security.enforcementProfile`, default `balanced`.** The profile
  resolves the individual `on*` actions as a group. Under `balanced`, the deterministic,
  near-zero-false-positive checks now **block by default** — argument/schema violations and
  command-injection (`onSchemaViolation`) and cross-server data-flow (`onDataFlow`) — joining rug-pull
  and identity-change, which already blocked. Heuristic checks (description poisoning `onPoisoning`,
  response-content `onResponse`) still only **warn**. Set `enforcementProfile: "observe"` to restore
  the previous warn-on-everything behavior, or set any individual `on*` value to override the profile.
  `strict` blocks on any finding.

### Added

- **Evasion normalization** — heuristics now run over normalized _views_ of scanned text (NFKC,
  homoglyph-folded, base64-decoded), so a payload hidden behind Unicode look-alikes or base64 is
  caught the same as its plain form. Config `security.normalizeEvasion` (default true). New exports
  `normalizedViews` / `foldHomoglyphs` / `decodeBase64Segments`. (Evasion robustness 1/3 → 3/3.)
- **Inline DLP redaction** — credential-shaped secret _values_ (cloud keys, provider tokens,
  private-key blocks, `NAME=secret` assignments) are stripped from tool results inline — an enforcing
  mitigation that removes the secret before the agent or any log sees it. Config
  `security.redactResponseSecrets` (default true). New export `redactSecrets`.

### CI

- **Benchmark regression gate** (`.github/workflows/bench.yml`) — runs the vendor-neutral
  mcp-defense-bench against each build and fails if measured coverage drops below the floor or any
  false positive appears.

## [0.5.0] - 2026-07-15

### Added

Four new checks that each close an attack vector the mcp-defense-bench leaderboard showed **no
measured tool covering**, taking bastion's measured coverage from 38% to **48% (11.5/24 vectors)** at
zero false positives:

- **Cross-server data-flow (taint) tracking** — a credential-shaped token returned by one server and
  then sent in an argument to a _different_ server is flagged as cross-server exfiltration (the
  tool-transfer leg only an aggregating proxy can see). Exact-token propagation keeps false positives
  near zero. New exports `scanCallSequence` / `extractSensitiveTokens` / `TaintTracker`; config
  `security.trackDataFlow` (default true), `security.onDataFlow` (`warn`|`block`, default `warn`).
- **Server-identity pinning (TOFU)** — flags a claimed identity with no verified binding, and detects
  an endpoint/name/TLS-fingerprint change after first connect (server impersonation); a benign
  version bump does not trip it. Blocks by default on a changed pinned identity, mirroring rug-pull.
  New exports `checkServerIdentity` / `hashServerIdentity`; config `security.pinServerIdentity`
  (default true), `security.onIdentityChange` (`block`|`warn`, default `block`).
- **Command-injection argument scanning** — scans argument values for OS-command payloads (command
  substitution, `; rm …`-style chaining, `/etc/passwd` reads). Payload-shaped, not
  metacharacter-shaped, to avoid flagging benign text. New export `checkCommandInjection`; config
  `security.detectCommandInjection` (default true).
- **Configuration-drift detection** — pins a server's effective config snapshot (TOFU) and flags
  security-relevant _weakening_ (TLS downgrade, host allowlist widened with a wildcard, a protective
  flag disabled). New export `checkConfigDrift`; config `security.detectConfigDrift` (default true).

New audit decisions `blocked_identity` / `blocked_dataflow`, mapped to NIST MANAGE and OWASP
LLM02/LLM03/LLM06.

## [0.4.0] - 2026-07-14

### Added

- **Cross-tool correlation** — detects poisoning payloads _split across multiple tools_ to evade
  single-tool scanning (e.g. threshold "split-payload" poisoning such as ShareLock, arXiv:2606.27027).
  Because bastion observes a server's whole tool set, it scans the combined descriptions and flags
  coordinated `share`/`checksum`/`tool_id`-style staging metadata across tools. Config:
  `security.correlateTools` (default true). New exported helper `scanToolSet`; findings surface via
  `SecurityEngine.crossToolStatus()`. This is a heuristic for the staging pattern, not a cryptographic
  defeat of secret-sharing.

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

[Unreleased]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.3.1...v0.4.0
[0.2.0]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Gowthaman90/mcp-bastion/releases/tag/v0.1.0
