# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-09-08

- Fix two unchecked type assertions in the new end-to-end test file that failed `tsc --noEmit` (and
  therefore CI) on 1.0.1. No functional change.

## [1.0.1] - 2026-09-08

- **Node >= 20 required** (the SDK 2.0 packages declare `engines.node >= 20`); `engines` and the CI matrix
  (20 / 22 / 24) updated. Formatting of the 1.0.0 sources normalised (the CI `format:check` step failed on
  1.0.0). No functional change.

## [1.0.0] - 2026-09-08

**The stateless-era release.** mcp-bastion now runs on the MCP TypeScript SDK **2.0** line
(`@modelcontextprotocol/server` / `client` / `core` / `node`), speaks both protocol eras from one
process, and adds the two defences that only a gateway can provide once the protocol has no sessions:
custody of `requestState`, and a consent gate on in-band `input_required` rounds. Every pre-existing
detection is unchanged (benchmark development coverage on the 24 original vectors is byte-identical).

### Changed — BREAKING

- **SDK 2.0.** `@modelcontextprotocol/sdk` (1.x) is no longer a runtime dependency. Types are re-exported
  from `@modelcontextprotocol/server`. Zod 4 is required (config schema unchanged for users).
- **HTTP listener is stateless.** Built on `createMcpHandler`: a fresh front-door server serves every
  request; there is no `Mcp-Session-Id`, GET/DELETE streams answer 405, `Last-Event-ID` is ignored.
  `listen.maxSessions` is accepted but has no effect. Pre-2026-07-28 clients are served statelessly by
  default (`listen.legacy: "stateless"`) or refused with `-32022` (`listen.legacy: "reject"`).
- **stdio entry uses `serveStdio`**, negotiating the era at connection open (`listen.legacy: "reject"`
  applies here too).

### Added

- **Dual-stack upstreams.** Each upstream negotiates its era: `servers.<name>.protocol` = `auto`
  (default: probe `server/discover`, fall back to `initialize`), `legacy`, or `2026-07-28` (pin, never
  fall back). `bastion__status` reports the negotiated era. Legacy `tools/list_changed` and modern
  change streams (`subscriptions/listen`) both trigger an immediate cache-bypassing re-list and re-hash.
- **`requestState` custody (MRTR).** An upstream's continuation state never reaches the model context.
  Bastion seals it in an HMAC-SHA256 envelope (`bst1.<payload>.<mac>`) bound to the calling principal
  (bearer-token hash or `stdio`), the upstream server, the tool, and a TTL; the retry is forwarded only
  after the envelope verifies. Tampered, replayed (other principal / other tool / expired) or raw
  upstream states are refused with an explicit reason. Config: `security.requestStateKey` (or
  `MCP_BASTION_REQUEST_STATE_KEY`; random per process if unset), `security.requestStateTtlSeconds` (300).
  Exports: `sealRequestState`, `openRequestState`, `isSealedRequestState`, `generateRequestStateKey`.
- **MRTR consent gate.** Every `input_required` round is inspected before relay: credential-shaped
  elicitations (field names or message text asking for passwords / API keys / tokens) and sampling
  requests whose `systemPrompt` or messages trip the response heuristics are high-severity findings —
  blocked under `balanced` (`security.onInputRequired`, default `block`), stripped from the round under
  `warn`. A clean server-supplied `systemPrompt` is permitted by the spec and is not a finding. Exports:
  `checkInputRequests`, `isInputRequired`, `stripFlaggedInputRequests`.
- **Cache hints per request.** Policed `ttlMs` / `cacheScope` are attached both to the `tools/list`
  result and to the per-request server's `cacheHints`.
- 21 new tests (`request-state`, `mrtr`, `stateless-era` end-to-end against an SDK 2.0 upstream and a
  1.x upstream from the same manager); suite 219/219.

### Measured (mcp-defense-bench v0.7.x)

On the 32-vector development corpus: **61% CorpusRobustCoverage (19.4/32), 0 false positives on
51 matched controls**, up from 52% at v0.9.0. On the eight vectors introduced by the 2026-07-28
revision: **77% (6.2/8)**, up from 44% — header/body desync 3/3, list-cache poisoning 3/3, MRTR input
phishing 2/2, requestState forgery 2/3 (the non-normative tool-state-handle case is a miss), transport
downgrade 1/1, roots-scope 1/1, task authorization 1/2 (the routing-desync variant; task methods are
not proxied). The 24 pre-existing vectors are unchanged (55% dev / 43% held-out), and the benign-corpus
false-positive rate is unchanged (13/337) — the gate's first cut flagged every server-supplied
`systemPrompt` and the benchmark's matched control caught that before release.

### Not yet

Tasks (`tasks/*`) are not proxied — the SDK answers `-32601` on the 2026-07-28 era and does not
intercept them on the legacy era; MCP Apps (`ui://`) are rendered by the host, not the proxy. Both stay
honest misses on the benchmark.

## [0.9.0] - 2026-09-05

"Stateless-era hardening", part 1. When the protocol is stateless, the gateway is the only component
that can still hold security state — so the two 2026-07-28 checks added (unwired) in the previous
cycle are now **enforced in the proxy path**. Detection for every pre-existing vector is untouched: the
new code runs only on requests that carry 2026-07-28 routing headers and on list results that carry
caching hints, neither of which a pre-revision client or server ever sends.

### Added

- **Header/body coherence is enforced on the HTTP listener.** Every POST is checked with
  `checkHeaderBodyCoherence` _before_ session handling; a `header-body-mismatch`, `header-invalid-value`
  or `header-duplicate-conflict` finding is rejected with HTTP 400 and JSON-RPC error **`-32020`
  (HeaderMismatch)**, echoing the request `id`. Medium-severity findings (unvalidated routing headers
  under an older revision, missing/unknown `Mcp-Param-*`) are logged. New config
  `listen.validateRoutingHeaders` (default `true`); `startHttpServer` option `validateRoutingHeaders`.
- **Cache policy is enforced on upstream list results.** `UpstreamConnection` now reads `ttlMs` /
  `cacheScope` off every `tools/list`, logs each `checkCachePolicy` violation, and retains a _clamped_
  copy; `UpstreamManager.listCacheHints()` folds them (shortest TTL, `private` if any upstream is) and
  Bastion's own `tools/list` forwards the policed hints. A poisoned list can therefore never be pinned
  downstream longer than `security.maxCacheTtlMs` (new, default 1 h), and an authenticated upstream's
  list is never advertised `public`. A `tools/list_changed` notification still re-lists immediately
  (since 0.7.0), which is the spec's invalidation rule — a stale cache can no longer hide a rug pull.
- 7 new tests (`test/spec-2026-07-28-wiring.test.ts`); suite 198/198.

### Previously (0.8.x, unreleased)

Two pure, zero-false-positive checks for the **2026-07-28 protocol revision**, which mirrors JSON-RPC
body fields into HTTP headers and makes list results cacheable. Both are exported from
`src/security/` and unit-tested in isolation.

- **Header/body coherence** (`checkHeaderBodyCoherence`, `src/security/headers.ts`). Compares
  `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*` against the request body — the
  desync the spec calls out, where "a load balancer routes on the header value while the MCP server
  executes based on the body value" and which servers must reject with `-32020` (`HeaderMismatch`).
  Decodes the `=?base64?…?=` sentinel before comparing, as the spec requires, so a mismatch cannot hide
  behind the encoding; resolves `Mcp-Param-*` through `x-mcp-header` annotations when a tool schema is
  supplied; validates `Mcp-Name` against `params.taskId` on the Tasks extension's methods; and
  implements the spec's note to intermediaries — routing headers carried under a revision that does not
  mandate validation are flagged rather than trusted. Pre-2026-07-28 clients are never required to send
  these headers and are never flagged for omitting them.
- **Cache policy** (`checkCachePolicy` / `clampCacheHints`, `src/security/cache-policy.ts`). Clamps
  `ttlMs` (the spec sets a floor of 0 but **no ceiling**, so an arbitrarily long freshness window is
  spec-legal and a poisoned tool list can be pinned for as long as a server asks); downgrades
  `cacheScope: "public"` to `"private"` on authenticated requests, per the spec's own warning that a
  public result "may be shared between callers even if the Result is coming from an authenticated
  endpoint"; refuses caching hints on `input_required` and MRTR-retry results, which must not be cached;
  and flags a cached list served past a `list_changed` invalidation — the case that matters most here,
  because a stale cache hides the definition change that Bastion's own hash pinning exists to catch.

## [0.8.0] - 2026-08-03

Continued security self-audit remediation (Batches 3–4).

### Security

- **Audit integrity chain can now be keyed (HMAC).** With `audit.integrityKey` (or the
  `MCP_BASTION_AUDIT_KEY` env var), the chain is an HMAC-SHA256 chain a log-rewriter without the key
  cannot forge; unkeyed it remains a plain SHA-256 chain (naive-corruption detection only). Docs already
  describe it honestly as an integrity chain, not tamper-proofing. _(H5 — runtime verify-on-load with
  cross-run chain continuity is still to come.)_
- **Audit value-level redaction.** In `redacted` mode, every string argument value is now scrubbed against
  the secret patterns (not just values under known key names), so a secret under an unlisted key
  (`url: "…?token=…"`, a bare `pat`) no longer reaches the sinks. _(M6)_
- **Durable compliance totals.** `bastion__compliance` now reports from a monotonic accumulator instead of
  a 1000-event RAM ring, so a flood of benign calls can no longer evict an earlier malicious event. _(M4)_
- **HTTP mode authentication.** New `listen.authToken` — a bearer token required on every request
  (constant-time compared). The server **refuses to start on a non-loopback bind without it** (fail-closed). _(M1)_
- **HTTP DNS-rebinding defense.** On a loopback bind, requests whose `Host` is not loopback are rejected
  (the rebinding shape), not just those with a foreign `Origin`. _(M2)_
- **HTTP resource limits.** Request bodies over `listen.maxBodyBytes` (default 1 MiB) get a 413; concurrent
  sessions are capped at `listen.maxSessions` (default 256). _(M3; upstream-response size cap still to come.)_
- **Reconnect rate-limit.** `bastion__reconnect` is now rate-limited per server (5s), so a prompt-injected
  agent can't thrash upstream subprocesses. _(M5)_

## [0.7.0] - 2026-07-26

### Security

- **Operator-only re-approval (authority separation).** `bastion__approve` is **no longer exposed on the
  client tool surface**, and a client-channel call to it is refused. Clearing a rug-pull block is a
  _security_ authority, not a recovery action: previously a prompt-injected agent shown a changed
  (malicious) tool definition could call the re-approval tool itself and clear its own block — detection
  held, but approval authority was not separated from the agent being protected. Recovery actions
  (`bastion__status`, `bastion__reconnect`, `bastion__security`, `bastion__compliance`) remain
  agent-callable; re-approving a changed tool is now operator-only / out-of-band. Added a regression test
  asserting a client `bastion__approve` call is refused and clears no block. Reported by **Massimiliano
  Brighindi**. Maps to OWASP Agentic ASI03 (Identity & Privilege Abuse).
  - **BREAKING:** `bastion__approve` is no longer a callable client tool.
- **Fixed a ReDoS in the command-injection scanner.** The backtick rule used two unbounded ``[^`]*``
  quantifiers, so a hostile tool-call argument (one backtick, many command verbs, no closing backtick)
  cost O(n²) CPU. Rewrote it to a single bounded quantifier and added a per-argument input-size cap.
- **Rug-pull hashing and the poisoning scanner now cover `title`, `annotations`, and `outputSchema`** —
  not just name/description/inputSchema. A rug pull or injection through those model-visible fields (e.g.
  flipping `annotations.destructiveHint`, or a payload in `title`) is now detected. (Tools that use those
  fields re-pin once on upgrade.)
- **DLP redaction now catches modern OpenAI keys** (`sk-proj-…`, `sk-svcacct-…`, `sk-admin-…`), which the
  previous pattern missed — they no longer leak into agent context or the audit log.
- **Command-injection detection now flags path-qualified binaries** after a separator (e.g. `; /bin/rm`).
- **Rug-pull detection now handles mid-session `tools/list_changed`.** Previously the cached tool set (and
  thus rug-pull detection) refreshed only at (re)connect, so a live definition swap could be missed until
  the next reconnect. Bastion now re-lists on the notification and catches the change before the next call.
- **Pin state is now sticky across a tool disappearing.** A tool that vanishes and returns with a changed
  definition is still flagged as a rug pull, instead of being silently re-pinned as trusted.
- **Server-identity pinning and config-drift detection now default OFF (reserved, opt-in).** They were
  installed by default but never wired into the connect path, implying a guarantee that was not active;
  they are honestly gated off until wired. "Server-identity changes" was removed from the default-blocked
  list accordingly.
- **Audit claims tightened** to match the implementation: the hash chain is described as an integrity
  (corruption-detecting) chain, not cryptographic tamper-proofing; redaction is documented as best-effort.

_These items were surfaced by an internal security self-review._

### Note

- An ergonomic operator re-approval path — a signed, one-time grant bound to server + old digest + new
  digest + expiry — is planned as a follow-up. Until then, a changed tool stays blocked until an operator
  clears it out-of-band.

## [0.6.1] - 2026-07-16

### Added

- **Official MCP Registry metadata** — `mcpName` (`io.github.Gowthaman90/mcp-bastion`) in `package.json`
  and a `server.json` manifest, so mcp-bastion can be published to and discovered through the official
  Model Context Protocol registry. No functional change to the proxy.

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

[Unreleased]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.3.1...v0.4.0
[0.2.0]: https://github.com/Gowthaman90/mcp-bastion/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Gowthaman90/mcp-bastion/releases/tag/v0.1.0
