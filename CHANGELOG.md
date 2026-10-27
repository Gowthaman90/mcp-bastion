# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Runtime authorization: who may call which tool, with which arguments, decided before any upstream
contact. Inactive unless `authorization.enabled`; nothing changes for existing configs. All audit
changes are additive; `AUDIT_SCHEMA_VERSION` stays `1`.

- **`authorization`** (new top-level config): `default` (`deny`, or `allow`), `rules` and
  `trustStructuralClaims`. A rule has an `id`, an `effect` (`allow` / `deny`), a `principal` (`"*"`, or
  exactly one of `client`, `user`, `agent`, each a name or a list of names), `tools` (namespaced names,
  exact or with one trailing `*`) and optional `args` constraints on top-level arguments: `equals`,
  `in`, `max`, `min`, `pathWithin`.
- **Semantics.** A call carries each authenticated identity it has: the `client`, plus the `user`
  (`sub`) and `agent` (current actor) of the delegate token for the target upstream. Prior actors grant
  nothing, and nothing in the arguments, headers, `_meta` or input responses is ever an identity. The
  call is allowed only if **every** identity is permitted, so an agent acting for a user needs both
  grants. Per identity, a matching deny wins (deny overrides allow); otherwise an allow whose argument
  constraints all hold is needed. Matching is exact: no case folding, Unicode normalisation or type
  coercion; `max`/`min` accept JSON numbers only; `pathWithin` resolves `.` and `..` (nothing is
  percent-decoded) and checks the boundary at `/`; a missing constrained argument fails an allow. Under
  `default: "allow"`, an identity with no allow rule for the tool is permitted, but one whose allow
  rules all fail their argument constraints is still refused.
- **Deny rules with `args` fail closed.** A deny applies unless its constraints evaluate and do not
  hold: a missing constrained argument, or one of a type the constraint cannot compare (a non-number
  for `max`/`min`, a value of a different JSON type for `equals`/`in`, a relative or NUL-containing
  path for `pathWithin`), refuses the call. A deny whose constraints evaluate and do not match does not
  apply. This is deliberately stricter than rule 3 of mcp-defense-bench's authorization pre-registration
  (§4), where a deny applies only when its `args` are satisfied. Allow rules are unchanged.
- **Where it runs.** In `tools/call`, after the delegation checks and before any upstream contact, so a
  refused call never opens an on-demand connection carrying the caller's forwarded headers. MRTR retries
  are re-authorized. Control tools (`bastion__*`) are authorized under server name `bastion`, which is
  then reserved, and every control-tool call is audited with its `authorization` decision: refused
  calls as `blocked_authorization`, allowed ones with their real outcome (and `wouldBlock` when a `warn`
  action let a refused one through). Control-tool calls are still not audited with authorization
  disabled. `tools/list` hides a tool when some identity could never be allowed it (whatever the
  arguments), and does not connect an idle on-demand upstream none of whose tools the client could be
  allowed.
- **`listen.clients`**: named HTTP clients, each with its own bearer token read from an environment
  variable (`{ "ops": { "tokenEnv": "BASTION_TOKEN_OPS" } }`). Tokens are compared by SHA-256 digest in
  constant time across all clients; a missing or shared token stops startup. A named client's principal
  is `client:<name>`. `listen.authToken` keeps working and is the client `default`; stdio is `stdio` and
  an unauthenticated loopback request is `anonymous`. Named clients alone satisfy the non-loopback bind
  guard.
- **Trust in delegation claims.** `user` and `agent` come only from a trusted delegate token:
  signature-verified, or in structural mode with `trustStructuralClaims: true`, and with no delegation
  finding against it. A rule naming a `user` or `agent` that can match tools of a structural-mode upstream
  is a config error unless `trustStructuralClaims` is set. A token that is present but untrusted refuses
  the call (`delegation:unverified`) instead of silently dropping its identities.
- **Enforcement.** New `security.onAuthorization`: `warn` under `observe` (the call goes through and the
  audit event gets `wouldBlock: "blocked_authorization"`), `block` under `balanced` and `strict`. A
  refusal is answered `Blocked by mcp-bastion: this caller is not authorized to call "<tool>" (rule <id>).`
  (or `(no matching grant)`); no other policy content is revealed.
- **Audit.** New decision `blocked_authorization`, mapped to NIST AI RMF MANAGE and OWASP LLM06
  (Excessive Agency). New optional event field `authorization`: `{ effect, rule, byDefault, client,
identities, violations }`, with violations such as `"agent:argument"` or `"client:denied"`. Rule ids
  and identity kinds only: never a user `sub` or a token.
- **`bastion__status`** gains an `authorization` summary when enabled: default, rule count, action,
  `trustStructuralClaims`, and the last denial (rule id and time only).
- **Finding kinds.** Audit `findings` / `responseFindings` and `bastion__security` findings carry
  `kind: "heuristic" | "deterministic"` (`findingKind()` in `security/types.ts`). Pinning, identity,
  schema, data-flow, custody, transport, header, delegation and authorization checks are
  deterministic; poisoning, response, command-injection, DLP and steering checks are heuristic. A consumer
  comparing whole finding objects will see the new field.
- New exports: `authorize`, `mayList`, `matchesToolPattern`, `isPathWithin`, `resolvePosixPath`,
  `findingKind`, `resolveListenClients` and their types.
- Tests: the 12 pre-registered `authorization` dev fixtures of mcp-defense-bench (tag
  `authorization-prereg-2026-10-26`) are replayed through a real gateway; each attack is refused before
  upstream contact with exactly the pre-registered violation, and each benign control is allowed.

### Audit evidence and sinks

Trustworthy audit evidence: sinks that are safe by default and survive failure, per-sink redaction, and
signed checkpoints that make a shortened log or a deleted run detectable. New record kinds appear only
when `audit.checkpoint` is configured; `AUDIT_SCHEMA_VERSION` stays `1`.

- **Changed (may need a config change): remote audit sinks require HTTPS.** A `webhook` `url` or `otlp`
  `endpoint` using plain `http://` to a non-loopback host is now a config error. Set
  `allowInsecureTransport: true` on that sink to keep it (a warning is logged at startup).
- **`headersEnv`** on the `webhook` and `otlp` sinks (header name → environment variable), so tokens stay
  out of the config file; a missing variable stops startup. The `webhook` sink also accepts `headers`.
- **Delivery that survives an outage.** A failed batch is no longer retried once and dropped: it goes back
  to a bounded queue (`maxQueue`, default 10 000 events) and is retried with exponential backoff and
  jitter (0.5 s doubling, 30 s cap). Beyond `maxQueue` the oldest events are dropped and counted.
- **Sink health** in `bastion__status` (`audit.sinks`): `healthy`, `delivered`, `dropped`, `queued`,
  `failedAttempts`, `lastError`, for every sink including the file sink.
- **`audit.onSinkFailure`**: `continue` (default) or `block`. With `block`, calls are refused
  (`blocked_audit_unavailable`) while no sink can deliver, for deployments where an unaudited call is not
  acceptable. Bastion's own control tools (`bastion__status`, `bastion__reconnect`, …) are never refused, so
  the sinks can still be inspected and recovered.
- **Per-sink `includeArgs`**, overriding `audit.includeArgs` per sink (e.g. full arguments to a local
  file, none to a shared SIEM). When sinks differ and `tamperEvident` is on, events use **chain v2**
  (`chainVersion: 2`): the hash covers the event without its `args` view plus `argsDigest` (HMAC-SHA256 of
  the full arguments with the integrity key), so every sink verifies the same chain. Without an
  integrity key, arguments are then not covered by the chain (a warning is logged). Sinks that agree keep
  chain v1, unchanged.
- **Every event carries `runId`.**
- **`audit.checkpoint`** (opt-in, needs `tamperEvident`): each run starts with a chained `run-start`
  record (seq 0) that links to the previous run's last checkpoint via `stateFile` (written `0600`), and an
  Ed25519-signed `checkpoint` of the chain head is written every `everyEvents` (100) events, every
  `everySeconds` (60) seconds when there is something new, and at shutdown, to every sink plus
  checkpoint-only witness `sinks`. Consumers that assume every line is a call event should skip records
  with a `recordType`.
- **`mcp-bastion audit verify <log>`** checks the hash chain (v1 and v2, keyed via `--key-env`), seq
  continuity, checkpoint signatures (`--public-key`), a log cut short or a deleted run (against a witness,
  `--checkpoints`) and run links; exit 0 intact, 1 tampered, 2 cannot verify; `--json` for the report.
  **`mcp-bastion audit keygen --out <dir>`** writes a checkpoint key pair and never overwrites. Limit: a
  cut is detected only back to the last checkpoint that reached a witness the attacker cannot rewrite.
- **Redaction.** Inline DLP now also catches GitHub fine-grained tokens, Stripe and Google API keys, npm
  tokens, Slack webhook URLs, JWTs, `Bearer` credentials and passwords in URLs. On the new 39-case corpus
  (`test/redaction-corpus.test.ts`) it went from 16/27 secrets caught and 2/12 benign values over-redacted
  to 27/27 and 0/12. **Fixed:** a `NAME=secret` whose name starts with the credential word (`PASSWORD=…`,
  `TOKEN: …`) was missed; booleans, null-ish words and short numbers (`max_tokens: 1500`) are no longer
  redacted. **Changed:** JWTs and bearer credentials in tool results are now redacted by default; set
  `security.redactResponseSecrets: false` if a tool must return one to the agent.
- **Fixed:** with `redactResponseSecrets: false`, a secret in a tool result left no trace. It is now
  recorded as a `secret-in-result` (high) response finding, and the result is left untouched.
- **Fixed:** a refused HTTP bind (non-loopback without credentials) exited after the stdio upstreams were
  spawned, orphaning them. The listener is checked before any upstream starts, and a later startup
  failure closes the upstreams before exiting.

## [1.3.1] - 2026-10-26

Fixes a crash in the audit file sink and picks up a `zod` security fix. Upgrading is recommended.

- **Fixed:** an audit file that could not be opened (missing directory, no permission) crashed the
  process with an unhandled `error` event shortly after startup. The file is now opened at startup, and a
  bad path stops Bastion with a clear message: `audit file sink cannot open "<path>": <reason>`.
- **Fixed:** a write error while running (for example a full disk) also crashed the process. The sink
  now logs the error once, stops writing, and counts later events as dropped instead of throwing. Other
  sinks and tool calls are unaffected, and `flush`/`close` return promptly on a failed stream.
- **Changed:** a newly created audit file is readable and writable by its owner only (`0600`). An
  existing file keeps its permissions; tighten them with `chmod 600 <file>` if needed.
- New on `FileSink`: read-only `lastError` and `dropped`.
- **Security (dependencies):** `zod` to 4.6.7 (minimum raised to `^4.6.6`) for
  [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5) (memory exhaustion while
  validating oversized constrained collections). Bastion and the MCP SDK validate incoming messages with
  zod, so it may be reachable; HTTP request bodies were already capped by `listen.maxBodyBytes` (1 MiB by
  default), which limits the exposure. `npm audit --omit=dev` is clean. Dev: `body-parser` (via the test-only MCP
  SDK 1.x) updated for GHSA-27r3-jxmh-p828.

## [1.3.0] - 2026-10-20

Shadow-mode (`enforcementProfile: "observe"`) audit events now show everything enforcement would have
acted on, so a pilot can report what `balanced` would have blocked. All audit changes are additive;
`AUDIT_SCHEMA_VERSION` stays `1`.

- **Rug pulls are recorded as a finding.** A tool whose definition changed after approval now adds
  `tool-definition-changed` (high) to the call's `findings`, whether the call is blocked or let through.
  Before, a rug pull under `warn` was only logged to stderr.
- **`AuditEvent.wouldBlock`** (optional): the decision the `balanced` profile would have recorded, set
  when a check found a problem but its action was `warn`. Covers rug pull, identity change, argument
  inspection, cross-server data flow, MRTR and delegation checks; the first such check wins. Heuristic
  checks that `balanced` only warns on (description poisoning, response heuristics, delegation chain
  depth) do not set it.
- **`AuditEvent.responseFindings`** and **`AuditEvent.redactedSecrets`** (optional): the findings from
  scanning the tool's result, and how many secret values inline DLP redacted from it. Both were computed
  before but never written to the audit event.
- **Fixed:** with `pinServerIdentity` on and the identity action at `warn`, the rug-pull check replaced
  the call's findings, so the `server-identity-changed` finding never reached the audit event. Findings
  from earlier checks are now kept.
- **Changed:** the rug-pull block message no longer tells the agent to call `bastion__approve`, a tool it
  is not offered and cannot use. It now says to ask an operator to review the change and re-approve.
- New exports: `SecurityDecision` (type) and `DelegationCheck.wouldBlock`.
- **Security (dependencies):** `@modelcontextprotocol/client`, `core` and `server` to 2.3.1 and `node` to
  2.1.1, for [GHSA-6qxp-vccf-f47h](https://github.com/advisories/GHSA-6qxp-vccf-f47h) (the SDK's OAuth
  client could send credentials to an authorization server chosen by the MCP server). Bastion does not use
  the SDK OAuth client, so the flaw was not reachable, but the advisory sat on the runtime tree. Transitive
  `hono` / `@hono/node-server` advisories are cleared too; `npm audit --omit=dev` is clean.
- Dev: `vitest` 2 → 4.1.12 (not 5, which drops Node 20) and `@modelcontextprotocol/sdk` 1.32.1.
- **Fixed:** `npm run demo` crashed since 1.2.0 (`security.requestStateKey` of undefined) because it built
  its config by hand. It now parses the config through `BastionConfigSchema`, as the CLI does.

## [1.2.0] - 2026-10-16

Per-user identity forwarding (gateway mode), so one Bastion can sit between an agent and sub-agents
that must each run as the signed-in user.

- **`servers.<name>.forwardHeaders`** (HTTP upstreams, `listen.mode: "http"`): a map of upstream header
  ← incoming header. For each upstream request made while serving a downstream request (`initialize`,
  `tools/list`, `tools/call`, `ping`), the incoming value is sent under the upstream name. Values are bound
  to their request with `AsyncLocalStorage` and merged in by a custom `fetch` on the upstream transport,
  so concurrent users sharing one connection never see each other's headers. Only listed headers are
  forwarded; a forwarded header overrides a static one; hop-by-hop and transport-owned targets are
  rejected at config load. Bastion holds no credential of its own in this mode.
- **`servers.<name>.onMissingForwardedHeader`**: `error` (default) answers a tool error and never calls
  the upstream; `omit` calls it without the header.
- **`servers.<name>.connect: "onDemand"`**: no connection at start-up; the first request that needs the
  upstream connects it with that request's headers. Health checks skip such upstreams (state `idle`); a
  failed connect goes back to `idle` with no reconnect timer.
- **`servers.<name>.authHeaders`**: extra header names that count as authentication. `forwardHeaders`
  keys count automatically, so `bastion__status` reports `authenticated: true` and the connect-time
  warning no longer fires.
- An upstream **HTTP 401** is reported as an authentication failure in the tool result and in
  `bastion__status` `lastError`, not as a generic failure or an unknown tool. One caller's 401 does not
  tear down the shared connection.
- Forwarded values never appear in logs, audit sinks or `bastion__status`. Audit events gain an optional
  `forwardedHeaders` field listing the forwarded header **names**.
- New public exports: `MissingForwardedHeaderError`; on the core layer, `runWithRequestHeaders`,
  `currentRequestContext`, `runOutsideRequest` and `isAuthFailure`. `ConnectionState` gains `idle`.
- No change for existing configs: `connect` defaults to `startup` and nothing is forwarded unless listed.

Keyless delegation checks (structural and signature mode): Bastion checks each agent-to-sub-agent
delegate JWT a request carries and records who acted for whom, while holding no secret or key.

- **`servers.<name>.delegation`** (HTTP upstreams with `forwardHeaders`): `audience` (required), `header`
  (a `forwardHeaders` key; default the only one), `verify` (`structural` | `signature`),
  `maxLifetimeSeconds` (3600), `clockSkewSeconds` (30), `allowedActors`, `requireActor`,
  `maxChainDepth`. Top-level **`delegation`**: `gatewayAudiences`, `oneUserPerRequest`
  (true), `recordSubject` (`hash` | `plain`, default `hash`), `subjectKey`. Config load rejects a
  `delegation` without `forwardHeaders`, a `header` that is not a `forwardHeaders` key, two upstreams with
  the same audience, an upstream audience listed as a gateway audience, and unknown keys.
- Rules: `delegation-malformed` (strict JWS compact decoding: canonical base64url, no padding, JSON
  objects with unique member names; fails closed), `-audience-mismatch`, `-passthrough` (no `aud`, or a
  gateway audience), `-subject-mixing` (more than one (`iss`, `sub`) across the request's tokens),
  `-expired`, `-not-yet-valid`, `-lifetime-excess` (or no `exp`), `-actor-not-allowed` (current actor =
  `act.sub`, else `act.client_id`), `-actor-required`, and the medium, warn-by-default `-chain-depth` and
  `-chain-cycle` (prior actors are informational, RFC 8693 §4.1).
- **`security.onDelegation`** and **`security.onDelegationChain`** (`block` | `warn`), defaulting from the
  enforcement profile: `observe` warn/warn, `balanced` block/warn, `strict` block/block.
- One verdict per request, cached in the request context. A blocked `tools/call` is refused before any
  upstream contact (including an on-demand connect) with a tool error naming the rule, and audited with
  the new decision **`blocked_delegation`** (`AuditEngine.recordPreflight`); `tools/list` omits a blocked
  upstream; the forwarding `fetch` refuses to send a token whose verdict blocks.
- Audit events gain an optional **`delegation`** record: subject (`hmac:` + 16 hex of HMAC-SHA256 over
  `iss|sub`, or `sub` in `plain` mode), issuer, audience, `jti`, expiry, actors, chain depth,
  `verified` and findings. Never the token. The pseudonym key falls back from `subjectKey`
  to `MCP_BASTION_SUBJECT_KEY`, the audit integrity key, then a random per-process key (not linkable
  across restarts).
- `bastion__status` gains `delegation: { mode, audience, lastViolation }` per configured upstream (rule
  id and time only).
- **Signature mode** (`verify: "signature"`): `issuer` (required), `algorithms` (required, non-empty;
  `HS256/384/512` and `none` rejected in any casing; asymmetric only) and exactly one key source,
  `jwksUrl` (HTTPS except loopback; `createRemoteJWKSet`) or inline public `jwks` (`createLocalJWKSet`;
  private or secret JWK members rejected). Keys come only from that source (`jku`, `x5u`, `x5c`, embedded
  `jwk` never followed); the case-sensitive allow-list runs before any key lookup; `crit` headers are
  refused; an unknown `kid` triggers at most one refetch per 30 s cooldown; a JWKS fetch failure or 5 s
  timeout fails closed and is reported as the upstream's `lastError`. New high, blocking rules:
  `delegation-alg-disallowed`, `-key-unknown`, `-signature-invalid`, `-issuer-mismatch`. The structural
  rules still run under the same names. The audit record's `verified` is `signature` when the signature
  verified, `failed` when it did not. `jose` 6.2.3 (already in the tree via the MCP SDK) becomes a direct
  dependency; no package is added.
- New public exports: `checkDelegation`, `checkDelegationAsync`, `delegationKeySet`,
  `decodeJwsCompact`, `subjectPseudonym`, `DelegationBlockedError`, and the delegation types.
- Limits: structural mode authenticates nothing (the upstream remains the verifier); signature mode
  holds public keys only and needs asymmetric tokens; the one-user check covers only tokens configured
  with `delegation`; replay within a token's lifetime is not stopped.

## [1.1.0] - 2026-09-30

Human-oversight gaps (the EU AI Act Art. 14 set in mcp-defense-bench v0.8.0: three of its seven vectors
had no measured defence in any tool).

- **False-error escalation check** (`checkErrorSteering`, rule `error-privilege-steering`, `medium`).
  Runs in the response scan on every tool result. Flags an error-shaped result whose text steers the
  agent toward a more privileged path (a shell/exec/admin-style tool call, `sudo`, elevated or broader
  permissions, `--force`-style flags) or tells it to switch a safety control off. Advisory: the result is
  relayed and the finding is audited.
- **Standing-grant elicitation** in the MRTR consent gate (rule `mrtr-standing-grant`, `medium`). Flags an
  in-band elicitation that asks for a persistent approval ("always allow", "don't ask again") on a broad
  or sensitive capability, in the message or in the form's options. Advisory.
- Measured against mcp-defense-bench v0.8.0 (leaderboard re-measured the same day): dev 61% → 62% CorpusRobustCoverage, uncovered vectors 6 → 5; held-out 32% → 33%; matched-
  control false positives still 0/51 dev and 0/48 held-out; benign corpus 13 → 14 flags (the new one is an
  EACCES error that suggests "elevated privileges", kept as a disclosed cost rather than tuned away). The
  standing-grant check does not score yet: the benchmark's consent-fatigue fixture is not elicitation-
  shaped, so the adapter still reports it as a miss.

## [1.0.3] - 2026-09-24

- Archival release for Zenodo (DOI minting). `CITATION.cff` gains the author ORCID, version and release
  date; the stale benchmark figure is removed from its abstract. No functional change.

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
