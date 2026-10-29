<div align="center">

# 🛡️ mcp-bastion

**A reliability &amp; security proxy for the Model Context Protocol (MCP).**

_Self-healing connections, runtime tool-security, and a compliance-mapped audit trail for your MCP servers._

[![npm version](https://img.shields.io/npm/v/mcp-bastion.svg?color=cb3837&logo=npm)](https://www.npmjs.com/package/mcp-bastion)
[![npm downloads](https://img.shields.io/npm/dm/mcp-bastion.svg?color=cb3837)](https://www.npmjs.com/package/mcp-bastion)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-listed-6f42c1)](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.Gowthaman90/mcp-bastion)
[![Measured coverage](<https://img.shields.io/badge/mcp--defense--bench-66%25_coverage_(37_vectors)-2ea44f>)](https://github.com/Gowthaman90/mcp-defense-bench)
[![mcp-bastion MCP server – quality and maintenance score on Glama](https://glama.ai/mcp/servers/Gowthaman90/mcp-bastion/badges/score.svg)](https://glama.ai/mcp/servers/Gowthaman90/mcp-bastion)
[![CI](https://github.com/Gowthaman90/mcp-bastion/actions/workflows/ci.yml/badge.svg)](https://github.com/Gowthaman90/mcp-bastion/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](https://www.typescriptlang.org/)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)

<br/>

<img src="./assets/demo.svg" alt="mcp-bastion: an MCP server crashes mid-session and the agent recovers it automatically" width="760">

</div>

---

`mcp-bastion` sits between your MCP client (Claude Code, Cursor, Cline, Windsurf, Zed, Claude
Desktop, or any MCP-compliant agent) and your MCP servers. It is **client-agnostic** — it works with
any compliant client through configuration alone, with zero client-specific code — and **non-invasive**:
your servers run unchanged, and removing Bastion is a one-line config revert.

📦 **Package:** [`mcp-bastion` on npm](https://www.npmjs.com/package/mcp-bastion) · 🗂️ **Official MCP Registry:** `io.github.Gowthaman90/mcp-bastion`

🔒 **Security, measured:** on the open, vendor-neutral [mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench) v0.9.0, Bastion covers **66% of the MCP attack surface (24.6/37 vectors; 23 enforced)** on development fixtures and **53%** on the pre-registered held-out set, at zero false positives on matched controls — the broadest of the proxies measured.

📖 **Launch story:** [Medium](https://medium.com/p/e74f638e9e15) · [dev.to](https://dev.to/gowthaman90/the-mcp-reliability-security-gap-and-an-open-source-proxy-that-fills-it-3ppo)

👤 **Created & maintained by [Gowthaman Arumugam](https://github.com/Gowthaman90)** — Independent Researcher. Companion benchmark: [mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench).

## Contents

- [Why](#why)
- [How it works](#how-it-works)
- [Security model](#security-model)
- [Features](#features)
- [Quick start](#quick-start)
- [Demo](#demo)
- [Control tools](#control-tools)
- [Configuration](#configuration)
- [Transports](#transports)
- [Per-user identity (gateway mode)](#per-user-identity-gateway-mode)
- [Delegation checks](#delegation-checks)
- [Runtime authorization](#runtime-authorization)
- [Runtime security](#runtime-security)
- [Audit & compliance](#audit--compliance)
- [Client setup](#client-setup)
- [Architecture](#architecture)
- [Development](#development)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Why

When an MCP server disconnects mid-session, the agent only sees a generic _"No such tool available"_
error — **indistinguishable from a tool that never existed** — and it cannot reconnect; only a human
can. Long agent sessions silently lose capabilities and fail in confusing ways.

Bastion closes that gap. It health-checks every server, auto-reconnects with backoff, and — crucially —
exposes control tools so the **agent itself** can inspect connection health and recover a dropped
server without human intervention.

> Bastion now spans three layers: **reliability** (v0.1), **runtime security** (v0.2 — tool pinning /
> rug-pull & poisoning detection), and **audit & compliance** (v0.3 — pluggable sinks mapped to NIST
> AI RMF / OWASP LLM Top 10). See the [roadmap](#roadmap).

## How it works

Today your client connects **directly** to each server. With Bastion, your client connects to
**Bastion**, which connects to those same servers on your behalf — so it sits in the tool-call path
and can add reliability (and, later, security) transparently.

```
Before:   Client ─▶ server A / server B / server C

After:    Client ─▶ mcp-bastion ─▶ server A
                                  ─▶ server B
                                  ─▶ server C
```

Bastion is a standard MCP **server** to your client and a standard MCP **client** to each upstream.
Because it speaks the protocol faithfully, it works with every compliant client automatically — the
only per-client difference is where you put a few lines of config.

## Security model

Bastion's security rests on **three independent mechanisms**. Heuristics feed all three and replace
none of them: a heuristic finding is a risk signal, never a proof that a tool is safe.

| Mechanism                      | What it gives you                                                                                             | Checks                                                                                                                                  |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Definition integrity**       | The tool, server and configuration you approved are the ones being called                                     | tool pinning (rug pull), server identity, config drift, argument schema                                                                 |
| **Runtime authorization**      | Each caller reaches only the tools and argument values its policy grants, decided before any upstream contact | [`authorization`](#runtime-authorization) rules, [delegation checks](#delegation-checks) (who acts for whom), MRTR continuation custody |
| **Trustworthy audit evidence** | Every decision is recorded without leaking secrets, and a changed or shortened log can be detected            | [audit events](#audit--compliance), hash chain, signed checkpoints, sink health, redaction                                              |

Every finding carries a `kind`: **deterministic** (an exact comparison against a pin, a schema, a policy
or a token's claims) or **heuristic** (pattern matching that can misfire on benign text and can be
evaded by a novel payload). What each enforcement profile does with them:

| Check                                                                                 | Kind          | `observe` | `balanced` (default) | `strict` |
| ------------------------------------------------------------------------------------- | ------------- | --------- | -------------------- | -------- |
| Tool pinning (rug pull), server identity                                              | deterministic | warn      | block                | block    |
| Runtime authorization                                                                 | deterministic | warn      | block                | block    |
| Delegation token checks                                                               | deterministic | warn      | block                | block    |
| Delegation chain depth / cycles                                                       | deterministic | warn      | warn                 | block    |
| Cross-server data flow                                                                | deterministic | warn      | block                | block    |
| Argument inspection: schema, plus command-injection and injected-instruction patterns | mixed         | warn      | block                | block    |
| MRTR (`input_required`) gate                                                          | mixed         | warn      | block                | block    |
| Description poisoning                                                                 | heuristic     | warn      | warn                 | block    |
| Response heuristics (injection, steering)                                             | heuristic     | warn      | warn                 | block    |

Argument inspection blocks under `balanced` even though part of it is heuristic: a false positive costs
the agent a retry, while a miss can run a command. Inline secret redaction in results
(`redactResponseSecrets`) is on in every profile. Under `observe` nothing is blocked and each audit event
records `wouldBlock`: what `balanced` would have done.

**Known limits.** Poisoning and response heuristics can be evaded by payloads they have not seen.
Redaction covers known secret shapes, not every secret. Bastion does not sandbox the upstream server
itself. Authorization trusts the identities it is given: bearer clients it authenticates itself, and
delegation claims it verifies only in signature mode (see `trustStructuralClaims`).

## Features

- 🔌 **Client-agnostic** — one binary, config-only integration; no per-client plugins.
- ♻️ **Self-healing** — health checks + capped exponential-backoff auto-reconnect for stdio servers.
- 🧭 **Agent-recoverable** — `bastion__status` and `bastion__reconnect` let the agent detect and fix
  drops itself, instead of hitting an opaque "no such tool" wall.
- 🧩 **Transparent aggregation** — merges many servers into one, with per-server tool namespacing to
  prevent collisions and tool-shadowing.
- 💬 **Legible failures** — a dropped server yields an actionable message, not a crash.
- 🛡️ **Runtime security** _(new in v0.2)_ — pins each tool's definition and blocks "rug pulls" (a
  server changing a tool after approval); heuristically inspects descriptions for poisoning; detects
  cross-server shadowing. See [Runtime security](#runtime-security).
- 🔐 **Runtime authorization** _(new in v1.4, opt-in)_ — per-caller, per-tool policy decided before any
  upstream contact: which client, user and agent may call which tool with which argument values,
  deny-overrides, default-deny, and an observe mode to preview a policy. See
  [Runtime authorization](#runtime-authorization).
- 📝 **Audit & compliance** _(opt-in)_ — structured, hash-chained audit events to pluggable sinks
  (console / file / webhook / OTLP), mapped to NIST AI RMF & OWASP LLM Top 10; since v1.4 with HTTPS-only
  remote sinks, retrying delivery, per-sink redaction and Ed25519-signed checkpoints that make a shortened
  log detectable. See [Audit & compliance](#audit--compliance).
- 🪶 **Non-invasive & reversible** — your servers run unchanged; uninstall is a config revert.
- 🧱 **Enterprise-grade codebase** — strict TypeScript, layered architecture, ESLint + Prettier, and
  unit + end-to-end tests.

## Quick start

Bastion is published on npm as [`mcp-bastion`](https://www.npmjs.com/package/mcp-bastion) — the
`npx` command below fetches it automatically, so there's nothing to install first.

**1. Add Bastion to your client**, pointing it at a config file:

```jsonc
// your client's mcpServers config
{
  "mcpServers": {
    "bastion": {
      "command": "npx",
      "args": ["-y", "mcp-bastion", "--config", "bastion.config.json"],
    },
  },
}
```

**2. List your real servers in `bastion.config.json`** (moved verbatim from the client):

```jsonc
{
  "servers": {
    "github": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/dir"],
    },
  },
  "reconnect": { "auto": true },
  "healthCheck": { "enabled": true },
}
```

**3. Restart your client.** Your tools now appear namespaced (e.g. `github__create_issue`) alongside
Bastion's control tools. See [`bastion.config.example.json`](./bastion.config.example.json) for the
full set of options.

> 🔒 **Security is on by default.** Out of the box, Bastion runs the `balanced` enforcement profile:
> it **blocks** high-confidence attacks (rug-pulls, argument/command injection, cross-server
> exfiltration) and **warns** on heuristic ones (description/response
> poisoning), while redacting leaked secrets from tool results. Set `security.enforcementProfile` to
> `observe` (warn-only) or `strict` (block-all), or tune any individual control — see
> [Runtime security](#runtime-security).

## Demo

See the whole thing in action — a server crashing mid-session and healing itself:

```bash
npm run demo
```

It boots Bastion in front of a server that crashes on command, shows the agent getting an actionable
"reconnect" message instead of a cryptic error, and then the connection auto-recovering with no human
involved. To record it as a GIF: `asciinema rec demo.cast -c "npm run demo" && agg demo.cast assets/demo.gif`.

## Control tools

Bastion injects control tools so the agent can manage connections and review security itself, using
only standard MCP calls:

| Tool                  | Purpose                                                                                                    |
| --------------------- | ---------------------------------------------------------------------------------------------------------- |
| `bastion__status`     | Health of every proxied server: connected / disconnected / reconnecting / failed, tool counts, last error. |
| `bastion__reconnect`  | Reconnect a named server (argument: `{ "server": "<name>" }`) without human intervention.                  |
| `bastion__security`   | Per-tool security report: pin status (approved vs changed), poisoning findings, and shadowing.             |
| `bastion__compliance` | Audit summary of recent activity mapped to NIST AI RMF / OWASP LLM Top 10 (requires `audit.enabled`).      |

> **Re-approval is operator-only.** Clearing a rug-pull block is a security authority, so it is **not** an
> agent-callable tool — a prompt-injected agent must not be able to re-approve the very tool it was blocked
> from. A changed tool stays blocked until an operator clears it out-of-band; `bastion__approve` is not
> advertised and a client call to it is refused.

## Configuration

| Key                                       | Type                                | Default              | Description                                                                                                                  |
| ----------------------------------------- | ----------------------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `servers`                                 | map                                 | —                    | Upstream servers to proxy (required, at least one).                                                                          |
| `servers.<name>.command`                  | string                              | —                    | Executable to launch (e.g. `npx`, `node`).                                                                                   |
| `servers.<name>.args`                     | string[]                            | `[]`                 | Arguments to `command`.                                                                                                      |
| `servers.<name>.env`                      | map                                 | —                    | Env overrides merged over the process env.                                                                                   |
| `servers.<name>.cwd`                      | string                              | —                    | Working directory for the spawned process.                                                                                   |
| `reconnect.auto`                          | boolean                             | `true`               | Auto-reconnect after an unexpected disconnect.                                                                               |
| `reconnect.maxRetries`                    | number                              | `10`                 | Max attempts before giving up (`-1` = unlimited).                                                                            |
| `reconnect.initialBackoffMs`              | number                              | `500`                | Initial backoff, doubled each attempt.                                                                                       |
| `reconnect.maxBackoffMs`                  | number                              | `30000`              | Backoff ceiling.                                                                                                             |
| `healthCheck.enabled`                     | boolean                             | `true`               | Enable periodic liveness probing.                                                                                            |
| `healthCheck.intervalMs`                  | number                              | `30000`              | Interval between probes.                                                                                                     |
| `healthCheck.timeoutMs`                   | number                              | `5000`               | Per-probe timeout.                                                                                                           |
| `namespace.strategy`                      | `prefix` \| `passthrough`           | `prefix`             | How upstream tool names are exposed.                                                                                         |
| `namespace.separator`                     | string                              | `__`                 | Separator used by the `prefix` strategy.                                                                                     |
| `security.pinTools`                       | boolean                             | `true`               | Pin tool definitions and detect later changes.                                                                               |
| `security.onRugPull`                      | `block` \| `warn`                   | `block`              | Action when a pinned tool's definition changed.                                                                              |
| `security.inspectDescriptions`            | boolean                             | `true`               | Run poisoning heuristics on tool descriptions.                                                                               |
| `security.onPoisoning`                    | `block` \| `warn`                   | `warn`               | Action on a high-severity poisoning finding.                                                                                 |
| `audit.enabled`                           | boolean                             | `false`              | Record an audit event for every tool call.                                                                                   |
| `audit.includeArgs`                       | `none`\|`redacted`\|`full`          | `none`               | How tool arguments are recorded.                                                                                             |
| `audit.tamperEvident`                     | boolean                             | `false`              | Hash-chain events so tampering is detectable.                                                                                |
| `audit.sinks`                             | array                               | console              | Destinations: `console`, `file`, `webhook`, `otlp`.                                                                          |
| `servers.<name>.transport`                | `stdio` \| `http`                   | `stdio`              | Local subprocess or remote endpoint.                                                                                         |
| `servers.<name>.url`                      | string                              | —                    | Remote MCP URL (required for `http`).                                                                                        |
| `servers.<name>.headers`                  | map                                 | —                    | Headers for `http` upstreams (e.g. `Authorization`).                                                                         |
| `servers.<name>.forwardHeaders`           | map                                 | —                    | `http` only. Upstream header ← incoming header, copied per request (gateway mode). Needs `listen.mode: "http"`.              |
| `servers.<name>.onMissingForwardedHeader` | `error` \| `omit`                   | `error`              | When a request lacks a forwarded header: answer a tool error without calling the upstream, or call it without.               |
| `servers.<name>.connect`                  | `startup` \| `onDemand`             | `startup`            | `onDemand`: connect on the first request that needs this upstream, with that request's forwarded headers.                    |
| `servers.<name>.authHeaders`              | string[]                            | —                    | Extra header names that count as authentication in `bastion__status` (`forwardHeaders` keys always count).                   |
| `servers.<name>.delegation`               | object                              | —                    | `http` only, needs `forwardHeaders`. Keyless checks on the delegate JWT in a forwarded header ([below](#delegation-checks)). |
| `servers.<name>.delegation.verify`        | `structural` \| `signature`         | `structural`         | `signature` also verifies the JWT against public keys (`jwksUrl` or `jwks`), with `issuer` and an `algorithms` allow-list.   |
| `delegation.gatewayAudiences`             | string[]                            | `[]`                 | Audiences that identify Bastion itself; a token for one of them (or with no `aud`) is passthrough.                           |
| `delegation.oneUserPerRequest`            | boolean                             | `true`               | All delegate tokens in one request must name the same user (`iss` + `sub`).                                                  |
| `delegation.recordSubject`                | `hash` \| `plain`                   | `hash`               | Audit subject: HMAC pseudonym of `iss\|sub`, or `sub` as is.                                                                 |
| `delegation.subjectKey`                   | string (≥16)                        | see below            | Pseudonym key; or `MCP_BASTION_SUBJECT_KEY`, then the audit integrity key, then random per process (warned at start-up).     |
| `security.onDelegation`                   | `block` \| `warn`                   | `block`              | Action on a delegation finding other than the chain rules.                                                                   |
| `security.onDelegationChain`              | `block` \| `warn`                   | `warn`               | Action on `delegation-chain-depth` / `-chain-cycle` (`block` under `strict`).                                                |
| `listen.mode`                             | `stdio` \| `http`                   | `stdio`              | Serve Bastion over stdio or Streamable HTTP.                                                                                 |
| `listen.host` / `listen.port`             | string / number                     | `127.0.0.1` / `3000` | Bind address for `http` mode.                                                                                                |
| `listen.validateRoutingHeaders`           | boolean                             | `true`               | Reject `Mcp-*` routing headers that disagree with the body (`-32020`, MCP 2026-07-28).                                       |
| `security.maxCacheTtlMs`                  | number (ms)                         | `3600000`            | Ceiling on upstream `ttlMs` cache hints forwarded downstream (MCP 2026-07-28).                                               |
| `servers.<name>.protocol`                 | `auto`\|`legacy`\|`2026-07-28`      | `auto`               | Era negotiation per upstream (probe 2026-07-28, fall back; or pin).                                                          |
| `listen.legacy`                           | `stateless` \| `reject`             | `stateless`          | Serve pre-2026-07-28 clients statelessly, or refuse them (`-32022`).                                                         |
| `security.inspectInputRequests`           | boolean                             | `true`               | Gate `input_required` rounds (credential phishing, model steering).                                                          |
| `security.onInputRequired`                | `block` \| `warn`                   | `block`              | Action on a high-severity MRTR finding (`warn` strips the request).                                                          |
| `security.requestStateKey`                | string (≥16)                        | random per process   | HMAC key sealing `requestState` envelopes; or `MCP_BASTION_REQUEST_STATE_KEY`.                                               |
| `security.requestStateTtlSeconds`         | number                              | `300`                | Lifetime of a sealed `requestState` envelope.                                                                                |
| `security.enforcementProfile`             | `observe` \| `balanced` \| `strict` | `balanced`           | Sets every `on*` action as a group; see [Security model](#security-model). An explicit `on*` overrides it.                   |
| `security.onAuthorization`                | `block` \| `warn`                   | `block`              | Action when `authorization` refuses a call (`warn` under `observe`).                                                         |
| `security.redactResponseSecrets`          | boolean                             | `true`               | Redact secret values from tool results before the agent sees them.                                                           |
| `authorization.enabled`                   | boolean                             | `false`              | Turn on runtime authorization; see [Runtime authorization](#runtime-authorization).                                          |
| `authorization.default`                   | `deny` \| `allow`                   | `deny`               | Decision for an identity no rule allows.                                                                                     |
| `authorization.rules`                     | array                               | `[]`                 | `{ id, effect, principal, tools, args? }` rules; deny overrides allow.                                                       |
| `authorization.trustStructuralClaims`     | boolean                             | `false`              | Accept `user`/`agent` from structural-mode delegate tokens.                                                                  |
| `listen.authToken`                        | string                              | —                    | Bearer token for the client `default`. Required for a non-loopback bind unless `listen.clients` is set.                      |
| `listen.clients`                          | map                                 | —                    | Named clients: `{ "<name>": { "tokenEnv": "VAR" } }`, one bearer token each.                                                 |
| `audit.integrityKey`                      | string                              | —                    | HMAC key for the chain; or `MCP_BASTION_AUDIT_KEY`.                                                                          |
| `audit.onSinkFailure`                     | `continue` \| `block`               | `continue`           | `block` refuses calls while no sink can deliver.                                                                             |
| `audit.sinks[].includeArgs`               | `none`\|`redacted`\|`full`          | `audit.includeArgs`  | Per-sink argument recording.                                                                                                 |
| `audit.sinks[].headersEnv`                | map                                 | —                    | `webhook`/`otlp`: header name → environment variable.                                                                        |
| `audit.sinks[].allowInsecureTransport`    | boolean                             | `false`              | `webhook`/`otlp`: allow plain HTTP to a non-loopback host.                                                                   |
| `audit.sinks[].maxQueue`                  | number                              | `10000`              | `webhook`/`otlp`: events held while the receiver is down.                                                                    |
| `audit.checkpoint`                        | object                              | —                    | Signed checkpoints: `privateKeyFile`, `everyEvents` (100), `everySeconds` (60), `stateFile`, `sinks`.                        |

## Transports

Bastion runs on the MCP TypeScript SDK **2.0** and speaks **both protocol eras** — the stateless
2026-07-28 revision and the pre-2026 `initialize` handshake — on both faces, per upstream and per
client. When the protocol is stateless, the gateway is the only component that can still hold security
state, which is why v1.0 adds `requestState` custody and an `input_required` consent gate (see
`CHANGELOG.md`).

Bastion speaks two transports on **both** faces:

- **stdio** (default) — the client spawns Bastion, and Bastion spawns local servers.
- **Streamable HTTP** — connect to **remote** MCP servers (`servers.<name>` with `transport: "http"`,
  a `url`, and optional auth `headers`), and/or **serve** Bastion over HTTP to multiple/remote clients
  (`listen.mode: "http"`, or `--http <port>`).

HTTP upstreams configured without an authentication header are flagged (`authenticated: false`) in
`bastion__status` and warned at connect time. A custom credential header counts once it is named in
`authHeaders`; a forwarded header always counts.

## Per-user identity (gateway mode)

When Bastion sits between an agent and sub-agents that must act **as the signed-in user**, each
upstream call has to carry that user's identity, not one fixed token. `forwardHeaders` does this:

```jsonc
{
  "servers": {
    "pfqa": {
      "transport": "http",
      "url": "http://localhost:8011/mcp",
      "protocol": "legacy",
      "connect": "onDemand",
      "forwardHeaders": { "x-cso-identity": "x-cso-delegate-pfqa" },
    },
  },
  "listen": { "mode": "http" },
}
```

The map reads _upstream header ← incoming header_. For every upstream request made while serving a
downstream HTTP request (`initialize`, `tools/list`, `tools/call`, `ping`), Bastion copies the value of
the incoming `x-cso-delegate-pfqa` header onto the upstream request as `x-cso-identity`.

**Bastion holds no credential in this mode. It only passes on what each request carries.**

- **Bound to the request.** The incoming headers live in an `AsyncLocalStorage` for exactly the
  lifetime of one downstream request. A custom `fetch` on the upstream transport reads them at send
  time. Concurrent requests from different users share one upstream connection but never see each
  other's headers.
- **Only listed headers travel.** No other incoming header is forwarded. Hop-by-hop and
  transport-owned headers (`connection`, `mcp-session-id`, `content-type`, …) are rejected as forward
  targets at config load. While `listen.authToken` is set, the incoming `authorization` header (Bastion's
  own bearer token) cannot be forwarded.
- **A forwarded header overrides a static `headers` entry** of the same name.
- **Missing header.** By default (`onMissingForwardedHeader: "error"`) the upstream is not called. The
  caller gets a tool error such as
  `pfqa: the request carried no x-cso-delegate-pfqa header, so the call was not forwarded.`
  Use `"omit"` to call the upstream anyway and let it decide.
- **On-demand connection.** With `connect: "onDemand"`, nothing is sent at start-up. The first request
  that needs the upstream (`tools/list`, or a direct `tools/call` of `pfqa__…`) connects it with that
  request's headers. The tool list is then cached as usual. Health checks skip on-demand upstreams,
  which show as `idle` until first used. A failed connect returns to `idle` with no reconnect timer.
  `connect: "startup"` with `forwardHeaders` connects at boot with the static `headers` only, so use
  `onDemand` when the upstream authenticates `initialize` too.
- **401 is an authentication failure.** It is reported as such in the tool result and in
  `bastion__status` (`lastError`), never as a crash or an unknown tool. One user's 401 does not tear down
  the connection other users share.
- **Values are never recorded.** Logs, audit sinks and `bastion__status` never contain a forwarded
  value. Audit events record only which headers were forwarded (`"forwardedHeaders": ["x-cso-identity"]`).
- **Pinning is shared.** Tool definitions are pinned on first sight and a change is blocked, whichever
  user's request saw it. Only the identity is per request.

`forwardHeaders`, `onMissingForwardedHeader`, `connect` and `authHeaders` are valid only on
`transport: "http"` upstreams. `forwardHeaders` also needs `listen.mode: "http"`. Other combinations
are rejected at config load. See
[`examples/identity-forwarding.config.json`](examples/identity-forwarding.config.json) for three
sub-agents behind one Bastion.

## Delegation checks

_Since v1.2.0._ In gateway mode a caller (say, a master agent working for a signed-in user) sends one
short-lived delegate JWT per sub-agent, each in its own header. Each sub-agent sees only its own token.
Bastion sees the whole request, so it can check what none of them can, **without holding any secret or
key**:

```jsonc
"servers": {
  "pfqa": {
    "transport": "http", "url": "http://localhost:8011/mcp", "protocol": "legacy", "connect": "onDemand",
    "forwardHeaders": { "x-cso-identity": "x-cso-delegate-pfqa" },
    "delegation": {
      "audience": "pfqa",                 // required: what this upstream's tokens must carry in `aud`
      "header": "x-cso-identity",         // forwardHeaders key carrying the JWT (default: the only one)
      "verify": "structural",             // or "signature" (below)
      "maxLifetimeSeconds": 120,          // default 3600
      "clockSkewSeconds": 30,             // default 30
      "allowedActors": ["master-quote-agent"],
      "requireActor": false,
      "maxChainDepth": 2
    }
  }
},
"delegation": { "gatewayAudiences": ["mcp-bastion"], "oneUserPerRequest": true, "recordSubject": "hash" }
```

| Rule                                               | Fires when                                                                               | Default (`balanced`) |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------- | -------------------- |
| `delegation-malformed`                             | not a strict JWS compact token (see below), or a wrongly typed claim                     | block                |
| `delegation-audience-mismatch`                     | no `aud` value equals this upstream's `audience` (a sibling's token)                     | block                |
| `delegation-passthrough`                           | `aud` is absent, or any `aud` value is in `gatewayAudiences`                             | block                |
| `delegation-subject-mixing`                        | the request's delegate tokens name more than one (`iss`, `sub`)                          | block                |
| `delegation-expired` / `-not-yet-valid`            | `now > exp + skew` / `nbf > now + skew`                                                  | block                |
| `delegation-lifetime-excess`                       | `exp − iat > maxLifetimeSeconds`, or no `exp`                                            | block                |
| `delegation-actor-not-allowed` / `-actor-required` | current actor (`act.sub`, else `act.client_id`) not in `allowedActors` / no `act`        | block                |
| `delegation-chain-depth` / `-chain-cycle`          | the `act` chain is longer than `maxChainDepth` / names an actor twice                    | **warn**             |
| `delegation-alg-disallowed`                        | signature mode: `alg` is not in `algorithms` (case-sensitive; `none` and HMAC never are) | block                |
| `delegation-key-unknown`                           | signature mode: no trusted key matches the `kid`, or the key set could not be fetched    | block                |
| `delegation-signature-invalid`                     | signature mode: the signature does not verify under the trusted key                      | block                |
| `delegation-issuer-mismatch`                       | signature mode: `iss` is not the configured `issuer`                                     | block                |

Chain depth and cycles concern prior actors, which RFC 8693 §4.1 calls informational, so they are
medium severity and only warned on unless `security.onDelegationChain` (or the `strict` profile) says
`block`. Everything else follows `security.onDelegation` (`warn` under `observe`).

- **Strict decoding.** Exactly three base64url segments, no padding, canonical encoding, JSON objects
  with unique member names (after escape decoding) and a string `alg`; an optional `Bearer ` prefix is
  allowed. Anything else fails closed as `delegation-malformed`.
- **One verdict per request.** On first need Bastion decodes every delegation-configured token the
  request carries, runs the per-upstream checks and the cross-token subject check, and caches the
  verdict for the rest of the request. The checkers are exported as
  `checkDelegation(policy, carriedHeaders, now)` (structural, synchronous) and
  `checkDelegationAsync(policy, carriedHeaders, now)` (adds signature verification).
- **Before any upstream contact.** A blocked `tools/call` is refused before Bastion connects (on-demand
  connects included), with a tool error naming the rule, never a token or claim value, and an audit event
  with decision `blocked_delegation`. `tools/list` leaves out an upstream the request is blocked from. As a
  backstop, the upstream transport refuses to send a token whose verdict blocks (reconnects and other
  sends made inside the request).
- **Who acted for whom.** Calls to a delegation-configured upstream carry an audit `delegation` record:
  `subject`, `issuer`, `audience`, `tokenId` (`jti`), `expiresAt`, `actors` (current first), `chainDepth`,
  `verified` (`structural`, `signature` when the signature verified, or `failed`) and the findings. Never the token. In `hash` mode the subject is `"hmac:"` + the
  first 16 hex characters of HMAC-SHA256(key, `iss|sub`): an operator with the key can recompute it to find
  one user's records. The key is `delegation.subjectKey`, else `MCP_BASTION_SUBJECT_KEY`, else the audit
  integrity key, else a random key per process, whose pseudonyms do **not** link across restarts or
  across replicas. Set one shared key on every replica to link a user's records; Bastion logs a start-up
  warning while none is set.
- **Status.** `bastion__status` shows, per upstream, `delegation: { mode, audience, lastViolation }`, where
  the last violation is a rule id and a time only.
- **Config checks.** `delegation` needs `forwardHeaders`; `header` must be one of its keys; two upstreams
  cannot share an `audience`, and no upstream audience may be a gateway audience; unknown keys are
  rejected. Signature mode needs `issuer`, a non-empty `algorithms` list and exactly one key source.

### Signature mode

When the issuer signs delegate tokens with an asymmetric key (ES256, EdDSA, RS256, PS256, …), Bastion
can verify them against the issuer's **public** keys:

```jsonc
"delegation": {
  "audience": "pfqa",
  "verify": "signature",
  "issuer": "https://spire.example/identity",               // exact match on `iss`
  "algorithms": ["ES256", "EdDSA"],                          // allow-list; HS256/384/512 and none are rejected
  "jwksUrl": "https://spire.example/.well-known/jwks.json"   // or "jwks": { "keys": [ … public JWKs … ] }
}
```

- **Keys come only from the configured source.** `jku`, `x5u`, `x5c` and embedded `jwk` headers are never
  followed. An inline `jwks` with private or secret members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`)
  is rejected at config load. `jwksUrl` must be HTTPS, except to a loopback host.
- **The algorithm allow-list runs first**, case-sensitively, before any key lookup: `alg: none` (in any
  casing) and HS256 signed with the public key are refused without a fetch. A critical header extension
  (`crit`, e.g. an unencoded payload) is refused.
- **Remote key sets** are fetched on first use and cached. A token with an unknown `kid` triggers at most
  one refetch per 30 s cooldown. A fetch failure or a 5 s timeout **fails closed**: the call is blocked as
  `delegation-key-unknown`, the upstream's `lastError` says the key set is unavailable, and further fetches
  wait for the cooldown.
- **The structural rules still run** on a verified token, under the same names, and the audit record says
  `verified: "signature"`.

**Honest limits.**

- Structural mode **authenticates nothing**: a party that can forge tokens can forge consistent claims. It
  stops misrouting, passthrough, user mixing, stale relay and chain abuse by honest-but-wrong or
  prompt-injected callers. The upstream remains the verifier. Use signature mode (asymmetric tokens) for
  authentication at the gateway.
- Signature mode holds **public keys only**, so Bastion stays keyless: it can verify tokens but never mint
  one. It needs the issuer to sign with an asymmetric algorithm; HS256 tokens can only be checked
  structurally, because verifying them needs the shared secret. It trusts whatever the configured key set
  says, so the security of `jwksUrl` (HTTPS, the issuer's own host) is the security of the check.
- The one-user-per-request check covers only tokens configured with `delegation`.
- Replay inside the token's lifetime is not stopped (no `jti` cache yet; possible later, opt-in, bounded).

See [`examples/delegation.config.json`](examples/delegation.config.json) for three sub-agents.

## Runtime authorization

_New in v1.4, opt-in._ Decide **who may call which tool, with which arguments**, on every call and
before any upstream server is contacted. Inactive unless `authorization.enabled`.

```jsonc
"listen": {
  "mode": "http",
  "clients": {                                   // one bearer token per client, read from the environment
    "docs-assistant":   { "tokenEnv": "BASTION_TOKEN_DOCS" },
    "release-pipeline": { "tokenEnv": "BASTION_TOKEN_RELEASE" },
    "ops-console":      { "tokenEnv": "BASTION_TOKEN_OPS" }
  }
},
"security": { "enforcementProfile": "observe" },   // preview first: log, never block
"authorization": {
  "enabled": true,
  "default": "deny",
  "rules": [
    { "id": "docs-read", "effect": "allow", "principal": { "client": "docs-assistant" },
      "tools": ["files__read_file", "files__list_dir"],
      "args": { "path": { "pathWithin": "/srv/docs" } } },
    { "id": "release-staging", "effect": "allow", "principal": { "client": "release-pipeline" },
      "tools": ["deploy__*"], "args": { "env": { "in": ["staging"] } } },
    { "id": "no-prod-rollback", "effect": "deny", "principal": "*",
      "tools": ["deploy__rollback"], "args": { "env": { "equals": "prod" } } },
    { "id": "ops-control", "effect": "allow", "principal": { "client": "ops-console" },
      "tools": ["bastion__*"] }
  ]
}
```

**Who is calling.** A call carries every identity Bastion has authenticated: the **client** (a named
`listen.clients` bearer token, `default` for `listen.authToken`, or `stdio`), plus the **user** and the
acting **agent** from the call's [delegate token](#delegation-checks) when there is one. Identities named
in arguments, headers, `_meta` or input responses are ignored: a request cannot promote itself by
claiming to be someone else.

**How a call is decided.**

- **Every identity must be permitted.** An agent acting for a user needs the user's grant _and_ its own,
  so an agent's broad service grant is never used for a user who lacks the right (the confused deputy),
  and a user's right is never used by an agent that was not granted it. Earlier agents in a delegation
  chain grant nothing; only the current one counts.
- **Deny overrides allow.** Per identity, any matching `deny` refuses; otherwise an `allow` whose
  argument constraints all hold is needed. With `default: "deny"`, no matching allow means no access.
- **Rules.** `principal` is `"*"` or one of `client`, `user`, `agent` (a name or a list). `tools` are
  namespaced names, exact or ending in one `*`. `args` constrain top-level arguments with `equals`, `in`,
  `max`, `min` and `pathWithin`. Matching is exact: no case folding, Unicode normalisation or type
  coercion; `max`/`min` accept JSON numbers only; `pathWithin` resolves `.` and `..` and checks the
  boundary at a `/` (so `/srv/docs-archive` is not inside `/srv/docs`).
- **Fail closed.** A missing constrained argument fails an `allow`. A `deny` with `args` applies unless
  its constraints can be evaluated and do not hold, so a missing or wrongly typed argument cannot slip
  past a deny.
- **Control tools** (`bastion__*`) are authorized like any tool, under server name `bastion`. With
  `default: "deny"`, grant them to an operator client, as `ops-console` above.

**Where it runs.** In `tools/call`, after the delegation checks and before any upstream contact, so a
refused call never opens a connection carrying the caller's forwarded headers. Continuations
(`input_required` retries) are re-authorized. `tools/list` hides tools a caller could never be allowed.

**Rolling it out.** Start under `enforcementProfile: "observe"`: nothing is refused, and each audit
event carries an `authorization` record (`effect`, deciding `rule`, `violations` such as
`agent:argument`, and `rules`, the deciding rule per identity, e.g.
`{ "client": "orchestrator-files", "user": "files-run" }`, so the record shows which grant admitted
each identity) plus `wouldBlock: "blocked_authorization"` where enforcement would have refused. Rule ids
appear in audit records, so keep personal data (user ids, e-mail addresses) out of them. When
the log shows only refusals you intend, switch to `balanced`. Under `balanced` a refused call is answered
`Blocked by mcp-bastion: this caller is not authorized to call "<tool>" (rule <id>).`; no other policy
content is revealed.

**Trust in user and agent identities.** They come only from a trusted delegate token: one verified in
[signature mode](#signature-mode), or, in structural mode, only with `trustStructuralClaims: true`. Set
that only when the upstream verifies the same token itself, so a forged claim that passes Bastion is still
rejected upstream. A rule naming a `user` or `agent` for a structural-mode upstream is a config error
otherwise, and a token that is present but untrusted refuses the call (`delegation:unverified`). While
`trustStructuralClaims` is on, Bastion logs a start-up warning naming the upstreams it applies to.

**Measured.** This family of checks was pre-registered as test cases in
[mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench) (tag
`authorization-prereg-2026-10-26`) before this code was written. Per-caller MCP authorization also exists
in other gateways (for example agentgateway's CEL rules and ToolHive's Cedar policies), and the
benchmark's pre-registration commits to scoring them side by side.

## Runtime security

_New in v0.2._ Bastion adds a security layer in the tool-call path (an interceptor pipeline), enabled
by default:

- **Rug-pull detection (tool pinning).** Each tool's definition is pinned on first use. If a server
  later changes that definition, the tool is blocked (`onRugPull: "block"`) until an operator reviews it
  and re-approves it out-of-band (operator-only — not an agent-callable tool). This catches a server that
  looks benign at install time and turns malicious afterward.
- **Poisoning inspection.** Tool names and descriptions are scanned for manipulation heuristics
  (instruction override, secret access, data exfiltration, covert instructions, embedded directives,
  hidden/zero-width characters). Because heuristics can false-positive, the default is `warn` (logged
  and reported, not blocked); set `onPoisoning: "block"` to enforce.
- **Shadowing.** When two servers expose a tool with the same name, it's surfaced in the report.

Review everything with the `bastion__security` tool. Each finding says whether it is `heuristic` or
`deterministic`; see [Security model](#security-model).

## Audit & compliance

_Opt-in._ Enable `audit` to record a structured, versioned event for every tool call, including calls
refused by the security layer or by [authorization](#runtime-authorization):

```jsonc
"audit": {
  "enabled": true,
  "includeArgs": "redacted",            // none | redacted | full (default for every sink)
  "tamperEvident": true,                // hash chain; keyed with integrityKey / MCP_BASTION_AUDIT_KEY
  "onSinkFailure": "continue",          // or "block": refuse calls while no sink can deliver
  "sinks": [
    { "type": "file", "path": "./bastion-audit.jsonl", "includeArgs": "full" },
    { "type": "otlp", "endpoint": "https://collector.example:4318",
      "headersEnv": { "authorization": "OTEL_AUTH_HEADER" }, "includeArgs": "none" }
  ],
  "checkpoint": {                       // signed checkpoints (needs tamperEvident)
    "privateKeyFile": "/etc/bastion/checkpoint-private.pem",
    "stateFile": "/var/lib/bastion/audit-state.json",
    "sinks": [{ "type": "webhook", "url": "https://witness.example/checkpoints" }]
  }
}
```

**Events.** Each event names the server, tool, decision (`allowed`, `blocked_rug_pull`,
`blocked_authorization`, …), outcome, findings with their `kind`, the `authorization` record (with the
deciding rule per identity) and the delegation record when present, a `runId`, and a mapping to
**NIST AI RMF** functions and **OWASP LLM Top 10** categories. A call that passed the checks and then
failed before reaching the tool (an on-demand connect refused, an upstream not connected) is recorded
with `outcome: "error"`. `bastion__compliance` returns aggregate totals.

**Each sink is its own security boundary.**

- `console` (stderr), `file` (JSON lines, created `0600`), `webhook` and `otlp` (OpenTelemetry logs).
- Remote sinks must use **HTTPS** unless the host is loopback. Plain HTTP to a remote host is a config
  error unless the sink sets `allowInsecureTransport: true`, which logs a warning.
- Credentials come from the environment (`headersEnv`), not the config file; a missing variable stops
  startup.
- A failed delivery is retried with exponential backoff instead of being dropped. Events wait in a
  bounded queue (`maxQueue`, default 10 000); beyond it the oldest are dropped and counted. Receivers can
  also spot gaps from each event's `seq`.
- `bastion__status` shows each sink's health: `healthy`, `delivered`, `dropped`, `queued`, `lastError`.
- With `onSinkFailure: "block"`, calls are refused (`blocked_audit_unavailable`) while no sink can
  deliver, for deployments where an unaudited call is not acceptable. Bastion's own control tools stay
  usable so the sinks can be inspected and recovered.

**Redaction is first-class.**

- Arguments are not recorded by default. Each sink can record its own level (`includeArgs` per sink):
  for example full arguments to a local file and none to a shared SIEM.
- `redacted` keeps structure and masks values under credential key names and values that look like
  secrets: cloud and provider keys, GitHub, Slack, Stripe, Google and npm tokens, JWTs, `Bearer`
  credentials, passwords in URLs, private-key blocks and `NAME=secret` assignments. The same patterns
  redact secrets from tool **results** before the agent sees them (`redactResponseSecrets`, on by
  default). Measured on a 45-case corpus (`test/redaction-corpus.test.ts`): 29/29 secrets caught, 0/16
  benign look-alikes changed.
- Never written to any sink: tool results, delegate-token values, forwarded header values (names only),
  and the raw user `sub` when `delegation.recordSubject` is `hash`. Arguments are recorded only as
  `includeArgs` allows, so a secret passed as an argument is kept under `full`.
- Redaction is pattern-based. A secret in an unrecognised shape under an unrecognised key can still be
  recorded, so prefer `none` for high-sensitivity sinks.

**Tamper evidence, and its limits.**

- With `tamperEvident`, events form a hash chain. With an `integrityKey` the chain is HMAC-SHA256:
  without the key, a party who rewrites the log cannot recompute it. Unkeyed, it only detects naive
  edits.
- When sinks record arguments differently, the chain (v2) covers each event without its `args` view
  plus an `argsDigest` (HMAC of the full arguments), so every sink verifies the same chain.
- A hash chain cannot show that the newest records were cut off. **Signed checkpoints** can:
  `audit.checkpoint` writes an Ed25519-signed statement of the chain head every `everyEvents` (100)
  events, every `everySeconds` (60) seconds and at shutdown, and each run starts with a `run-start`
  record linked to the previous run through `stateFile`. Send checkpoints to a witness sink the log's
  host cannot rewrite.
- `mcp-bastion audit verify <log> --checkpoints <witness.jsonl> --public-key <pem>` checks the chain,
  `seq` continuity, checkpoint signatures, run links, a log cut short and a deleted run. Exit `0` intact,
  `1` tampered, `2` cannot verify. `mcp-bastion audit keygen --out <dir>` creates the key pair.
- **Limit:** a cut is detected only back to the last checkpoint that reached a witness the attacker
  cannot rewrite; without a witness, cutting a log together with its checkpoints is not detectable. An
  attacker holding the private key can forge checkpoints, so keep it off the log's host.

**Shadow mode.** Under `security.enforcementProfile: "observe"` nothing is blocked, and each event says
what enforcement would have done: `wouldBlock` holds the decision `balanced` would have recorded, a rug
pull appears in `findings` as `tool-definition-changed`, and `responseFindings` / `redactedSecrets`
record what the result scan and inline DLP found (or `secret-in-result` when redaction is off).

## Standards alignment

Every security check maps to recognized frameworks — the **NIST AI Risk Management Framework** (a U.S.
federal standard), the **OWASP Top 10 for LLM (2025)** and **Agentic (2026)** Applications, and
**STRIDE**. The full per-check mapping (with reference links to the MCP-security literature the checks
are drawn from) is in **[docs/CHECKS-MAPPING.md](docs/CHECKS-MAPPING.md)**.

Coverage is measured independently — bastion is scored against a 22-vector attack surface by the
vendor-neutral [mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench) benchmark, with a
public [leaderboard and framework mapping](https://gowthaman90.github.io/mcp-defense-bench/).

## Client setup

The steps are identical for every client — only the **config file location** differs:

| Client         | Where to add the `bastion` entry                   |
| -------------- | -------------------------------------------------- |
| Claude Code    | project `.mcp.json` (or `claude mcp add`)          |
| Cursor         | `~/.cursor/mcp.json` or project `.cursor/mcp.json` |
| Claude Desktop | `claude_desktop_config.json`                       |
| Cline          | `cline_mcp_settings.json`                          |
| Windsurf       | `~/.codeium/windsurf/mcp_config.json`              |

> **Gradual adoption:** you don't have to route every server through Bastion — put only your flaky or
> untrusted servers behind it and leave the rest connected directly.

## Architecture

Bastion is organized into clear layers with a one-directional dependency flow, so each concern is
independently testable and easy to evolve:

```
src/
├── cli.ts              # thin CLI entrypoint (parse → wire → serve)
├── index.ts            # public library API
├── errors.ts           # error hierarchy (BastionError, …)
├── config/             # schema (Zod) + loader
├── core/               # domain: upstream connection lifecycle, aggregation & routing
├── proxy/              # client-facing MCP server + control tools
├── observability/      # logging (audit sinks in v0.3)
└── internal/           # small cross-cutting utilities
```

Design details — including the client-agnostic rationale, the interceptor pipeline, and the audit-sink
strategy — live in the project's design docs.

## Development

```bash
npm install
npm run check      # format:check + lint + typecheck + test (the full gate)
npm test           # unit + end-to-end (in-memory transport) tests
npm run build      # bundle to dist/ (CLI + library)
npm run dev -- --config bastion.config.json
```

| Script                    | Does                                |
| ------------------------- | ----------------------------------- |
| `build`                   | Bundle CLI + library with `tsup`.   |
| `dev`                     | Run the CLI from source with `tsx`. |
| `typecheck`               | `tsc --noEmit` (strict).            |
| `lint` / `lint:fix`       | ESLint (flat config).               |
| `format` / `format:check` | Prettier.                           |
| `test` / `test:watch`     | Vitest.                             |
| `check`                   | Everything above, as one gate.      |

## Roadmap

| Version     | Theme                        | Highlights                                                                                                                    |
| ----------- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **v0.1** ✅ | **Reliability**              | Aggregating proxy, auto-reconnect, `bastion__status` / `__reconnect`.                                                         |
| **v0.2** ✅ | **Runtime security**         | Tool-definition pinning (rug-pull detection), poisoning inspection, shadowing detection.                                      |
| **v0.3** ✅ | **Audit & compliance**       | Pluggable audit sinks (console / file / webhook), NIST AI RMF / OWASP LLM Top 10 mapping.                                     |
| **v1.2** ✅ | **Delegation**               | Keyless checks on delegate tokens: audience, subject mixing, expiry, actor chains, signatures.                                |
| **v1.4**    | **Authorization & evidence** | Per-caller runtime authorization; HTTPS-only, retrying, per-sink-redacted audit sinks; signed checkpoints and `audit verify`. |

Both **stdio** and **Streamable HTTP** transports are supported (see [Transports](#transports)).

## Contributing

Contributions are very welcome — this project is built to be community-owned. Please read
**[CONTRIBUTING.md](./CONTRIBUTING.md)** for the dev setup, project layout, and PR workflow, and our
**[Code of Conduct](./CODE_OF_CONDUCT.md)**.

In short: open an issue for non-trivial changes, keep PRs focused with tests, and make sure
`npm run check` passes (CI runs it on Node 18/20/22). Good first areas: additional client setup
recipes, more upstream test fixtures, and Streamable HTTP transport support.

## Security

`mcp-bastion` is security-adjacent software, so we hold it to a high bar. Please report
vulnerabilities privately — **do not open a public issue**. See **[SECURITY.md](./SECURITY.md)** for
the disclosure process.

## License

[Apache-2.0](./LICENSE) © Gowthaman Arumugam and mcp-bastion contributors
