# Threat model

_Covers mcp-bastion 1.4.x. Last reviewed 2026-11-03._

This document says what mcp-bastion protects, who it protects it from, where the trust boundaries are,
and what it deliberately does **not** protect against. The per-check mapping to STRIDE, NIST AI RMF and
OWASP is in [docs/CHECKS-MAPPING.md](docs/CHECKS-MAPPING.md); how each check behaves under each
enforcement profile is in the README's [Security model](README.md#security-model).

## What Bastion is

Bastion is a proxy that sits between an MCP client (an agent host such as Claude Code, Cursor or a
custom app) and one or more MCP servers ("upstreams"). Every tool listing and tool call passes through
it. It runs either as a local process spawned by the client (stdio) or as a self-hosted gateway
(Streamable HTTP).

```text
 ┌──────────────┐  (1)   ┌──────────────────────────────┐  (2)   ┌──────────────────┐
 │  MCP client  │ ─────► │          mcp-bastion          │ ─────► │  upstream server │
 │ (agent host, │ ◄───── │ checks · authorization · audit│ ◄───── │  (stdio or HTTP) │
 │  the model)  │        └──────────────┬───────────────┘        └──────────────────┘
 └──────────────┘                       │ (3)
                                        ▼
                              audit sinks (file, webhook, OTLP)
```

## Assets

| Asset                           | Why it matters                                                                                                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| The tools the operator approved | An agent should call the tool definitions that were reviewed, not ones swapped in later                                                                                                    |
| Tool arguments and results      | They can carry customer data, credentials, file contents and commands                                                                                                                      |
| Credentials                     | Upstream API keys and tokens in config or environment, forwarded user credentials, Bastion's own bearer tokens and keys (audit HMAC, checkpoint signing, request-state, subject pseudonym) |
| Caller identity                 | Which client, user and agent made each call: the basis for authorization and audit                                                                                                         |
| The audit record                | The evidence of what was allowed, blocked or would have been blocked                                                                                                                       |

## Adversaries

| Adversary                              | Capability we assume                                                                                                                                                                                                                       |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Malicious or compromised upstream**  | Controls everything it sends: tool names, descriptions, schemas and results. Can change them mid-session ("rug pull"), shadow another server's tool names, plant instructions in results, or ask for user input to phish credentials.      |
| **Prompt-injected agent**              | The model follows instructions planted in a result or description. It can call any tool it is shown with any arguments, including trying to send data from one server to another, run commands through arguments, or clear its own blocks. |
| **Unauthorized caller (gateway mode)** | Can reach Bastion's HTTP endpoint over the network. May have no token, a stolen low-privilege token, or a forged delegation token.                                                                                                         |
| **Network attacker**                   | Can observe or modify plaintext traffic between Bastion and remote upstreams or sinks, or use DNS rebinding against a loopback listener.                                                                                                   |
| **Log tamperer**                       | Can edit or truncate audit files after the fact, but does not hold the audit keys.                                                                                                                                                         |

## Trust boundaries

1. **Client → Bastion.** Over stdio, the client spawned Bastion, so the client is trusted as the local
   user. Over HTTP, every request must carry a bearer token (`listen.authToken` or `listen.clients`),
   and a non-loopback bind without one is refused at start-up. A loopback listener checks the `Origin`
   header to stop DNS rebinding. The **model** inside the client is never trusted: its tool calls are
   checked like any other input.
2. **Bastion → upstream.** Upstreams are untrusted. Their definitions are pinned on first sight, and
   later changes are detected. Their results are scanned before they reach the agent. HTTP upstreams
   without an authentication header, or reached over plain HTTP, are flagged.
3. **Bastion → audit sinks.** Remote sinks must use HTTPS unless the host is loopback. Records are
   redacted before they leave Bastion. The hash chain (HMAC-SHA256 when a key is set) shows a changed
   record. Ed25519-signed checkpoints sent to a separate witness show a truncated log.

## Threats and mitigations

| Threat                                                | Mitigation                                                                                                                                              | Kind                                |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Rug pull or mid-session tool injection                | Definitions are pinned and hash-compared on every listing; a changed tool is blocked until an **operator** re-approves it. The agent cannot approve it. | deterministic                       |
| Server identity swap, config drift                    | Server identity and configuration are pinned on first sight; a weakening is flagged                                                                     | deterministic                       |
| Out-of-schema or undeclared arguments                 | Arguments are validated against the pinned schema                                                                                                       | deterministic                       |
| Command injection, injected instructions in arguments | Argument pattern scan                                                                                                                                   | heuristic (blocks under `balanced`) |
| Cross-server exfiltration (confused deputy)           | Cross-server data-flow check on arguments                                                                                                               | deterministic                       |
| Credential phishing through `input_required`          | MRTR gate on input requests; request-state continuations are custody-checked                                                                            | mixed                               |
| Tool poisoning or shadowing                           | Description scan and cross-server name-collision check                                                                                                  | heuristic (warns under `balanced`)  |
| Injection or steering in results                      | Response scan                                                                                                                                           | heuristic (warns under `balanced`)  |
| Secrets leaking through results                       | Inline redaction of known secret shapes                                                                                                                 | heuristic                           |
| Unauthorized caller or over-broad access              | Bearer authentication, then runtime authorization per client, user and agent, decided before any upstream contact                                       | deterministic                       |
| Forged, misdirected or expired delegation tokens      | Delegation checks (audience, pass-through, expiry and lifetime, chain depth and cycles); signature mode verifies tokens against the issuer's JWKS       | deterministic                       |
| Audit log edited or truncated                         | Keyed hash chain, signed checkpoints, sink-failure policy (`onSinkFailure`)                                                                             | deterministic                       |
| Personal data in the audit record                     | Arguments left out by default; user subjects pseudonymised with a keyed hash by default                                                                 | —                                   |

Under the `observe` profile none of these blocks. Each one is recorded as the decision `balanced` would
have made (`wouldBlock`), so a team can measure false positives before turning enforcement on.

## Assumptions

- The **host, the Bastion process and its config file are trusted.** Anyone who can edit the config,
  set environment variables or attach to the process can turn every check off.
- **Keys are managed by the operator.** Audit, checkpoint, request-state and subject keys come from the
  operator's secret store. Without an audit key, the hash chain catches accidental corruption only.
- **The first sight of a tool is trusted** (trust on first use). A definition that was already malicious
  when first pinned, or that changed while Bastion was not running, is not flagged as a rug pull. It is
  still scanned by the heuristics.
- **Pins live in memory.** Each process (each laptop, each gateway replica) keeps its own pins, and a
  restart re-pins the current definitions.
- **Identities are only as good as their source.** Bastion authenticates its own bearer clients. It
  verifies delegation tokens only in signature mode. In structural mode it trusts their claims only when
  `trustStructuralClaims` is set, and it warns at start-up when it does.

## Non-goals

Bastion does not, and does not try to:

- **sandbox the upstream server.** A server that is allowed to run can still do harm with the access it
  has on its own host, such as its filesystem and network.
- **guarantee that heuristics catch new payloads.** Poisoning, response and argument-pattern checks
  match known patterns and can be evaded. They are risk signals, not proof a tool is safe.
- **find every secret.** Redaction covers known secret shapes.
- **protect against a compromised host, client application or model provider.**
- **replace the client's own consent prompts** or a human review of which servers to install.
- **check what an upstream does with data you send it.** That is governed by the upstream and your
  policies.

## Reporting

Found a way past one of these mitigations? Report it privately: see [SECURITY.md](SECURITY.md). Bypasses
of the heuristic checks by a new payload are better contributed as test vectors to
[mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench).
