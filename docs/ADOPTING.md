# Adopting mcp-bastion in your organization

This guide is for a platform or security team rolling out MCP (Model Context Protocol) servers to
developers, and wanting a control point in the tool-call path before it goes wide. It runs in three
stages, and each one has to earn the next:

| Stage               | Time                   | Can it break anything?                        | You come out with                                                            |
| ------------------- | ---------------------- | --------------------------------------------- | ---------------------------------------------------------------------------- |
| **1. Trial**        | 10 minutes, one laptop | No. One person, one server, `observe` mode    | "It works with our client and our servers"                                   |
| **2. Shadow pilot** | 2–4 weeks, one team    | No. `observe` never blocks a call (see below) | An audit log of what _would_ have been blocked, and your false-positive rate |
| **3. Enforcement**  | rollout                | Yes, by design                                | Blocking on the checks your pilot showed are clean                           |

The [evidence a security reviewer will ask for](#evidence-for-your-security-review) is at the end.

---

## Stage 1 — 10-minute trial

You need Node.js 20 or later and one MCP server you already use. The example uses the official
filesystem server.

**1. Write a Bastion config** somewhere stable, e.g. `~/mcp-bastion/bastion.config.json`. Move your
server's entry here, exactly as it was in your client's config:

```json
{
  "servers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/you/projects"]
    }
  },
  "security": { "enforcementProfile": "observe", "redactResponseSecrets": false },
  "audit": {
    "enabled": true,
    "includeArgs": "none",
    "tamperEvident": true,
    "sinks": [{ "type": "file", "path": "/Users/you/mcp-bastion/bastion-audit.jsonl" }]
  }
}
```

- `enforcementProfile: "observe"` means warn only. Nothing is blocked.
- `redactResponseSecrets: false` turns off the one inline change Bastion makes even in `observe`,
  which is stripping credential-shaped strings out of tool results. Turn it off for the trial and
  pilot, so the claim "nothing changed" is literally true. A secret in a result is still recorded in
  the audit log as a `secret-in-result` finding; the result itself is left untouched.
- `includeArgs: "none"` keeps tool arguments out of the log. Start here.
- **Use absolute paths.** Desktop clients don't start Bastion from your project directory, so a
  relative path fails.

**2. Point your client at Bastion instead of the server.** Pick your client:

<details open><summary><b>Claude Desktop</b>, in <code>~/Library/Application Support/Claude/claude_desktop_config.json</code> (macOS) or <code>%APPDATA%\Claude\claude_desktop_config.json</code> (Windows)</summary>

```json
{
  "mcpServers": {
    "bastion": {
      "command": "npx",
      "args": ["-y", "mcp-bastion", "--config", "/Users/you/mcp-bastion/bastion.config.json"]
    }
  }
}
```

If the server fails with `spawn npx ENOENT` (common with nvm or Volta), replace `"npx"` with the
full path that `which npx` prints.
</details>

<details><summary><b>Cursor</b>, in <code>~/.cursor/mcp.json</code> (global) or <code>.cursor/mcp.json</code> (project)</summary>

```json
{
  "mcpServers": {
    "bastion": {
      "command": "npx",
      "args": ["-y", "mcp-bastion", "--config", "/Users/you/mcp-bastion/bastion.config.json"]
    }
  }
}
```

</details>

<details><summary><b>VS Code</b> (Copilot agent mode), in <code>.vscode/mcp.json</code>. Note the different shape: <code>"servers"</code> plus <code>"type"</code></summary>

```json
{
  "servers": {
    "bastion": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "mcp-bastion", "--config", "${workspaceFolder}/bastion.config.json"]
    }
  }
}
```

</details>

<details><summary><b>Claude Code</b></summary>

```bash
claude mcp add bastion -- npx -y mcp-bastion --config /Users/you/mcp-bastion/bastion.config.json
```

</details>

These snippets follow each client's documented config format. Bastion itself has been run end to
end with Claude Code and with Node.js, Python, .NET and OpenAI Agents SDK clients, over stdio and
HTTP. If a snippet doesn't work in your client, please
[open an issue](https://github.com/Gowthaman90/mcp-bastion/issues).

**3. Restart the client and check.** Ask the agent to call `bastion__status`. You should see your
server `connected` with its tool count. Your server's tools now appear under a prefix
(`fs__read_text_file`), next to four Bastion control tools:

| Control tool          | What it tells you                                                             |
| --------------------- | ----------------------------------------------------------------------------- |
| `bastion__status`     | Each upstream's connection state, tool count, last error                      |
| `bastion__security`   | Every tool's pin status (`pinned` / `changed`), poisoning findings, shadowing |
| `bastion__compliance` | Audit events so far, grouped by decision and by NIST AI RMF / OWASP control   |
| `bastion__reconnect`  | Force a reconnect to an upstream                                              |

**4. Use a tool once, then look at the log:**

```bash
jq -c '{seq, server, tool, decision, outcome}' ~/mcp-bastion/bastion-audit.jsonl
```

One line per tool call, with `decision: "allowed"`. That's the trial. If anything here didn't work,
[open an issue](https://github.com/Gowthaman90/mcp-bastion/issues). That's useful to us too.

---

## Stage 2 — Shadow pilot (`observe`)

**Goal:** run Bastion in front of a real team's real servers for 2–4 weeks, never blocking, and
answer two questions with data:

1. What would Bastion have blocked?
2. Of those, how many were false positives?

### What `observe` does and doesn't change

- **Never blocks.** All ten enforcing actions (`onRugPull`, `onSchemaViolation`, `onDataFlow`,
  `onIdentityChange`, `onInputRequired`, `onDelegation`, `onDelegationChain`, `onAuthorization`,
  `onPoisoning`, `onResponse`) resolve to `warn`. We checked this against an upstream that sends a command-injection
  argument, an undeclared parameter, and a mid-session tool-definition change. All three passed
  through under `observe` and were blocked under the default `balanced` profile.
- **Does change:** tool names get a prefix (`fs__…`), and four `bastion__*` tools are added. Bastion
  also reconnects a crashed upstream automatically, which is usually welcome, but it does change
  behaviour.
- **Redaction:** keep `redactResponseSecrets: false` during the pilot (see Stage 1).
- **What gets recorded:** each audit event says what enforcement would have done. `wouldBlock` holds
  the decision the `balanced` profile would have recorded (for example `blocked_rug_pull` or
  `blocked_schema`), a rug pull appears in `findings` as `tool-definition-changed`, and
  `responseFindings` / `redactedSecrets` record what the result scan found.

### Deploying it

- **Per developer (stdio):** ship the same `bastion.config.json` through your device-management or
  dotfiles tooling. Each laptop writes its own audit file, so add an `otlp` or `webhook` sink to
  collect centrally:

  ```json
  "sinks": [
    { "type": "file", "path": "/Users/you/mcp-bastion/bastion-audit.jsonl" },
    { "type": "otlp", "endpoint": "https://otel-collector.internal:4318" }
  ]
  ```

- **Shared gateway (Streamable HTTP):** run one Bastion as a service (`--http 3000`, or
  `listen.mode: "http"`) in front of shared remote servers, with per-user identity forwarding. See
  [Per-user identity (gateway mode)](../README.md#per-user-identity-gateway-mode). If you run more than
  one replica, set `security.requestStateKey` (or `MCP_BASTION_REQUEST_STATE_KEY`) to the same value
  on every replica.

- **Key the audit chain.** Set `MCP_BASTION_AUDIT_KEY` from your secret store. With a key, the hash
  chain is HMAC-SHA256, so someone who can edit the log file can't forge a valid chain. Without a key,
  the chain only catches accidental corruption.

### Reading the results

What `balanced` would have blocked, by decision:

```bash
jq -r 'select(.wouldBlock) | .wouldBlock' bastion-audit.jsonl | sort | uniq -c | sort -rn
```

Everything Bastion flagged:

```bash
jq -r 'select((.findings // []) | length > 0)
       | [.ts, .server, .tool, (.findings | map(.rule) | join(","))] | @tsv' bastion-audit.jsonl
```

Counts by rule. This is your false-positive worksheet:

```bash
jq -r '(.findings // [])[].rule' bastion-audit.jsonl | sort | uniq -c | sort -rn
```

Was the log edited? Run this with `mcp-bastion` installed (`npm i mcp-bastion`). It prints `-1` if
the chain is intact, otherwise the index of the first broken event:

```js
// verify-audit.mjs  —  node verify-audit.mjs bastion-audit.jsonl
import fs from "node:fs";
import { verifyChain } from "mcp-bastion";
const events = fs
  .readFileSync(process.argv[2], "utf8")
  .trim()
  .split("\n")
  .map((l) => JSON.parse(l));
console.log(verifyChain(events, process.env.MCP_BASTION_AUDIT_KEY));
```

For each flagged rule, decide: **real** (would have been a good block), **noise** (false positive in
your environment), or **unclear**. That table is your exit criterion for the pilot.

---

## Stage 3 — Enforcement

Turn blocking on **one check at a time**, starting with the checks that are deterministic (not
heuristic) and that your pilot showed were clean. A good order:

1. **Switch to `balanced`**, the shipped default:

   ```json
   "security": { "enforcementProfile": "balanced" }
   ```

   This blocks rug pulls, argument/schema violations and command injection, cross-server data flow,
   identity changes, credential-phishing `input_required` rounds, delegation failures, and (if you
   turned on [runtime authorization](../README.md#runtime-authorization)) calls no rule allows. It only
   warns on the heuristics (description and response poisoning), and it redacts secrets from results
   again.

2. **Overrides for anything that was noisy in your pilot**, check by check. An explicit `on*` value
   always wins over the profile:

   ```json
   "security": { "enforcementProfile": "balanced", "onDataFlow": "warn" }
   ```

3. **Consider `strict`**, which also blocks on the heuristics, only for high-risk servers (shell,
   cloud admin, finance data) and only after their pilot was clean. Bastion only reads its config at
   startup, so to give different servers different strictness, run separate Bastion instances.

**When a block happens,** the agent receives a tool error that starts `Blocked by mcp-bastion:` and
says which check fired and how to override it. The audit event has `outcome: "blocked"` and a
`decision` such as `blocked_rug_pull`.

**Rug pulls are re-approved by an operator, never by the agent.** On purpose, the agent can't clear
a rug-pull block. `bastion__approve` isn't exposed, and Bastion refuses a direct call to it, so a
prompt-injected agent can't approve the tool it was blocked from. Tool pins live in memory. The operator workflow is: check the change (`bastion__security` shows `status: "changed"`),
then restart Bastion. It re-pins the current definitions on first sight.

Two consequences to know about:

- A definition that changes while Bastion is **not running** is pinned as new on the next start, and
  isn't flagged.
- Each Bastion process (each laptop, each gateway replica) keeps its own pins.

**Roll back** by setting `enforcementProfile` back to `"observe"` and restarting the client or
gateway. There's no state to migrate.

---

## Evidence for your security review

These are the questions a security or procurement reviewer typically asks, with where to find each
answer.

| Question                                   | Answer / evidence                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| What is it, and what licence?              | Apache-2.0 TypeScript MCP proxy, published as `mcp-bastion` on npm and listed in the official MCP Registry as `io.github.Gowthaman90/mcp-bastion`. The similarly named `vaquarkhan/MCP-Bastion` is a different project.                                                                                                                                                       |
| Where does data go?                        | Nowhere by default. Bastion is a local process (stdio) or a self-hosted service (HTTP), with no telemetry. Audit events go only to the sinks you configure. Tool arguments are not logged unless you set `includeArgs`.                                                                                                                                                       |
| What does it defend against, and what not? | Per-check mapping to STRIDE, NIST AI RMF and OWASP LLM/Agentic Top 10: [CHECKS-MAPPING.md](CHECKS-MAPPING.md). ⏳ A threat model with trust boundaries and explicit non-goals is planned as `THREAT-MODEL.md`.                                                                                                                                                                |
| How well does it work?                     | Scored on the open [mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench) (same author; corpus, scoring code and pre-registered held-out set are public): 66% weighted coverage on development fixtures, 53% held-out, zero false positives on matched controls (v0.9.0). The benign false-positive rate in _your_ environment comes from your pilot.          |
| Is it tested?                              | CI on Node 20/22/24 runs format, lint, typecheck and the test suite. CodeQL runs weekly and on every PR. The benchmark regression gate fails any PR that lowers coverage or adds a false positive.                                                                                                                                                                            |
| How do we report a vulnerability?          | Privately, through GitHub private vulnerability reporting or email. Response targets and scope: [SECURITY.md](../SECURITY.md).                                                                                                                                                                                                                                                |
| Can we verify the package we install?      | Releases after 1.4.1 are published from GitHub Actions with npm provenance, which ties each package to the commit and workflow that built it. Check with `npm audit signatures`. Earlier versions were published by hand: review `dist/` against the tagged source. ⏳ A CycloneDX SBOM attached to each release is planned. Always install a pinned version with a lockfile. |
| Supply-chain hygiene score?                | ⏳ OpenSSF Scorecard planned.                                                                                                                                                                                                                                                                                                                                                 |
| Versioning and support?                    | Semver. The latest minor gets fixes; the previous minor gets security fixes for 3 months after the next one ships (see [SECURITY.md](../SECURITY.md)). The audit event schema is versioned (`schemaVersion: 1`).                                                                                                                                                              |
| Who maintains it? Bus factor?              | One maintainer today (Gowthaman Arumugam). Contributions are welcome under [CONTRIBUTING.md](../CONTRIBUTING.md). If this is a blocker for you, say so. It's exactly the feedback we need.                                                                                                                                                                                    |
| Commercial support?                        | None offered. Help comes through GitHub issues and discussions.                                                                                                                                                                                                                                                                                                               |

---

## Tell us how it went

Whatever the outcome, an issue describing your pilot (anonymised is fine) helps make the project
better. If Bastion ends up in real use, you're welcome to add your organization to
[ADOPTERS.md](../ADOPTERS.md) by pull request, but only if your organization is happy to be named.
