# Security Policy

`mcp-bastion` sits in the tool-call path of AI agents, so its own security matters. Thank you for
reporting issues responsibly.

## Supported versions

| Version              | Supported                                                 |
| -------------------- | --------------------------------------------------------- |
| 1.5.x (latest minor) | ✅ security and bug fixes                                 |
| 1.4.x                | ✅ security fixes until 2027-02-04 (3 months after 1.5.0) |
| 1.3.x                | ✅ security fixes until 2027-01-27 (3 months after 1.4.0) |
| < 1.3                | ❌ please upgrade                                         |

From 1.x on we follow semantic versioning. When a new minor ships, the previous minor gets security
fixes for 3 months; a window that has already started keeps its end date. Older minors are not
supported.

## Reporting a vulnerability

**Please don't report vulnerabilities in public issues, discussions, or pull requests.**

Use one of these private channels:

- **GitHub private vulnerability reporting** (preferred): the repository's _Security_ tab →
  _Report a vulnerability_.
- **Email:** agowthaman1990@outlook.com, with `[mcp-bastion security]` in the subject.

It helps if you include:

- what the issue is, and what an attacker could do with it
- steps to reproduce (a minimal config plus a malicious or mock upstream is ideal)
- affected version(s), transport (stdio / HTTP), and Node.js version
- any fix you'd suggest

## Scope

**In scope:** flaws in mcp-bastion itself, for example:

- a way to get a call past a check that is configured to `block`
- a way for the agent or an upstream to clear a block or re-approve a tool
- leaking secrets or arguments into logs or audit sinks against the configured `includeArgs`
- forging or silently truncating a _keyed_ audit chain
- auth or identity-forwarding bypass in HTTP / gateway mode
- crashes or resource exhaustion triggered by a malicious upstream

**Usually out of scope** (report it to the relevant project instead):

- vulnerabilities in an upstream MCP server
- vulnerabilities in the MCP client
- vulnerabilities in the MCP SDK

Also out of scope:

- heuristic checks (description or response poisoning) missing a _new_ payload. These are
  bypassable by design. Please open a normal issue or contribute a vector to
  [mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench).
- anything that needs control of the host, the config file, or the Bastion process

If you're not sure, report it privately anyway.

## What to expect

| Step                                      | Target                                                                                          |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Acknowledgement                           | within 3 business days                                                                          |
| Initial assessment and severity (CVSS)    | within 7 business days                                                                          |
| Fix released for high and critical issues | within 30 days of confirmation where feasible                                                   |
| Public disclosure                         | when the fix ships, or 90 days after the report, whichever is first (unless we agree otherwise) |

Confirmed vulnerabilities are published as a **GitHub Security Advisory** with a **CVE** requested
through GitHub. The fix goes into the changelog, and you're credited unless you'd rather not be.

## Safe harbor

We won't pursue or support legal action against good-faith research that follows this policy:

- you test only against your own installations
- you avoid harming others' data or services
- you give us reasonable time to fix before public disclosure

There's no bug bounty.
