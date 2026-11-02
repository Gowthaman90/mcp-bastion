# Privacy policy

_Last updated: 2026-11-02_

mcp-bastion is open-source software that you run yourself, on a laptop or as a self-hosted service.
The project has no servers or accounts, and collects no data from anyone.

## What the project collects

Nothing. mcp-bastion has no telemetry, analytics, crash reporting or update checks, and it never
contacts the project or its maintainer.

## Where your data goes

mcp-bastion connects only to the addresses in your configuration:

- **Upstream MCP servers.** Tool calls and their results pass through Bastion to the servers you
  configure, as they would without it.
- **Audit sinks.** If you turn on `audit`, events go only to the sinks you configure (a file, a
  webhook, or an OTLP endpoint). Tool arguments are left out unless you set `audit.includeArgs`.
- **JWKS URLs.** In delegation signature mode, Bastion fetches public keys from the `jwksUrl` you
  configure.

By default, user subjects from delegate tokens are written to audit events as keyed pseudonyms, not
in clear text (`delegation.recordSubject: "hash"`; set it to `"plain"` only if your policy allows). What happens to data after it reaches your upstreams or sinks is governed by those services and
by your organization's policies.

## Third parties

Installing the package from npm or reading this repository on GitHub is covered by
[npm's](https://docs.npmjs.com/policies/privacy) and
[GitHub's](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement)
privacy policies. The maintainer gets only the aggregate download and traffic counts those services
show every package owner.

## Contact

Questions about this policy: open an issue, or email agowthaman1990@outlook.com.
