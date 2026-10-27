# Authorization dev fixtures (copied from mcp-defense-bench)

These 12 files are verbatim copies of `staging/authorization/dev/` in
[mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench) at tag
`authorization-prereg-2026-10-26` (commit 3198cce), the pre-registered `authorization` vector family.
`test/authorization-dev-fixtures.test.ts` replays each one through a real Bastion gateway: the
attack must be refused before any upstream contact, the benign control must go through.

Only the dev split is here. The held-out split is run once, by the benchmark, after a defender
freeze. Do not edit these files; refresh them from the benchmark instead.
