# Contributing to mcp-bastion

Thanks for your interest in improving mcp-bastion! This project is built to be
community-owned, and thoughtful contributions of all sizes are welcome — code,
tests, docs, bug reports, and ideas.

By participating, you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md).

## Ways to contribute

- 🐛 **Report bugs** or unexpected behavior via an issue.
- 💡 **Propose features** — open an issue to discuss non-trivial changes _before_ investing in a PR.
- 📝 **Improve docs** — README, client setup recipes, examples.
- 🧪 **Add tests** — especially new upstream fixtures and edge cases.
- 🔧 **Send PRs** — see the workflow below.

Good first areas: additional client setup recipes, more upstream test fixtures, and Streamable HTTP
transport support.

## Development setup

Requires Node.js **>= 18**.

```bash
git clone <your-fork-url>
cd mcp_bastion
npm install

npm run check      # the full gate: format:check + lint + typecheck + test
npm test           # tests only (unit + end-to-end via in-memory transport)
npm run dev -- --config bastion.config.json
npm run demo       # narrated kill-and-recover walkthrough
```

**`npm run check` must pass before you push.** CI runs the same gate on Node 18, 20, and 22.

## Project layout

The code is organized into layers with a one-directional dependency flow. Please keep new code in the
layer that matches its responsibility:

| Path                 | Responsibility                                                     |
| -------------------- | ------------------------------------------------------------------ |
| `src/config/`        | Configuration schema (Zod) and loading/validation.                 |
| `src/core/`          | Domain logic: upstream connection lifecycle, aggregation, routing. |
| `src/proxy/`         | The client-facing MCP server and Bastion's control tools.          |
| `src/observability/` | Logging today; audit sinks in a later release.                     |
| `src/internal/`      | Small, dependency-free cross-cutting utilities.                    |
| `src/errors.ts`      | The `BastionError` hierarchy.                                      |
| `src/cli.ts`         | Thin CLI entrypoint.                                               |
| `src/index.ts`       | Public library API.                                                |

## Coding standards

- **TypeScript, strict.** No `any` escapes; prefer precise types.
- **Client-agnostic.** Never depend on a specific MCP client's API — only on the MCP spec and the
  official SDK. If a change would only work in one client, it doesn't belong here.
- **stdout is sacred.** On the stdio transport, stdout carries JSON-RPC. All logging goes through the
  shared logger (stderr). Never `console.log` to stdout in runtime code.
- **Doc comments.** Public modules get a file-level banner; exported symbols get JSDoc
  (`@param` / `@returns` / `@throws`). Match the surrounding style.
- **Formatting & lint** are enforced by Prettier and ESLint. Run `npm run lint:fix` and
  `npm run format` before committing.

## Pull request workflow

1. Fork and create a topic branch (`feat/…`, `fix/…`, `docs/…`).
2. Make focused changes; **add or update tests** for any behavior change.
3. Run `npm run check` locally until green.
4. Write a clear PR description: what changed, why, and how you verified it.
5. Keep PRs small and single-purpose — they review and merge faster.

We loosely follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`) for titles.

## Reporting security issues

Please do **not** open public issues for vulnerabilities. See [SECURITY.md](./SECURITY.md).
