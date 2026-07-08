# Releasing mcp-bastion

This is the maintainer checklist for cutting a release to npm. The package publishes the bundled
`dist/` (built by `prepublishOnly`), `README.md`, and `LICENSE`.

## Prerequisites

- You are an npm owner/maintainer of `mcp-bastion` and have run `npm login`.
- You have push access to the repository and can create GitHub releases.
- `main` is green in CI.

## Steps

1. **Sync and verify.**

   ```bash
   git checkout main && git pull
   npm ci
   npm run check          # format + lint + typecheck + tests
   npm run build          # sanity-check the bundle
   npm pack --dry-run     # confirm tarball contents (dist + README + LICENSE)
   ```

2. **Update the changelog.** Move items from `## [Unreleased]` into a new `## [x.y.z] - YYYY-MM-DD`
   section and update the link references at the bottom.

3. **Bump the version.** This updates `package.json`, commits, and tags:

   ```bash
   npm version patch      # or: minor | major
   ```

   Also bump `BASTION_VERSION` in `src/core/constants.ts` to match.

4. **Publish.** `prepublishOnly` runs the build automatically:

   ```bash
   npm publish
   ```

   For a pre-release, use a tag: `npm version prerelease --preid=rc && npm publish --tag next`.

5. **Push and release on GitHub.**

   ```bash
   git push --follow-tags
   ```

   Create a GitHub Release for the tag, pasting the changelog section as the notes.

6. **Smoke-test the published package.**

   ```bash
   npx mcp-bastion@latest --version
   ```

## Versioning

- Pre-1.0: `0.MINOR.PATCH`. New features bump MINOR; fixes bump PATCH. Breaking changes are allowed in
  MINOR while pre-1.0, but call them out prominently in the changelog.
- Keep `BASTION_VERSION` (constants) and `package.json` version in lockstep.
