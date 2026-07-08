import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/cli.ts", "src/index.ts"],
  format: ["esm"],
  target: "node18",
  platform: "node",
  clean: true,
  dts: true,
  sourcemap: true,
  // cli.ts carries a `#!/usr/bin/env node` shebang; tsup preserves it on the entry.
});
