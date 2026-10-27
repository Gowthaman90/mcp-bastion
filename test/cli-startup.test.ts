import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { checkHttpListenOptions } from "../src/proxy/index.js";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const tsx = fileURLToPath(new URL("../node_modules/.bin/tsx", import.meta.url));

/** Run the CLI with a config; resolve with its exit code and stderr. */
function runCli(configPath: string): Promise<{ code: number | null; output: string }> {
  return new Promise((resolve) => {
    execFile(tsx, [cli, "--config", configPath], { timeout: 20_000 }, (err, stdout, stderr) => {
      resolve({
        code: err ? ((err as { code?: number }).code ?? 1) : 0,
        output: `${stdout}${stderr}`,
      });
    });
  });
}

describe("CLI startup order", () => {
  it("refuses an unauthenticated public bind before spawning any upstream", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bastion-cli-"));
    const marker = join(dir, "upstream-started");
    const config = join(dir, "bastion.json");
    // The upstream writes a marker file the moment it is spawned.
    writeFileSync(
      config,
      JSON.stringify({
        servers: {
          probe: {
            transport: "stdio",
            command: process.execPath,
            args: ["-e", `require("fs").writeFileSync(${JSON.stringify(marker)}, "x")`],
          },
        },
        listen: { mode: "http", host: "0.0.0.0", port: 39871 },
      }),
    );

    const { code, output } = await runCli(config);

    expect(code).toBe(1);
    expect(output).toMatch(/Refusing to bind mcp-bastion HTTP to non-loopback host/);
    expect(existsSync(marker)).toBe(false);
  }, 30_000);
});

describe("checkHttpListenOptions", () => {
  it("accepts a loopback bind without credentials", () => {
    expect(() => checkHttpListenOptions({ host: "127.0.0.1" })).not.toThrow();
  });

  it("refuses a public bind without credentials", () => {
    expect(() => checkHttpListenOptions({ host: "0.0.0.0" })).toThrow(/non-loopback/);
  });

  it("accepts a public bind with a bearer token", () => {
    expect(() =>
      checkHttpListenOptions({ host: "0.0.0.0", authToken: "t0k3n-long-enough" }),
    ).not.toThrow();
  });
});
