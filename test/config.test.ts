import { describe, expect, it } from "vitest";
import { writeFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadConfig } from "../src/config/index.js";

async function tmpConfig(contents: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "bastion-cfg-"));
  const path = join(dir, "bastion.config.json");
  await writeFile(path, contents, "utf8");
  return path;
}

describe("loadConfig", () => {
  it("loads a valid config and applies defaults", async () => {
    const path = await tmpConfig(
      JSON.stringify({ servers: { fs: { command: "node", args: ["server.js"] } } }),
    );
    const cfg = await loadConfig(path);
    const fs = cfg.servers.fs;
    expect(fs.transport).toBe("stdio");
    if (fs.transport === "stdio") expect(fs.command).toBe("node");
    expect(cfg.reconnect.auto).toBe(true); // default applied
    expect(cfg.namespace.separator).toBe("__"); // default applied
  });

  it("rejects a config with no servers", async () => {
    const path = await tmpConfig(JSON.stringify({ servers: {} }));
    await expect(loadConfig(path)).rejects.toThrow(/no upstream servers/i);
  });

  it("rejects invalid JSON", async () => {
    const path = await tmpConfig("{ not json");
    await expect(loadConfig(path)).rejects.toThrow(/Invalid JSON/i);
  });

  it("rejects a server missing a command", async () => {
    const path = await tmpConfig(JSON.stringify({ servers: { bad: { args: [] } } }));
    await expect(loadConfig(path)).rejects.toThrow(/Invalid Bastion config/i);
  });
});
