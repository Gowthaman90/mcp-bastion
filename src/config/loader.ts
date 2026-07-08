/**
 * Loading and validation of Bastion configuration files.
 *
 * @packageDocumentation
 */
import { readFile } from "node:fs/promises";

import { ConfigError } from "../errors.js";
import { BastionConfigSchema, type BastionConfig } from "./schema.js";

/**
 * Read, parse, and validate a Bastion configuration file.
 *
 * @param path Path to a JSON configuration file.
 * @returns The fully validated configuration with defaults applied.
 * @throws {@link ConfigError} if the file cannot be read, is not valid JSON,
 *   fails schema validation, or defines no upstream servers.
 */
export async function loadConfig(path: string): Promise<BastionConfig> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    throw new ConfigError(`Could not read config file "${path}": ${(err as Error).message}`);
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (err) {
    throw new ConfigError(`Invalid JSON in config "${path}": ${(err as Error).message}`);
  }

  const parsed = BastionConfigSchema.safeParse(json);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `  - ${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("\n");
    throw new ConfigError(`Invalid Bastion config "${path}":\n${issues}`);
  }

  if (Object.keys(parsed.data.servers).length === 0) {
    throw new ConfigError(`Config "${path}" defines no upstream servers under "servers".`);
  }

  return parsed.data;
}
