/**
 * Stable hashing of tool definitions, used to pin an approved definition and
 * detect later changes ("rug pulls").
 *
 * @packageDocumentation
 */
import { createHash } from "node:crypto";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Deterministically serialize a JSON value with object keys sorted, so that
 * semantically-equal definitions always produce identical strings regardless of
 * key ordering.
 */
function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(record[k])}`).join(",")}}`;
}

/**
 * Compute a stable SHA-256 fingerprint of the security-relevant parts of a tool
 * definition: its name, description, and input schema. Two definitions with the
 * same fingerprint are treated as identical.
 *
 * @param tool The tool definition.
 * @returns A hex-encoded SHA-256 digest.
 */
export function hashToolDefinition(tool: Tool): string {
  const subset = {
    name: tool.name,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? {},
  };
  return createHash("sha256").update(canonicalize(subset)).digest("hex");
}
