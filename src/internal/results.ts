/**
 * Helpers for constructing MCP `CallToolResult` values.
 *
 * @packageDocumentation
 */
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

/**
 * Build a {@link CallToolResult} carrying a single text block.
 *
 * @param text    The text content to return to the caller.
 * @param isError Whether this result represents a tool-level error (default `false`).
 */
export function textResult(text: string, isError = false): CallToolResult {
  return { content: [{ type: "text", text }], isError };
}
