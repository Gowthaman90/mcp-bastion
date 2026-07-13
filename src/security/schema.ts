/**
 * Argument/schema validation: checks a tool call's arguments against the tool's own declared
 * `inputSchema`. Two classes of violation are security-relevant:
 *
 *   - **undeclared parameters** — an argument the schema never declared (parameter smuggling); and
 *   - **type / enum violations** — a declared parameter whose value breaks its declared type or enum
 *     (a validation-bypass attempt, e.g. an array where a scalar is expected).
 *
 * This is deliberately a minimal, dependency-free, linear-time check over the subset of JSON Schema
 * that MCP tool definitions use in practice ({ type: "object", properties, required }). It is not a
 * full JSON-Schema validator; it targets the security signals, not spec conformance.
 *
 * @packageDocumentation
 */
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

import type { SecurityFinding } from "./types.js";

type JsonSchema = {
  type?: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  enum?: unknown[];
  additionalProperties?: boolean | JsonSchema;
};

function typeOf(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (Number.isInteger(value)) return "integer";
  return typeof value; // string | number | boolean | object | undefined
}

/** Whether `value` satisfies a JSON-Schema `type` keyword. */
function matchesType(value: unknown, type: string): boolean {
  const actual = typeOf(value);
  if (type === "number") return actual === "number" || actual === "integer";
  if (type === "integer") return actual === "integer";
  return actual === type;
}

/**
 * Validate `args` against a tool's `inputSchema`. Returns security findings (empty if clean).
 * Undeclared parameters and type/enum violations are high severity.
 */
export function validateArguments(
  schema: Tool["inputSchema"] | undefined,
  args: Record<string, unknown>,
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const s = schema as JsonSchema | undefined;
  if (!s || s.type !== "object" || typeof args !== "object" || args === null) return findings;

  const properties = s.properties ?? {};
  const declared = new Set(Object.keys(properties));

  // Undeclared parameters (parameter smuggling / out-of-scope params).
  for (const name of Object.keys(args)) {
    if (!declared.has(name)) {
      findings.push({ rule: "undeclared-parameter", severity: "high", excerpt: name });
    }
  }

  // Type / enum violations on declared parameters (schema/validation bypass).
  for (const [name, spec] of Object.entries(properties)) {
    if (!(name in args)) continue;
    const value = args[name];
    if (typeof spec.type === "string" && !matchesType(value, spec.type)) {
      findings.push({
        rule: "type-violation",
        severity: "high",
        excerpt: `${name}: expected ${spec.type}, got ${typeOf(value)}`,
      });
    }
    if (Array.isArray(spec.enum) && !spec.enum.includes(value as never)) {
      findings.push({
        rule: "enum-violation",
        severity: "high",
        excerpt: `${name}=${JSON.stringify(value)}`,
      });
    }
  }

  return findings;
}
