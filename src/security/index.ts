/**
 * Public surface of the security layer.
 *
 * @packageDocumentation
 */
export { SecurityEngine } from "./engine.js";
export { runPipeline } from "./pipeline.js";
export { hashToolDefinition } from "./hashing.js";
export { scanText, scanTool, hasSeverityAtLeast } from "./poisoning.js";
export { ToolRegistry } from "./tool-registry.js";
export type { ObserveOptions } from "./tool-registry.js";
export type {
  Severity,
  SecurityFinding,
  PinStatus,
  ToolSecurityReport,
  ToolCallContext,
  Interceptor,
  NextFn,
} from "./types.js";
