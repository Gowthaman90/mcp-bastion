/**
 * Public surface of the core domain layer.
 *
 * @packageDocumentation
 */
export {
  BASTION_NAME,
  BASTION_VERSION,
  CONTROL_NAMESPACE,
  ControlAction,
  controlToolName,
} from "./constants.js";
export type { ConnectionState, ServerStatus, ReconnectResult, ToolRoute } from "./types.js";
export { UpstreamConnection } from "./upstream-connection.js";
export type { UpstreamChangeListener } from "./upstream-connection.js";
export { UpstreamManager } from "./upstream-manager.js";
