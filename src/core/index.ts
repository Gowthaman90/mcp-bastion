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
export { isAuthFailure, UpstreamConnection } from "./upstream-connection.js";
export {
  currentRequestContext,
  runOutsideRequest,
  runWithRequestHeaders,
} from "./request-context.js";
export type { RequestContext } from "./request-context.js";
export type { UpstreamChangeListener } from "./upstream-connection.js";
export { UpstreamManager } from "./upstream-manager.js";
export { DelegationGate } from "./delegation-gate.js";
export type { DelegationCheck, DelegationStatus, DelegationVerdict } from "./delegation-gate.js";
