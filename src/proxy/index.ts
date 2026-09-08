/**
 * Public surface of the proxy (client-facing) layer.
 *
 * @packageDocumentation
 */
export { buildBastionServer } from "./bastion-server.js";
export { broadcastToolsChanged, addToolsChangedTarget } from "./bastion-server.js";
export type { BastionServerOptions } from "./bastion-server.js";
export { buildControlTools, isControlToolName, handleControlTool } from "./control-tools.js";
export { startHttpServer, principalOf, HEADER_MISMATCH_CODE } from "./http-server.js";
export type { HttpListener, HttpListenOptions } from "./http-server.js";
