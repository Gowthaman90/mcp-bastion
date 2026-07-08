/**
 * Public surface of the proxy (client-facing) layer.
 *
 * @packageDocumentation
 */
export { buildBastionServer } from "./bastion-server.js";
export { buildControlTools, isControlToolName, handleControlTool } from "./control-tools.js";
export { startHttpServer } from "./http-server.js";
export type { HttpListener, HttpListenOptions } from "./http-server.js";
