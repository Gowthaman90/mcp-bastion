// End-to-end smoke test: connect a real MCP client to the built Bastion CLI.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "node:url";
import { writeFileSync } from "node:fs";

const root = fileURLToPath(new URL("..", import.meta.url));
const mock = fileURLToPath(new URL("../test/fixtures/mock-server.mjs", import.meta.url));
const cfgPath = fileURLToPath(new URL("../.smoke.config.json", import.meta.url));

writeFileSync(
  cfgPath,
  JSON.stringify({
    servers: { mock: { command: process.execPath, args: [mock] } },
    healthCheck: { enabled: false },
  }),
);

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [`${root}dist/cli.js`, "--config", cfgPath],
});
const client = new Client({ name: "smoke", version: "0.0.0" }, { capabilities: {} });

await client.connect(transport);

const tools = (await client.listTools()).tools.map((t) => t.name);
console.log("TOOLS:", tools.join(", "));

const echo = await client.callTool({ name: "mock__echo", arguments: { msg: "end-to-end" } });
console.log("ECHO:", echo.content[0].text);

const status = await client.callTool({ name: "bastion__status", arguments: {} });
console.log("STATUS:", status.content[0].text.replace(/\s+/g, " "));

const recon = await client.callTool({ name: "bastion__reconnect", arguments: { server: "mock" } });
console.log("RECONNECT:", recon.content[0].text.replace(/\s+/g, " "));

const ok =
  tools.includes("mock__echo") &&
  tools.includes("bastion__status") &&
  tools.includes("bastion__reconnect") &&
  echo.content[0].text.includes("end-to-end");

await client.close();
console.log(ok ? "\nSMOKE: PASS" : "\nSMOKE: FAIL");
process.exit(ok ? 0 : 1);
