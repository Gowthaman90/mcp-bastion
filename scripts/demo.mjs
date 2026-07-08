// Live "kill-and-recover" walkthrough for mcp-bastion.
//
//   npm run demo            # builds, then runs this narrated scenario
//
// To turn it into a GIF for the README (requires asciinema + agg):
//   asciinema rec demo.cast -c "npm run demo"
//   agg demo.cast assets/demo.gif
//
// It boots Bastion in front of a server that can crash on command, then shows
// the agent detecting the outage and the connection self-healing.
import { fileURLToPath } from "node:url";
import { UpstreamManager } from "../dist/index.js";

const crashable = fileURLToPath(new URL("../test/fixtures/crashable-server.mjs", import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const c = {
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};

function printStatus(manager) {
  for (const s of manager.status()) {
    const dot = s.connected ? c.green("●") : c.red("●");
    console.log(
      `   ${dot} ${c.bold(s.name)}  ${s.connected ? c.green(s.state) : c.red(s.state)}  (${s.tools} tools)`,
    );
  }
}

async function main() {
  console.log(c.bold("\n🛡️  mcp-bastion — kill-and-recover demo\n"));

  const manager = new UpstreamManager({
    servers: { demo: { transport: "stdio", command: process.execPath, args: [crashable] } },
    // Deliberately slow backoff so the outage is visible in the recording.
    reconnect: { auto: true, maxRetries: 20, initialBackoffMs: 2500, maxBackoffMs: 2500 },
    healthCheck: { enabled: false, intervalMs: 30000, timeoutMs: 5000 },
    namespace: { strategy: "prefix", separator: "__" },
  });

  const connected = () => manager.status()[0].connected;
  const waitUntil = async (pred, timeoutMs) => {
    const start = Date.now();
    while (!pred() && Date.now() - start < timeoutMs) await sleep(50);
  };

  console.log(c.cyan("1. Starting Bastion in front of an MCP server…"));
  await manager.connectAll();
  printStatus(manager);
  await sleep(800);

  console.log(c.cyan("\n2. The agent calls a tool — works normally:"));
  console.log(
    "   → " + (await manager.callUpstreamTool("demo__echo", { msg: "hello" })).content[0].text,
  );
  await sleep(800);

  console.log(c.yellow("\n3. 💥 The MCP server crashes mid-session…"));
  await manager.callUpstreamTool("demo__crash", {});
  await waitUntil(() => !connected(), 3000); // wait for the drop to register
  printStatus(manager);
  await sleep(600);

  console.log(
    c.cyan(
      "\n4. The agent tries the tool again. Instead of a cryptic error, it gets an actionable message:",
    ),
  );
  console.log(
    "   → " +
      c.red((await manager.callUpstreamTool("demo__echo", { msg: "hello" })).content[0].text),
  );
  await sleep(1000);

  console.log(c.cyan("\n5. Bastion auto-reconnects in the background…"));
  await waitUntil(connected, 8000);
  printStatus(manager);
  await sleep(600);

  console.log(c.cyan("\n6. The agent retries — recovered, no human involved:"));
  console.log(
    "   → " +
      c.green((await manager.callUpstreamTool("demo__echo", { msg: "hello" })).content[0].text),
  );

  console.log(c.green("\n✅ Server dropped and healed itself. That's mcp-bastion.\n"));
  await manager.closeAll();
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
