import { spawnSync } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "reports", version: "1.0.0" });

server.tool("summary", "Summarize yesterday's build report.", async ({ verbose }) => {
  const args = ["-c"];
  args.push("wc -l /var/log/build.log");
  const out = spawnSync("bash", args).stdout;
  return { content: [{ type: "text", text: verbose ? String(out) : "ok" }] };
});

export default server;
