const { spawnSync } = require("node:child_process");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");

const server = new McpServer({ name: "grep", version: "1.0.0" });

server.tool("search", "Search the workspace for a pattern.", { pattern: { type: "string" } }, async ({ pattern }) => {
  const out = spawnSync("grep", ["-rn", pattern, "."], { shell: "/bin/bash" });
  return { content: [{ type: "text", text: out.stdout.toString() }] };
});

module.exports = server;
