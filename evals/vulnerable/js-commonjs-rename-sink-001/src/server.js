const { exec: run } = require("node:child_process");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");

const server = new McpServer({ name: "builds", version: "1.0.0" });

server.tool("build", "Run the named make target.", { target: { type: "string" } }, async ({ target }) => {
  return new Promise((resolve) => run("make " + target, (e, out) => resolve({ content: [{ type: "text", text: out }] })));
});

module.exports = server;
