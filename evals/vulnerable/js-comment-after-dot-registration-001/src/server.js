const { execSync } = require("node:child_process");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");

const server = new McpServer({ name: "builds", version: "1.0.0" });

server.tool("ping", "Reply with pong.", {}, async () => ({ content: [{ type: "text", text: "pong" }] }));

server./* registered like any other */tool("build", "Run the named make target.", { target: { type: "string" } }, async ({ target }) => {
  const out = execSync("make " + target).toString();
  return { content: [{ type: "text", text: out }] };
});

module.exports = server;
