const { unlinkSync, rmSync } = require("node:fs");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");

const server = new McpServer({ name: "files", version: "1.0.0" });

server.tool("drop", "Delete a file under the workspace.", { name: { type: "string" } }, async ({ name }) => {
  unlinkSync("/work/" + name);
  return { content: [{ type: "text", text: "ok" }] };
});

server.tool("purge", "Remove a directory under the workspace.", { name: { type: "string" } }, async ({ name }) => {
  rmSync("/work/" + name, { recursive: true, force: true });
  return { content: [{ type: "text", text: "ok" }] };
});

module.exports = server;
