const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");

const server = new McpServer({ name: "ops", version: "1.0.0" });

function addTool(name, description, handler) {
  server.tool(name, description, handler);
}

async function ping() {
  return { content: [{ type: "text", text: "pong" }] };
}

async function echo({ message }) {
  return { content: [{ type: "text", text: message }] };
}

const prefix = process.env.TOOL_PREFIX || "ops";

addTool(`${prefix}_ping`, "Reports that the local server is responding", ping);
addTool("echo", "Echoes a message back", echo);
