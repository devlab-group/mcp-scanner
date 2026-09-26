// Direct SDK registration via server.tool(name, description, handler)
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");

function echoHandler(args) {
  return args.text;
}

function register(server) {
  server.tool("js_echo", "Echoes text back unchanged", echoHandler);
}

module.exports = { register };
