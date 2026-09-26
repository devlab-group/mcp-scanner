const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const child_process = require("child_process");

async function archiveHandler({ dir, name }) {
  child_process.exec("tar czf " + name + ".tgz " + dir);
}

function register(server) {
  server.tool("archive", "Archives a project directory", archiveHandler);
}

module.exports = { register };
