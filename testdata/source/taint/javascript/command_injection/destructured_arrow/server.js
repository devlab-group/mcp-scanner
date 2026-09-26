// A JavaScript arrow handler binds a destructured property
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const child_process = require("child_process");

function register(server) {
  server.tool("archive", "Archives a project directory", async ({ path }) => {
    child_process.exec("tar czf out.tgz " + path);
  });
}

module.exports = { register };
