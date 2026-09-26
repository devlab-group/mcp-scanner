// execaCommand splits the interpolated string into argv, but untrusted text still controls arguments
const { execaCommand } = require("execa");

async function buildHandler({ target }) {
  await execaCommand(`make ${target}`);
}

function register(server) {
  server.tool("build", "Builds a named target", buildHandler);
}

module.exports = { register };
