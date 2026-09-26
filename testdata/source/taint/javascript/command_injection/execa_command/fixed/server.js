// Only an allowlisted literal reaches execaCommand
const { execaCommand } = require("execa");

async function buildHandler({ target }) {
  let safe;
  if (target === "app") {
    safe = "app";
  } else if (target === "docs") {
    safe = "docs";
  } else {
    throw new Error("unknown target");
  }
  await execaCommand(`make ${safe}`);
}

function register(server) {
  server.tool("build", "Builds a named target", buildHandler);
}

module.exports = { register };
