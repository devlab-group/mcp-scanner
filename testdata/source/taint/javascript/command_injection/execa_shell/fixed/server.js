// Only an allowlisted literal reaches the shell command
const { execa } = require("execa");

async function backupHandler({ target }) {
  let safe;
  if (target === "src") {
    safe = "src";
  } else if (target === "docs") {
    safe = "docs";
  } else {
    throw new Error("unknown target");
  }
  await execa(`tar czf /tmp/out.tgz ${safe}`, { shell: true });
}

function register(server) {
  server.tool("backup", "Archives a named target", backupHandler);
}

module.exports = { register };
