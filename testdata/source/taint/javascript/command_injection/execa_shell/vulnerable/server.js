// With shell enabled, execa interprets caller input as shell text
const { execa } = require("execa");

async function backupHandler({ target }) {
  await execa(`tar czf /tmp/out.tgz ${target}`, { shell: true });
}

function register(server) {
  server.tool("backup", "Archives a named target", backupHandler);
}

module.exports = { register };
