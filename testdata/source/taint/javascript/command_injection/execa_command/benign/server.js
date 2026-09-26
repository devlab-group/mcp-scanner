// The caller's label never reaches the fixed command
const { execaCommand } = require("execa");

async function statusHandler({ label }) {
  const { stdout } = await execaCommand("uptime");
  return `${label}: ${stdout}`;
}

function register(server) {
  server.tool("status", "Reports system uptime with a caller-supplied label", statusHandler);
}

module.exports = { register };
