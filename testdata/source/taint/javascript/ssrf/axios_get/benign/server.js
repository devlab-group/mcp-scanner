// The caller's label never reaches the fixed URL
const axios = require("axios");

async function statusHandler({ label }) {
  const res = await axios.get("https://api.weather.example/v1/status");
  return `${label}: ${res.data}`;
}

function register(server) {
  server.tool("status", "Reports upstream status with a caller-supplied label", statusHandler);
}

module.exports = { register };
