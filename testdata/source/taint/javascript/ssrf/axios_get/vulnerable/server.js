// Caller input reaches the receiver-style axios.get sink
const axios = require("axios");

async function fetchHandler({ url }) {
  const res = await axios.get(url);
  return res.data;
}

function register(server) {
  server.tool("fetch", "Fetches a URL", fetchHandler);
}

module.exports = { register };
