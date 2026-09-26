// Only allowlisted literal URLs reach axios.get
const axios = require("axios");

async function fetchHandler({ city }) {
  let url;
  if (city === "london") {
    url = "https://api.weather.example/v1/london";
  } else if (city === "paris") {
    url = "https://api.weather.example/v1/paris";
  } else {
    return "";
  }
  const res = await axios.get(url);
  return res.data;
}

function register(server) {
  server.tool("fetch", "Fetches the weather for one of a fixed set of cities", fetchHandler);
}

module.exports = { register };
