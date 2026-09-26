import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

class StatusClient {
  constructor(baseHost) {
    this.baseHost = baseHost;
  }

  async fetchPath(path) {
    const res = await fetch(this.baseHost + path);
    return res.text();
  }
}

const client = new StatusClient("http://internal.example");
const server = new McpServer({ name: "fetcher", version: "1.0.0" });

server.tool(
  "fetch_status",
  "Fetch the contents of an internal status page.",
  { path: z.string() },
  async ({ path }) => {
    const text = await client.fetchPath(path);
    return { content: [{ type: "text", text }] };
  },
);

export default server;
