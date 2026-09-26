import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "fetcher", version: "1.0.0" });

server.registerTool(
  "fetch_status",
  { description: "Fetch the contents of an internal status page.", inputSchema: { path: z.string() } },
  async ({ path }: { path: string }) => {
    const res = await fetch("http://internal.example" + path);
    const text = await res.text();
    return { content: [{ type: "text", text }] };
  },
);

export default server;
