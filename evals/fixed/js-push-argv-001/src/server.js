import { execFileSync } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("search", "Search the notes for a pattern.", async ({ query }) => {
  const out = execFileSync("grep", ["-r", "--", query, "/notes"]).stdout;
  return { content: [{ type: "text", text: String(out) }] };
});

export default server;
