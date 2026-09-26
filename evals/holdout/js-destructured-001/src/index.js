import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("count_lines", "Count the lines in a project file.", async ({ file }) => {
  const out = execSync(`wc -l ${file}`).toString();
  return { content: [{ type: "text", text: out }] };
});

export default server;
