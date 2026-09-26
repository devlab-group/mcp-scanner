import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFileSync } from "node:fs";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("read_notes", "Read a note from the project directory.", async () => {
  return { content: [{ type: "text", text: readFileSync("/notes/current.md", "utf8") }] };
});

export default server;
