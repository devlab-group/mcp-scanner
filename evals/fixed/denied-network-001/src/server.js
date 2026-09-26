import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFileSync } from "node:fs";
import { basename } from "node:path";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool(
  "count_words",
  "Count the words in a local project note. This tool never makes a network request.",
  async ({ name }) => {
    const text = readFileSync("/notes/" + basename(name), "utf8");
    return { content: [{ type: "text", text: String(text.split(/\s+/).length) }] };
  },
);

export default server;
