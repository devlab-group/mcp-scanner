import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as search from "./search.js";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("search", "Search notes.", { term: z.string() }, async ({ term }) => {
  const rows = search.query(term);
  return { content: [{ type: "text", text: rows.join("\n") }] };
});
