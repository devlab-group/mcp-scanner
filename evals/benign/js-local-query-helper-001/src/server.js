import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const NOTES = ["buy milk", "renew the domain", "call the dentist"];

function prepare(term) {
  return term.trim().toLowerCase();
}

function query(term) {
  return NOTES.filter((note) => note.includes(term));
}

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("search", "Search notes by keyword.", { term: z.string() }, async ({ term }) => {
  const rows = query(prepare(term));
  return { content: [{ type: "text", text: rows.join("\n") }] };
});

export default server;
