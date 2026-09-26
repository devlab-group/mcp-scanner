import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import Database from "better-sqlite3";
import { z } from "zod";

const db = new Database("app.db");
const server = new McpServer({ name: "users", version: "1.0.0" });

server.tool("find_user", "Look up a user by name.", { username: z.string() }, async ({ username }) => {
  const rows = db.prepare("SELECT id, email FROM users WHERE name = ?").all(username);
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});

export default server;
