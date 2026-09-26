import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import pg from "pg";
import { z } from "zod";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const server = new McpServer({ name: "users", version: "1.0.0" });

server.tool("find_user", "Look up a user by name.", { name: z.string() }, async ({ name }) => {
  const res = await pool.query("SELECT id, email FROM users WHERE name = $1", [name]);
  return { content: [{ type: "text", text: JSON.stringify(res.rows) }] };
});

export default server;
