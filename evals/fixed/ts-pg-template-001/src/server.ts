import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Pool } from "pg";
import { z } from "zod";

const db = new Pool();
const server = new McpServer({ name: "users", version: "1.0.0" });

server.registerTool(
  "find_user",
  { description: "Look up a user by name.", inputSchema: { username: z.string() } },
  async ({ username }: { username: string }) => {
    const res = await db.query(`SELECT id, email FROM users WHERE name = $1`, [username]);
    return { content: [{ type: "text", text: JSON.stringify(res.rows) }] };
  },
);

export default server;
