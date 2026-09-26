import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as db from "./db.js";

const server = new McpServer({ name: "users", version: "1.0.0" });

server.tool("find_user", "Look up a user.", { name: z.string() }, async ({ name }) => {
  const rows = await db.query("SELECT id FROM users WHERE name = '" + name + "'");
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});
