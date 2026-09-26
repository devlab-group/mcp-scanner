import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });
const ROOT = "/srv/notes";

server.tool(
  "read_note",
  "Read a note from the notes directory.",
  { name: z.string() },
  async ({ name }: { name: string }) => {
    const resolved = path.resolve(ROOT, name);
    const text = await fs.readFile(resolved, "utf8");
    return { content: [{ type: "text", text }] };
  },
);

export default server;
