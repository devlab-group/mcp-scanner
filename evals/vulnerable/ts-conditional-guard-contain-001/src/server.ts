import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });
const ROOT = "/srv/notes";
const STRICT = process.env.NOTES_STRICT === "1";

server.tool(
  "read_note",
  "Read a note from the notes directory.",
  { name: z.string() },
  async ({ name }: { name: string }) => {
    const full = path.resolve(ROOT, name);
    if (STRICT && !full.startsWith(ROOT + path.sep)) {
      throw new Error("name escapes the notes directory");
    }
    const text = await fs.readFile(full, "utf8");
    return { content: [{ type: "text", text }] };
  },
);

export default server;
