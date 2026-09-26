import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { promises as fs } from "node:fs";

const server = new McpServer({ name: "notes", version: "1.0.0" });
const ROOT = "/srv/notes";

server.tool(
  "read_note",
  "Read a note from the notes directory.",
  async ({ name }) => {
    const full = ROOT + "/" + name;
    if (!full.startsWith(ROOT)) {
      throw new Error("name escapes the notes directory");
    }
    const text = await fs.readFile(full, "utf8");
    return { content: [{ type: "text", text }] };
  },
);

export default server;
