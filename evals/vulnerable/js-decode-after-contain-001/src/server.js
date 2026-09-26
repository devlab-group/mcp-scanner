import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fs from "fs";
import * as path from "path";
import { z } from "zod";

const ROOT = "/srv/notes";
const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("read_note", "Read a note.", { name: z.string() }, async ({ name }) => {
  const full = path.join(ROOT, name);
  if (!full.startsWith(ROOT + "/")) {
    throw new Error("name escapes the notes directory");
  }
  const real = decodeURIComponent(full);
  return { content: [{ type: "text", text: fs.readFileSync(real, "utf8") }] };
});
