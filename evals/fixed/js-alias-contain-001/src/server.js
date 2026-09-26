import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fs from "fs/promises";
import * as path from "path";
import { z } from "zod";

const ROOT = "/srv/notes";
const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("read_note", "Read a note.", { name: z.string() }, async ({ name }) => {
  const resolved = path.resolve(ROOT, name);
  const target = resolved;
  if (!target.startsWith(ROOT + path.sep)) {
    throw new Error("escapes");
  }
  return { content: [{ type: "text", text: await fs.readFile(target, "utf8") }] };
});
