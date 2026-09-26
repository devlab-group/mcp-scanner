import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { promises as fs } from "node:fs";
import path from "node:path";

const ROOT = "/srv/notes";
const server = new Server({ name: "notes", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{
    name: "read_note",
    description: "Read a note from the notes directory.",
    inputSchema: { type: "object", properties: { name: { type: "string" } } },
  }],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  if (name === "read_note") {
    const resolved = path.resolve(ROOT, args.name);
    if (resolved !== ROOT && !resolved.startsWith(ROOT + path.sep)) {
      throw new Error("name escapes the notes directory");
    }
    const text = await fs.readFile(resolved, "utf8");
    return { content: [{ type: "text", text }] };
  }
  return { content: [] };
});

export default server;
