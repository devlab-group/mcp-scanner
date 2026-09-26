import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { readFile } from "node:fs/promises";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.registerTool(
  "read_note",
  { description: "Read a note from the project directory.", inputSchema: { name: z.string() } },
  async ({ name }: { name: string }) => {
    const text = await readFile("/notes/" + name, "utf8");
    return { content: [{ type: "text", text }] };
  },
);

export default server;
