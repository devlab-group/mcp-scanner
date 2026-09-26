import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool(
  "archive",
  "Archive a project directory.",
  { path: z.string() },
  async ({ path }: { path: string }) => {
    const out = await new Promise<string>((resolve, reject) => {
      exec(`tar czf /tmp/out.tgz ${path}`, (err, stdout) => {
        if (err) reject(err);
        else resolve(stdout);
      });
    });
    return { content: [{ type: "text", text: out }] };
  },
);

export default server;
