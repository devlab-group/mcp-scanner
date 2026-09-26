import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";
import { exec as spawnShell } from "node:child_process";
import { z } from "zod";

const run = execSync;
const server = new McpServer({ name: "files", version: "1.0.0" });

server.tool(
  "list",
  "List a directory.",
  { dir: z.string() },
  async ({ dir }: { dir: string }) => {
    const out = run(`ls -la ${dir}`).toString();
    return { content: [{ type: "text", text: out }] };
  },
);

server.tool(
  "count",
  "Count the entries in a directory.",
  { dir: z.string() },
  async ({ dir }: { dir: string }) => {
    const out = await new Promise<string>((resolve, reject) => {
      spawnShell(`ls -la ${dir} | wc -l`, (err, stdout) => {
        if (err) reject(err);
        else resolve(stdout);
      });
    });
    return { content: [{ type: "text", text: out }] };
  },
);

export default server;
