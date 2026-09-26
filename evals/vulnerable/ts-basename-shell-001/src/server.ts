import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "node:child_process";
import { basename } from "node:path";
import { z } from "zod";

const server = new McpServer({ name: "reports", version: "1.0.0" });

server.tool(
  "render",
  "Render a report to PDF and return the rendered text.",
  { report: z.string() },
  async ({ report }: { report: string }) => {
    const safe = basename(report);
    const out = await new Promise<string>((resolve, reject) => {
      exec(`pandoc /reports/${safe}`, (err, stdout) => {
        if (err) reject(err);
        else resolve(stdout);
      });
    });
    return { content: [{ type: "text", text: out }] };
  },
);

export default server;
