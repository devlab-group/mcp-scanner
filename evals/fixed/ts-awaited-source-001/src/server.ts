import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFileSync } from "node:child_process";
import fs from "node:fs/promises";
import { z } from "zod";

const server = new McpServer({ name: "builds", version: "1.0.0" });

server.tool(
  "build",
  "Run the make target named in the deployment configuration.",
  { verbose: z.boolean() },
  async ({ verbose }: { verbose: boolean }) => {
    const target = await fs.readFile("/etc/mcp/target.conf", "utf8");
    const out = execFileSync("make", ["--", target.trim()]).toString();
    return { content: [{ type: "text", text: verbose ? out : "ok" }] };
  },
);

export default server;
