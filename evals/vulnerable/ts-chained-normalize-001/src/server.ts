import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "builds", version: "1.0.0" });

server.tool(
  "build",
  "Run a make target.",
  { name: z.string() },
  async ({ name }: { name: string }) => {
    const target = name.trim().toLowerCase();
    const out = execSync(`make ${target}`).toString();
    return { content: [{ type: "text", text: out }] };
  },
);

export default server;
