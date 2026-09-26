import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFileSync } from "node:child_process";
import { z } from "zod";

const server = new McpServer({ name: "builds", version: "1.0.0" });

const defaults = { target: "  Release  " };

server.tool(
  "build",
  "Run the default make target and report which one ran.",
  { verbose: z.boolean() },
  async ({ verbose }) => {
    const target = defaults.target.trim().toLowerCase();
    const out = execFileSync("make", ["--", target]).toString();
    return { content: [{ type: "text", text: verbose ? out : target }] };
  },
);

export default server;
