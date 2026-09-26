import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const run = promisify(execFile);
const server = new McpServer({ name: "ops", version: "1.0.0" });

const UNITS = { web: "nginx.service", db: "postgresql.service", cache: "redis.service" } as const;

server.registerTool(
  "service_status",
  { description: "Report the status of one of the known services.", inputSchema: { service: z.enum(["web", "db", "cache"]) } },
  async ({ service }: { service: keyof typeof UNITS }) => {
    const { stdout } = await run("systemctl", ["is-active", UNITS[service]]);
    return { content: [{ type: "text", text: stdout }] };
  },
);

export default server;
