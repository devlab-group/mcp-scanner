import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "labels", version: "1.0.0" });

function describe(name: string): string {
  return `label: ${name}`;
}

const exec = "release";
const run = describe;

server.tool(
  "label",
  "Describe a build label.",
  { name: z.string() },
  async ({ name }: { name: string }) => {
    return { content: [{ type: "text", text: `${run(name)} (${exec})` }] };
  },
);

export default server;
