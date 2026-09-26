import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const server = new McpServer({ name: "toolbox", version: "1.0.0" });

server.tool("hello", "Greet the caller by name.", async ({ who }) => {
  return { content: [{ type: "text", text: `hello ${who}` }] };
});
