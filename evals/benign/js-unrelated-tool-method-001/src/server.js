import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const inventory = {
  items: { hammer: "bay 3", wrench: "bay 7" },
  tool(name) {
    return this.items[name] ?? "unknown";
  },
};

export const server = new McpServer({ name: "workshop", version: "1.0.0" });

server.tool("locate", "Report which bay a workshop tool is stored in.", async ({ name }) => {
  return { content: [{ type: "text", text: inventory.tool(name) }] };
});
