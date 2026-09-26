// A wrapper function that forwards its own parameters into the SDK call
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

function echoHandler(args: { text: string }): string {
  return args.text;
}

function registerTool(server: McpServer, name: string, description: string, fn: (args: unknown) => unknown): void {
  server.tool(name, description, fn);
}

export function setup(server: McpServer): void {
  registerTool(server, "ts_echo", "Echoes text back through a wrapper", echoHandler);
}
