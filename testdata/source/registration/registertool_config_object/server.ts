// The description and title must resolve from a config object
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

function echoHandler(args: { text: string }): string {
  return args.text;
}

export function setup(server: McpServer): void {
  server.registerTool(
    "config_echo",
    { title: "Echo Tool", description: "Echoes the given text back to the caller." },
    echoHandler
  );
}
