// An inline handler binds attacker-controlled destructured properties
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as child_process from "child_process";

export function register(server: McpServer): void {
  server.tool("archive", "Archives a project directory", async ({ path }: { path: string }) => {
    child_process.exec("tar czf out.tgz " + path);
  });
}
