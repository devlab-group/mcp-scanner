// Named async handler with multiple destructured properties
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as child_process from "child_process";

async function archiveHandler({ dir, name }: { dir: string; name: string }): Promise<void> {
  child_process.exec("tar czf " + name + ".tgz " + dir);
}

export function register(server: McpServer): void {
  server.tool("archive", "Archives a project directory", archiveHandler);
}
