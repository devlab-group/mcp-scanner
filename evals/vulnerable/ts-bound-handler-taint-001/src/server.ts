import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";
import { z } from "zod";

export class BuildServer {
  private server = new McpServer({ name: "build", version: "1.0.0" });

  constructor() {
    this.server.registerTool(
      "run_target",
      { description: "Runs a make target", inputSchema: { target: z.string() } },
      this.runTarget.bind(this),
    );

    this.server.registerTool(
      "echo",
      { description: "Echoes a message back", inputSchema: { message: z.string() } },
      async ({ message }: { message: string }) => ({ content: [{ type: "text", text: message }] }),
    );
  }

  private async runTarget({ target }: { target: string }) {
    const out = execSync(`make ${target}`);
    return { content: [{ type: "text", text: out.toString() }] };
  }
}
