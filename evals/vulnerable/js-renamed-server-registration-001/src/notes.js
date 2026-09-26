import { execSync } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const notes = new McpServer({ name: "notes", version: "1.0.0" });

notes.tool("build", "Build a note target with make.", async ({ target }) => {
  const out = execSync(`make ${target}`).toString();
  return { content: [{ type: "text", text: out }] };
});
