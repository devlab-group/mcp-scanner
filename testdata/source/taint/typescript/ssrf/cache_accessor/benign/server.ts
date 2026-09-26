// Map.get stays benign because this file imports no recognized HTTP client
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const cache = new Map<string, string>();
cache.set("greeting", "hello");

async function lookupHandler({ key }: { key: string }): Promise<string> {
  return cache.get(key) ?? "";
}

export function register(server: McpServer): void {
  server.tool("lookup", "Looks up a cached value by key", lookupHandler);
}
