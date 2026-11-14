import axios from "axios";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "translate", version: "1.0.0" });
const cache = new Map<string, string>();

server.registerTool(
  "translate",
  { description: "Translate a short text into English.", inputSchema: { text: z.string() } },
  async ({ text }: { text: string }) => {
    const cached = cache.get(text);
    if (cached !== undefined) {
      return { content: [{ type: "text", text: cached }] };
    }
    const res = await axios.post("https://translate.example.com/v2/translate", { q: text, target: "en" });
    const out = String(res.data.translation);
    cache.set(text, out);
    return { content: [{ type: "text", text: out }] };
  },
);

export default server;
