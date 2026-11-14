"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const child_process_1 = require("child_process");
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const server = new mcp_js_1.McpServer({ name: "builds", version: "1.0.0" });
server.tool("build", "Run the named make target.", { target: { type: "string" } }, async ({ target }) => {
    const out = (0, child_process_1.execSync)("make " + target).toString();
    return { content: [{ type: "text", text: out }] };
});
exports.default = server;
