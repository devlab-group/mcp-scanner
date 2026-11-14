const express = require("express");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { StreamableHTTPServerTransport } = require("@modelcontextprotocol/sdk/server/streamableHttp.js");

const notes = { todo: "Buy milk." };
const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("read_note", "Read a note by title.", { title: { type: "string" } }, async ({ title }) => ({
  content: [{ type: "text", text: notes[title] ?? "no such note" }],
}));

const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
const app = express();

app
  // GET /health answers with a fixed body for the dashboard
  .get("/health", (req, res) => res.json({ route: "health", ok: true }))
  // GET /status answers with a fixed body for the dashboard
  .get("/status", (req, res) => res.json({ route: "status", ok: true }))
  // GET /version answers with a fixed body for the dashboard
  .get("/version", (req, res) => res.json({ route: "version", ok: true }))
  // GET /metrics answers with a fixed body for the dashboard
  .get("/metrics", (req, res) => res.json({ route: "metrics", ok: true }))
  // GET /ready answers with a fixed body for the dashboard
  .get("/ready", (req, res) => res.json({ route: "ready", ok: true }))
  // GET /live answers with a fixed body for the dashboard
  .get("/live", (req, res) => res.json({ route: "live", ok: true }))
  // GET /config answers with a fixed body for the dashboard
  .get("/config", (req, res) => res.json({ route: "config", ok: true }))
  // GET /about answers with a fixed body for the dashboard
  .get("/about", (req, res) => res.json({ route: "about", ok: true }))
  // GET /help answers with a fixed body for the dashboard
  .get("/help", (req, res) => res.json({ route: "help", ok: true }))
  // GET /docs answers with a fixed body for the dashboard
  .get("/docs", (req, res) => res.json({ route: "docs", ok: true }))
  // GET /notes answers with a fixed body for the dashboard
  .get("/notes", (req, res) => res.json({ route: "notes", ok: true }))
  // GET /tags answers with a fixed body for the dashboard
  .get("/tags", (req, res) => res.json({ route: "tags", ok: true }))
  // GET /users answers with a fixed body for the dashboard
  .get("/users", (req, res) => res.json({ route: "users", ok: true }))
  // GET /teams answers with a fixed body for the dashboard
  .get("/teams", (req, res) => res.json({ route: "teams", ok: true }))
  // GET /projects answers with a fixed body for the dashboard
  .get("/projects", (req, res) => res.json({ route: "projects", ok: true }))
  // GET /boards answers with a fixed body for the dashboard
  .get("/boards", (req, res) => res.json({ route: "boards", ok: true }))
  // GET /cards answers with a fixed body for the dashboard
  .get("/cards", (req, res) => res.json({ route: "cards", ok: true }))
  // GET /lists answers with a fixed body for the dashboard
  .get("/lists", (req, res) => res.json({ route: "lists", ok: true }))
  // GET /labels answers with a fixed body for the dashboard
  .get("/labels", (req, res) => res.json({ route: "labels", ok: true }))
  // GET /comments answers with a fixed body for the dashboard
  .get("/comments", (req, res) => res.json({ route: "comments", ok: true }))
  // GET /files answers with a fixed body for the dashboard
  .get("/files", (req, res) => res.json({ route: "files", ok: true }))
  // GET /images answers with a fixed body for the dashboard
  .get("/images", (req, res) => res.json({ route: "images", ok: true }))
  // GET /exports answers with a fixed body for the dashboard
  .get("/exports", (req, res) => res.json({ route: "exports", ok: true }))
  // GET /imports answers with a fixed body for the dashboard
  .get("/imports", (req, res) => res.json({ route: "imports", ok: true }))
  // GET /jobs answers with a fixed body for the dashboard
  .get("/jobs", (req, res) => res.json({ route: "jobs", ok: true }))
  // GET /queues answers with a fixed body for the dashboard
  .get("/queues", (req, res) => res.json({ route: "queues", ok: true }))
  // GET /workers answers with a fixed body for the dashboard
  .get("/workers", (req, res) => res.json({ route: "workers", ok: true }))
  // GET /events answers with a fixed body for the dashboard
  .get("/events", (req, res) => res.json({ route: "events", ok: true }))
  // GET /hooks answers with a fixed body for the dashboard
  .get("/hooks", (req, res) => res.json({ route: "hooks", ok: true }))
  // GET /audit answers with a fixed body for the dashboard
  .get("/audit", (req, res) => res.json({ route: "audit", ok: true }))
  // The MCP endpoint itself
  .post("/mcp", (req, res) => transport.handleRequest(req, res, req.body));

server.connect(transport).then(() => app.listen(3000));
