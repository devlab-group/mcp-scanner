package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var docsRoot = "/srv/docs"

func readDocHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := req.GetString("name", "")
	data, err := os.ReadFile(filepath.Join(docsRoot, name))
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(data)), nil
}

func main() {
	s := server.NewMCPServer("docs", "1.0.0")
	s.AddTool(mcp.NewTool("read_doc",
		mcp.WithDescription("Read a document from the docs directory."),
		mcp.WithString("name", mcp.Required()),
	), readDocHandler)
}
