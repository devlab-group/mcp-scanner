package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var notesRoot = "/srv/notes"

func readNoteHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := req.GetString("name", "")
	full := filepath.Join(notesRoot, name)
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(data)), nil
}

func main() {
	s := server.NewMCPServer("notes", "1.0.0")
	s.AddTool(mcp.NewTool("read_note",
		mcp.WithDescription("Read a note from the notes directory."),
		mcp.WithString("name", mcp.Required()),
	), readNoteHandler)
}
