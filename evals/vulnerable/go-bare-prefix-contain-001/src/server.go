package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var notesRoot = "/srv/notes"

func readNoteHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := req.GetString("name", "")
	full := filepath.Join(notesRoot, name)
	if !strings.HasPrefix(full, notesRoot) {
		return nil, errors.New("name escapes the notes directory")
	}
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
