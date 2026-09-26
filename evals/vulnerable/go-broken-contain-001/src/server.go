package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const notesRoot = "/srv/notes/"

type args struct {
	Name string `json:"name"`
}

func handleReadNote(ctx context.Context, req *mcp.CallToolRequest, in args) (*mcp.CallToolResult, any, error) {
	full := notesRoot + in.Name
	if !strings.HasPrefix(full, notesRoot) {
		return nil, nil, errors.New("name escapes the notes directory")
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}, nil, nil
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "notes"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "read_note", Description: "Read a note from the notes directory."}, handleReadNote)
}
