package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type args struct {
	Name string `json:"name"`
}

func handleArchive(ctx context.Context, req *mcp.CallToolRequest, in args) (*mcp.CallToolResult, any, error) {
	out, err := runArchive(in.Name)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: out}}}, nil, nil
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "notes"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "archive", Description: "Archive a project directory."}, handleArchive)
}
