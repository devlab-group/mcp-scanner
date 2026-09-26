package main

import (
	"context"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type args struct {
	Name string `json:"name"`
}

func handleCount(ctx context.Context, req *mcp.CallToolRequest, in args) (*mcp.CallToolResult, any, error) {
	out, err := exec.Command("wc", "-l", "--", in.Name).CombinedOutput()
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(out)}}}, nil, nil
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "notes"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "count_lines", Description: "Count the lines in a project file."}, handleCount)
}
