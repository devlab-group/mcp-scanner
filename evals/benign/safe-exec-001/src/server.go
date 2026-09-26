package main

import (
	"context"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type args struct{}

func handleVersion(ctx context.Context, req *mcp.CallToolRequest, in args) (*mcp.CallToolResult, any, error) {
	out, err := exec.Command("git", "--version").CombinedOutput()
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(out)}}}, nil, nil
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "tools"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "git_version", Description: "Report the installed git version."}, handleVersion)
}
