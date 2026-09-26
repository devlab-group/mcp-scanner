package main

import (
	"context"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type args struct {
	Pattern string `json:"pattern"`
}

func handleGrep(ctx context.Context, req *mcp.CallToolRequest, in args) (*mcp.CallToolResult, any, error) {
	script := `set -e
cd /data
grep -rn \
  --color=never \` + " " + in.Pattern
	out, err := exec.Command("sh", "-c", script).Output()
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(out)}}}, nil, nil
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "grep"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "grep_data", Description: "Search files under /data."}, handleGrep)
}
