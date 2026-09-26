package main

import (
	"context"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type args struct {
	Label  string `json:"label"`
	Target string `json:"target"`
}

func runIn(label, command string) ([]byte, error) {
	println("running " + label)
	return exec.Command("sh", "-c", command).CombinedOutput()
}

func handleBuild(ctx context.Context, req *mcp.CallToolRequest, in args) (*mcp.CallToolResult, any, error) {
	out, err := runIn(in.Label, in.Target)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(out)}}}, nil, nil
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "build"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "build", Description: "Run a make target under a label."}, handleBuild)
}
