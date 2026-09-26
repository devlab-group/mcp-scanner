package main

import (
	"context"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func buildHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target := req.GetString("target", "")
	out, err := exec.Command("make", "--", target).CombinedOutput()
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(out)), nil
}

func main() {
	s := server.NewMCPServer("build", "1.0.0")
	s.AddTool(mcp.NewTool("build",
		mcp.WithDescription("Run the project's make target and return its output."),
		mcp.WithString("target", mcp.Required()),
	), buildHandler)
}
