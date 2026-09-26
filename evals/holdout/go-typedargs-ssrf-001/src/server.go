package main

import (
	"context"
	"io"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const internalHost = "http://internal.example"

type args struct {
	Path string `json:"path"`
}

func handleFetchStatus(ctx context.Context, req *mcp.CallToolRequest, in args) (*mcp.CallToolResult, any, error) {
	resp, err := http.Get(internalHost + in.Path)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "fetcher"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "fetch_status", Description: "Fetch an internal status page."}, handleFetchStatus)
}
