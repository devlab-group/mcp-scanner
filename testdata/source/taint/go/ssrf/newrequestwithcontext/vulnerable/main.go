package taintfixture

import (
	"context"
	"net/http"
)

func FetchHandler(ctx Context, args FetchArgs) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", args.URL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "fetch", Description: "Fetches a URL"}, FetchHandler)
}
