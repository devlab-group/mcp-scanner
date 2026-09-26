package taintfixture

import (
	"context"
	"net/http"
)

const statusURL = "https://api.weather.example/v1/status"

// The caller-supplied label never reaches the request URL - only a
// fixed, literal URL does
func StatusHandler(ctx Context, args StatusArgs) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", statusURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return args.Label, nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "status", Description: "Reports upstream status with a caller-supplied label"}, StatusHandler)
}
