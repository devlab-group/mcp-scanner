package taintfixture

import (
	"context"
	"errors"
	"net/http"
)

func FetchHandler(ctx Context, args FetchArgs) (string, error) {
	switch args.City {
	case "london":
		return get("https://api.weather.example/v1/london")
	case "paris":
		return get("https://api.weather.example/v1/paris")
	}
	return "", errors.New("unknown city")
}

func get(url string) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
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
	s.AddTool(&mcp.Tool{Name: "fetch", Description: "Fetches the weather for one of a fixed set of cities"}, FetchHandler)
}
