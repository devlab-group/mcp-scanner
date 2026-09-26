package taintfixture

import (
	"errors"
	"net/http"
)

var httpClient = &http.Client{}

// FetchHandler no longer builds the request URL from user input: the
// requested city selects one of a fixed set of literal URLs, so the
// argument passed to httpClient.Get never contains anything the caller
// wrote
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
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "fetch", Description: "Fetches the weather for one of a fixed set of cities"}, FetchHandler)
}
