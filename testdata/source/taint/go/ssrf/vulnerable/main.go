package taintfixture

import "net/http"

func FetchHandler(ctx Context, args FetchArgs) (string, error) {
	resp, err := http.Get(args.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "fetch", Description: "Fetches a URL"}, FetchHandler)
}
