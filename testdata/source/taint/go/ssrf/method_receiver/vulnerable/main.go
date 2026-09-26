package taintfixture

import "net/http"

// httpClient is configured once at package scope, the shape every real Go server actually
// uses: http.Get (the free function, already a sinkPatterns entry) is not how a client with
// its own timeout or transport gets called
var httpClient = &http.Client{}

func FetchHandler(ctx Context, args FetchArgs) (string, error) {
	resp, err := httpClient.Get(args.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "fetch", Description: "Fetches a URL"}, FetchHandler)
}
