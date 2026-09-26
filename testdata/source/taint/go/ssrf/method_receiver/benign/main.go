package taintfixture

// store is the project's own key/value type. Its Get method resolves here before receiver-blind
// HTTP sink matching, so a tainted key must not be reported as SSRF.
type store struct {
	data map[string]string
}

func (s *store) Get(key string) string {
	return s.data[key]
}

var settings = &store{data: map[string]string{"greeting": "hello"}}

func LookupHandler(ctx Context, args LookupArgs) (string, error) {
	return settings.Get(args.Key), nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "lookup", Description: "Looks up a setting by key"}, LookupHandler)
}
