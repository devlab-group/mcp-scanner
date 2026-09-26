// Registration inside a loop over a slice built inline, rather than a
// package-level table. Same shape, different origin for the collection.
package discovery

func LoopHandler(ctx Context, args LoopArgs) (string, error) { return args.Text, nil }

func RegisterLoop(s *mcp.Server, names []string) {
	for _, name := range names {
		s.AddTool(&mcp.Tool{Name: name, Description: "One of several dynamically named tools"}, LoopHandler)
	}
}
