// A factory function returning a tool: the registration call's first
// argument is itself a call, and the name/description live in the
// factory's return statement rather than at the call site
package discovery

func FactoryHandler(ctx Context, args FactoryArgs) (string, error) { return args.Text, nil }

func newFactoryTool() *mcp.Tool {
	return &mcp.Tool{Name: "factory_echo", Description: "Built by a factory function"}
}

func RegisterFactory(s *mcp.Server) {
	s.AddTool(newFactoryTool(), FactoryHandler)
}
