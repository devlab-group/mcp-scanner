// A wrapper/helper function that itself calls the SDK, forwarding its own parameters into
// the registration call
package discovery

func WrapperHandler(ctx Context, args WrapperArgs) (string, error) {
	return args.Text, nil
}

func registerWrapperTool(s *mcp.Server, name string, description string, fn Handler) {
	s.AddTool(&mcp.Tool{Name: name, Description: description}, fn)
}

func SetupWrapper(s *mcp.Server) {
	registerWrapperTool(s, "wrapper_echo", "Echoes text back through a wrapper", WrapperHandler)
}
