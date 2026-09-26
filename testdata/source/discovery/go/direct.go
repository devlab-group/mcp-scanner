// Direct SDK registration: a call straight into the server's AddTool with a
// composite literal declaring the name and description in place
package discovery

func DirectHandler(ctx Context, args DirectArgs) (string, error) {
	return args.Text, nil
}

func RegisterDirect(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "direct_echo", Description: "Echoes text back unchanged"}, DirectHandler)
}
