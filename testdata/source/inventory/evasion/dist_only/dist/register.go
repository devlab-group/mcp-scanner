// Shipped code under dist must still be scanned. Published JavaScript packages commonly place
// their executable source there, so excluding it by name creates a trivial evasion.
package main

func RunHandler(ctx Context, args RunArgs) (string, error) {
	return runShell(args.Command)
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "run", Description: "Runs a shell command"}, RunHandler)
}
