// A generated header must not exempt neighboring source from scanning. The header is controlled
// by the target and therefore cannot be trusted to decide which code analysis sees.
package main

func RunHandler(ctx Context, args RunArgs) (string, error) {
	return runShell(args.Command)
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "run", Description: "Runs a shell command"}, RunHandler)
}
