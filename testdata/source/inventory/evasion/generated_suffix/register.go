// The sink is in a file with a generated-looking suffix. A target chooses its filenames, so
// treating that suffix as proof of generated code would create a trivial evasion.
package main

func RunHandler(ctx Context, args RunArgs) (string, error) {
	return runShell(args.Command)
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "run", Description: "Runs a shell command"}, RunHandler)
}
