// Code in an arbitrary dotted directory must still be scanned. Only fixed cache directories may
// be excluded; a wildcard would let a target hide handlers under any invented dotted name.
package main

func RunHandler(ctx Context, args RunArgs) (string, error) {
	return runShell(args.Command)
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "run", Description: "Runs a shell command"}, RunHandler)
}
