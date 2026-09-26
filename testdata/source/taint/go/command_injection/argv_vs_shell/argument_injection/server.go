// Same shape as argv_vs_shell/safe, but without the literal "--": a
// tainted value in a later argv element of a non-shell command is still
// not shell command injection - there is no shell here - but it can still
// be read as a flag by tar if it starts with "-", so the lesser
// argument_injection finding must still fire
package main

func ArchiveHandler(ctx Context, args ArchiveArgs) (string, error) {
	return runArchive(args.Name)
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "archive", Description: "Archive a project directory"}, ArchiveHandler)
}
