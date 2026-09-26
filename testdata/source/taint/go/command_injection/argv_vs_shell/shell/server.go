// Same handler and helper name as argv_vs_shell/safe, but the helper
// builds a shell string instead of passing the name as a separate argv
// element - this one must still fire as command injection
package main

func ArchiveHandler(ctx Context, args ArchiveArgs) (string, error) {
	return runArchive(args.Name)
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "archive", Description: "Archive a project directory"}, ArchiveHandler)
}
