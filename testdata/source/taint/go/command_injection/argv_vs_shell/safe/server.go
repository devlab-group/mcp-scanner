// Caller input reaches a later argv element, not a shell command. Metacharacters stay literal
// bytes passed to tar, so this fixture must not be reported as command injection.
package main

func ArchiveHandler(ctx Context, args ArchiveArgs) (string, error) {
	return runArchive(args.Name)
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "archive", Description: "Archive a project directory"}, ArchiveHandler)
}
