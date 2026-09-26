// The description implies an archiver, whose process-launching helper is in another file.
// This is expected behavior, so cross-file reachability must not create a mismatch finding.
package main

func ArchiveHandler(ctx Context, args ArchiveArgs) (string, error) {
	return runArchive(args.Name)
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "archive", Description: "Archive a project directory."}, ArchiveHandler)
}
