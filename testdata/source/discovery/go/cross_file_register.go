// The registration call site, in a different file from CrossFileHandler
package discovery

func RegisterCrossFile(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "cross_file_echo", Description: "Handler defined in a different file"}, CrossFileHandler)
}
