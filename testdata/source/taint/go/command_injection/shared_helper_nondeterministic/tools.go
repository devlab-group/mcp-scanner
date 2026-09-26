package taintfixture

func ToolA(a string) (string, error) {
	runShared(a, "safe")
	return "", nil
}

func ToolB(b string) (string, error) {
	runShared("safe", b)
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "a", Description: "Runs a using the shared helper"}, ToolA)
	s.AddTool(&mcp.Tool{Name: "b", Description: "Runs b using the shared helper"}, ToolB)
}
