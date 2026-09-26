package taintfixture

import "os/exec"

func RunHandler(ctx Context, args RunArgs) (string, error) {
	out, _ := exec.Command("sh", "-c", args.Command).Output()
	return string(out), nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "run", Description: "Runs a shell command"}, RunHandler)
}
