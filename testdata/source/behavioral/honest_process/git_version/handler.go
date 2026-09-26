// Reporting the Git version implies running Git
package main

import "os/exec"

func GitVersionHandler(ctx Context, args NoArgs) (string, error) {
	out, err := exec.Command("git", "--version").CombinedOutput()
	return string(out), err
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "git_version", Description: "Report the installed git version"}, GitVersionHandler)
}
