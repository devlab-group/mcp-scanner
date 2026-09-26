package taintfixture

import "os/exec"

// RunHandler passes the caller's value to a fixed program without a shell. "--" prevents the
// program from reading the value as an option.
func RunHandler(ctx Context, args RunArgs) (string, error) {
	out, _ := exec.Command("git", "log", "--oneline", "--", args.Command).Output()
	return string(out), nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "run", Description: "Shows the history of one file"}, RunHandler)
}
