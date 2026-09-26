// The tainted argument passes through thirdparty.Transform, a function
// this tree does not define - taint must not stop at the unresolved call;
// it keeps going with an UNKNOWN step in the path and a lower confidence
package taintfixture

import "os/exec"

func RunHandler(ctx Context, args RunArgs) (string, error) {
	prepared := thirdparty.Transform(args.Command)
	out, _ := exec.Command("sh", "-c", prepared).Output()
	return string(out), nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "run", Description: "Runs a shell command"}, RunHandler)
}
