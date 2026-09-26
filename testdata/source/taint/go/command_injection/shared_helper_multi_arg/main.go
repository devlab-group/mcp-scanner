// The dangerous helper argument is not the first argument. Seeding only the first tainted call
// argument would leave the command parameter untraced and miss this sink.
package taintfixture

import "os/exec"

func runIn(label string, command string) (string, error) {
	_ = label
	out, _ := exec.Command("sh", "-c", command).Output()
	return string(out), nil
}

func BuildHandler(label string, target string) (string, error) {
	return runIn(label, target)
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "build", Description: "Builds a target"}, BuildHandler)
}
