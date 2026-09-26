// Taint must propagate through compact multi-name parameters such as a, b string. Tree-sitter
// represents the shared declaration as one node, but both names still need independent bindings.
package taintfixture

import "os/exec"

func runIn(label, command string) (string, error) {
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
