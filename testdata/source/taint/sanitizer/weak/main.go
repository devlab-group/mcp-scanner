// filepath.Clean is a real sanitizer, but on its own it does not stop traversal outside the
// base directory: "../../etc/passwd" stays exactly that after Clean, it just normalizes
// redundant separators
package taintfixture

import (
	"os"
	"path/filepath"
)

const baseDir = "/srv/project"

func ReadHandler(ctx Context, args ReadArgs) (string, error) {
	cleaned := filepath.Clean(args.Name)
	data, err := os.ReadFile(baseDir + "/" + cleaned)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "read", Description: "Reads a file from the project directory"}, ReadHandler)
}
