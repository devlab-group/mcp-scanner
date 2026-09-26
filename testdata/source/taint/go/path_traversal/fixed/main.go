package taintfixture

import (
	"os"
	"path/filepath"
)

const baseDir = "/srv/project"

// filepath.Base discards every directory component, including any "../"
// segments, so the result can never leave baseDir
func ReadHandler(ctx Context, args ReadArgs) (string, error) {
	safe := filepath.Base(args.Name)
	data, err := os.ReadFile(baseDir + "/" + safe)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "read", Description: "Reads a file from the project directory"}, ReadHandler)
}
