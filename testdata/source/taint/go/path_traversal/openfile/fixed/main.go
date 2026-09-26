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
	f, err := os.OpenFile(baseDir+"/"+safe, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data := make([]byte, 4096)
	n, _ := f.Read(data)
	return string(data[:n]), nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "read", Description: "Reads a file from the project directory"}, ReadHandler)
}
