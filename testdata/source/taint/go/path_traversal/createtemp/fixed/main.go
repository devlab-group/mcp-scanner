package taintfixture

import (
	"os"
	"path/filepath"
)

const baseDir = "/srv/project"

func UploadHandler(ctx Context, args UploadArgs) (string, error) {
	safe := filepath.Base(args.SubDir)
	f, err := os.CreateTemp(baseDir+"/"+safe, "upload-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return f.Name(), nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "upload", Description: "Stages an uploaded file in a project subdirectory"}, UploadHandler)
}
