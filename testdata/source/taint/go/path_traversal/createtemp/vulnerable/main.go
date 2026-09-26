package taintfixture

import "os"

const baseDir = "/srv/project"

// os.CreateTemp(dir, pattern) creates a file inside dir - a caller-
// controlled dir is just as dangerous here as one passed to os.Create
func UploadHandler(ctx Context, args UploadArgs) (string, error) {
	f, err := os.CreateTemp(baseDir+"/"+args.SubDir, "upload-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return f.Name(), nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "upload", Description: "Stages an uploaded file in a project subdirectory"}, UploadHandler)
}
