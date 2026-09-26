package taintfixture

import "os"

const uploadDir = "/srv/project/uploads"

// The caller-supplied label never reaches the directory passed to
// os.CreateTemp - only a fixed, literal directory does
func UploadHandler(ctx Context, args UploadArgs) (string, error) {
	f, err := os.CreateTemp(uploadDir, "upload-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return args.Label, nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "upload", Description: "Stages an uploaded file with a caller-supplied label"}, UploadHandler)
}
