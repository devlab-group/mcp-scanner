package taintfixture

import "os"

const baseDir = "/srv/project"

func ReadHandler(ctx Context, args ReadArgs) (string, error) {
	data, err := os.ReadFile(baseDir + "/" + args.Name)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "read", Description: "Reads a file from the project directory"}, ReadHandler)
}
