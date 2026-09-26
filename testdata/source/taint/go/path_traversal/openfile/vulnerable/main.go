package taintfixture

import "os"

const baseDir = "/srv/project"

// os.OpenFile is os.Open's own signature with explicit flags and
// permissions - the form real code reaches for once it needs anything
// other than read-only - and is a separate sinkPatterns entry from
// os.Open: mentionsIdent's word boundary means the shorter name never
// matches the longer one
func ReadHandler(ctx Context, args ReadArgs) (string, error) {
	f, err := os.OpenFile(baseDir+"/"+args.Name, os.O_RDONLY, 0)
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
