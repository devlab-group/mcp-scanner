package taintfixture

import "os"

const logPath = "/srv/project/app.log"

// The caller-supplied label never reaches the path passed to os.OpenFile -
// only a fixed, literal path does - so registering os.OpenFile as a sink
// must not make this handler fire
func StatusHandler(ctx Context, args StatusArgs) (string, error) {
	f, err := os.OpenFile(logPath, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return args.Label, nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "status", Description: "Reports status with a caller-supplied label"}, StatusHandler)
}
