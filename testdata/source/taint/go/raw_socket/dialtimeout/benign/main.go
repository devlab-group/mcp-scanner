package taintfixture

import (
	"net"
	"time"
)

const primaryHost = "primary.internal.example:443"

// The caller-supplied label never reaches the dialed host - only a
// fixed, literal host does
func ConnectHandler(ctx Context, args ConnectArgs) (string, error) {
	conn, err := net.DialTimeout("tcp", primaryHost, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return args.Label, nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "connect", Description: "Connects to a fixed internal service with a caller-supplied label"}, ConnectHandler)
}
