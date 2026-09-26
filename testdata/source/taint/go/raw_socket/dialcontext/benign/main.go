package taintfixture

import (
	"context"
	"net"
)

var dialer net.Dialer

const primaryHost = "primary.internal.example:443"

// The caller-supplied label never reaches the dialed host - only a
// fixed, literal host does
func ConnectHandler(ctx Context, args ConnectArgs) (string, error) {
	conn, err := dialer.DialContext(context.Background(), "tcp", primaryHost)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return args.Label, nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "connect", Description: "Connects to a fixed internal service with a caller-supplied label"}, ConnectHandler)
}
