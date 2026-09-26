package taintfixture

import (
	"context"
	"net"
)

var dialer net.Dialer

func ConnectHandler(ctx Context, args ConnectArgs) (string, error) {
	conn, err := dialer.DialContext(context.Background(), "tcp", args.Host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "connect", Description: "Opens a TCP connection to a host"}, ConnectHandler)
}
