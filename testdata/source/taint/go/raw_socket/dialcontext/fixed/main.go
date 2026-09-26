package taintfixture

import (
	"context"
	"errors"
	"net"
)

var dialer net.Dialer

func ConnectHandler(ctx Context, args ConnectArgs) (string, error) {
	switch args.Service {
	case "primary":
		return connect("primary.internal.example:443")
	case "backup":
		return connect("backup.internal.example:443")
	}
	return "", errors.New("unknown service")
}

func connect(host string) (string, error) {
	conn, err := dialer.DialContext(context.Background(), "tcp", host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "connect", Description: "Opens a TCP connection to one of a fixed set of internal services"}, ConnectHandler)
}
