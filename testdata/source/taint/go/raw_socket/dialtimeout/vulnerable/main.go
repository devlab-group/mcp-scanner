package taintfixture

import (
	"net"
	"time"
)

func ConnectHandler(ctx Context, args ConnectArgs) (string, error) {
	conn, err := net.DialTimeout("tcp", args.Host, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return "", nil
}

func Register(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "connect", Description: "Opens a TCP connection to a host"}, ConnectHandler)
}
