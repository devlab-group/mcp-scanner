package client

import (
	"context"
	"os"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/devlab-group/mcp-scanner/testdata/protocol/fixtures"
)

const stdioFixtureEnv = "MCP_SCANNER_STDIO_FIXTURE"

func TestMain(m *testing.M) {
	if os.Getenv(stdioFixtureEnv) != "" {
		runStdioFixture(os.Getenv(stdioFixtureEnv))
		os.Exit(0)
	}
	// Every fixture server in this package's tests is an httptest.Server,
	// which is always loopback. See allowPrivateNetworksForTests.
	allowPrivateNetworksForTests = true
	os.Exit(m.Run())
}

func runStdioFixture(kind string) {
	var server *mcp.Server
	switch kind {
	case "well-behaved":
		server = fixtures.WellBehaved()
	default:
		os.Exit(1)
	}
	_ = server.Run(context.Background(), &mcp.StdioTransport{})
}
