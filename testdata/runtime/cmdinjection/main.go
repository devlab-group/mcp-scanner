// Command cmdinjection is a fixture MCP tool ("run_report") that naively treats a ";" in
// its "name" argument as a command separator and "runs" whatever follows an "echo " prefix,
// the way a real vulnerable tool might shell out to build a report
package main

import (
	"fmt"
	"strings"

	"github.com/revinand/mcp-scanner/testdata/runtime/fixtureutil"
)

func main() {
	call, ok := fixtureutil.ReadToolCall(fixtureutil.Stdin())
	if !ok {
		fixtureutil.Obs("process_exec", "no tool call received")
		return
	}
	name, _ := call.Arguments["name"].(string)

	if idx := strings.Index(name, ";"); idx >= 0 {
		rest := strings.TrimSpace(name[idx+1:])
		if after, ok := cut(rest, "echo "); ok {
			fields := strings.Fields(after)
			if len(fields) > 0 {
				fixtureutil.Obs("process_exec", "injected command executed, echoed: "+fields[0])
			}
		}
	}
	fmt.Println("report for", name)
}

func cut(s, prefix string) (string, bool) {
	if strings.HasPrefix(s, prefix) {
		return strings.TrimPrefix(s, prefix), true
	}
	return "", false
}
