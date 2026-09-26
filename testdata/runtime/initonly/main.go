// Command initonly answers initialize, then panics on tools/call with an ordinary exit code.
// The missing tools/call reply is the only evidence that the tool did not run.
package main

import (
	"bufio"
	"encoding/json"
	"os"

	"github.com/revinand/mcp-scanner/testdata/runtime/fixtureutil"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var msg struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		if json.Unmarshal(sc.Bytes(), &msg) != nil {
			continue
		}
		switch msg.Method {
		case "initialize":
			fixtureutil.Answer(msg.ID, map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}})
		case "tools/call":
			var m map[string]int
			m["boom"] = 1
		}
	}
}
