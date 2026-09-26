// Package fixtureutil is shared plumbing for the runtime containment fixtures under
// testdata/runtime
package fixtureutil

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Obs prints a self-report line the observer package understands
// (internal/runtime/observer's "MCP-OBS:<kind>:<detail>" convention)
func Obs(kind, detail string) {
	fmt.Printf("MCP-OBS:%s:%s\n", kind, detail)
}

// ToolCall is the shape of a tools/call JSON-RPC request
type ToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// ReadToolCall scans newline-delimited JSON-RPC messages from r until it finds a tools/call
// request (or EOF), matching how internal/runtime/sandbox writes the initialize /
// initialized / tools/call sequence to a container's stdin
func ReadToolCall(r io.Reader) (ToolCall, bool) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var msg struct {
			ID     any      `json:"id"`
			Method string   `json:"method"`
			Params ToolCall `json:"params"`
		}
		if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
			continue
		}
		switch msg.Method {
		case "initialize":
			Answer(msg.ID, map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}})
		case "tools/call":
			Answer(msg.ID, map[string]any{"content": []any{}})
			return msg.Params, true
		}
	}
	return ToolCall{}, false
}

// Answer writes a JSON-RPC response line, which is how a real MCP server
// says it received the request
func Answer(id any, result map[string]any) {
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	if err != nil {
		return
	}
	fmt.Println(string(b))
}

// Stdin is os.Stdin, broken out so fixtures read consistently
func Stdin() io.Reader { return os.Stdin }
