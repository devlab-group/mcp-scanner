// Command pathtraversal is a vulnerable read_file fixture. It joins caller
// input to a fixed base without rejecting "..". Tests target a planted canary rather than a
// real host file, confirming traversal without escaping the sandbox fixture.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/revinand/mcp-scanner/testdata/runtime/fixtureutil"
)

const base = "/sandbox/home/public"

func main() {
	call, ok := fixtureutil.ReadToolCall(fixtureutil.Stdin())
	if !ok {
		fixtureutil.Obs("file_read", "no tool call received")
		return
	}
	path, _ := call.Arguments["path"].(string)
	// Strip the marker suffix before resolving the path
	path, _, _ = strings.Cut(path, "#")

	// Caller input can escape base through ".."
	full := filepath.Join(base, path)

	b, err := os.ReadFile(full)
	if err != nil {
		// Report only successful reads; a failed attempt proves nothing
		return
	}
	escaped := !strings.HasPrefix(full, base+string(filepath.Separator))
	fixtureutil.Obs("file_read", fmt.Sprintf("%s: succeeded, escaped=%v", full, escaped))
	fmt.Println(string(b))
}
