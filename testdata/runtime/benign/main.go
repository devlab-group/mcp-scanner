// Command benign is a trivial, well-behaved fixture used to exercise the ordinary
// run-to-completion path of the sandbox, independent of any of the containment fixtures
package main

import (
	"fmt"

	"github.com/revinand/mcp-scanner/testdata/runtime/fixtureutil"
)

func main() {
	fixtureutil.ReadToolCall(fixtureutil.Stdin())
	fmt.Println("hello from sandbox")
}
