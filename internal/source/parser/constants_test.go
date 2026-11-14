package parser

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

// Carry binding context downward once per node so deeply nested constant uses
// do not trigger repeated Node.Parent searches from the root
func TestParseFile_DeeplyNestedConstantUsesDoNotStallTheParse(t *testing.T) {
	const depth = 20000
	src := []byte(`BASE = "https://api.example.com"` + "\nx = " + strings.Repeat("[BASE, ", depth) + "1" + strings.Repeat("]", depth) + "\n")

	type result struct {
		res *FileResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := ParseFile(context.Background(), language.ByID(language.Python), "server.py", src)
		done <- result{res, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("ParseFile: %v", r.err)
		}
		if got, want := r.res.Constants["BASE"], "https://api.example.com"; got != want {
			t.Fatalf("Constants[BASE] = %q, want %q: reading a constant is not a binding of it", got, want)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("parse of %d nested uses of a module constant still running after 30s", depth)
	}
}
