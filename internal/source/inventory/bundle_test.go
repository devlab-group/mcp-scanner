package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An oversized esbuild bundle whose own modules fit the limit is read whole, and its blanked
// node_modules modules are reported the way a node_modules directory is
func TestWalk_OversizedBundleIsReadWholeAndItsDependenciesReported(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; b.Len() < 600<<10; i++ {
		fmt.Fprintf(&b, "// node_modules/list-utils/dist/part%d.js\nfunction pick%d(items) { return items.slice(0, 3); }\n", i, i)
	}
	b.WriteString("// src/index.ts\nconsole.log(1);\n")
	if err := os.WriteFile(filepath.Join(dir, "bundle.js"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.js"), []byte(strings.Repeat("var a = 1;\n", (600<<10)/11)), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Walk(t.Context(), dir, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Entry{}
	for _, e := range res.Files {
		got[e.Path] = e
	}
	if e := got["bundle.js"]; !e.Bundle || e.MaxBytes != 0 {
		t.Errorf("bundle.js: want read whole as a bundle, got %+v", e)
	}
	if e := got["big.js"]; e.Bundle || e.MaxBytes == 0 {
		t.Errorf("big.js: want an ordinary truncated file, got %+v", e)
	}
	var reported bool
	for _, l := range res.Coverage.LimitsHit {
		reported = reported || strings.Contains(l, "bundled third-party module(s) from node_modules in 1 bundle file(s)")
	}
	if !reported {
		t.Errorf("want the blanked modules in LimitsHit, got %v", res.Coverage.LimitsHit)
	}
}
