package source

import (
	"context"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
)

func TestDiscovery(t *testing.T) {
	cases := []struct {
		dir      string
		names    []string // expected NameResolved capability names
		forms    []string // every Form that must appear at least once
		minCount int      // total capabilities discovered, including unresolved
	}{
		{
			dir:   "../../testdata/source/discovery/go",
			names: []string{"direct_echo", "wrapper_echo", "factory_echo", "cross_file_echo", "aliased_echo"},
			forms: []string{"direct", "wrapper", "loop", "factory"},

			minCount: 7,
		},
		{
			dir:      "../../testdata/source/discovery/python",
			names:    []string{"direct_echo", "decorator_echo", "wrapper_echo", "factory_echo", "cross_file_echo", "aliased_echo"},
			forms:    []string{"direct", "decorator", "wrapper", "loop", "factory"},
			minCount: 7,
		},
		{
			dir:      "../../testdata/source/discovery/javascript",
			names:    []string{"js_echo"},
			forms:    []string{"direct"},
			minCount: 1,
		},
		{
			dir:      "../../testdata/source/discovery/typescript",
			names:    []string{"ts_echo"},
			forms:    []string{"wrapper"},
			minCount: 1,
		},
		{
			dir:      "../../testdata/source/discovery/java",
			names:    []string{"java_echo"},
			forms:    []string{"decorator"},
			minCount: 1,
		},
		{
			dir:      "../../testdata/source/discovery/rust",
			names:    []string{"rust_echo"},
			forms:    []string{"decorator"},
			minCount: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			g, cov, err := Build(context.Background(), tc.dir)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if cov.FilesFailed != 0 {
				t.Fatalf("want no parse failures, got %d (skip reasons: %v)", cov.FilesFailed, cov.SkipReasons)
			}
			if len(g.Capabilities) < tc.minCount {
				t.Fatalf("want at least %d capabilities, got %d: %+v", tc.minCount, len(g.Capabilities), g.Capabilities)
			}
			if cov.CapabilitiesDiscovered != len(g.Capabilities) {
				t.Fatalf("coverage.CapabilitiesDiscovered (%d) must match len(Capabilities) (%d)", cov.CapabilitiesDiscovered, len(g.Capabilities))
			}

			gotNames := map[string]bool{}
			gotForms := map[string]bool{}
			for _, c := range g.Capabilities {
				gotForms[c.Form] = true
				if c.NameResolved {
					gotNames[c.Name] = true
				}
			}
			for _, name := range tc.names {
				if !gotNames[name] {
					t.Errorf("expected a resolved capability named %q, got names %v (full: %+v)", name, gotNames, g.Capabilities)
				}
			}
			for _, form := range tc.forms {
				if !gotForms[form] {
					t.Errorf("expected a capability with form %q, got forms %v", form, gotForms)
				}
			}
		})
	}
}

func TestDiscovery_HandlersResolveCrossFile(t *testing.T) {
	for _, dir := range []string{"../../testdata/source/discovery/go", "../../testdata/source/discovery/python"} {
		g, _, err := Build(context.Background(), dir)
		if err != nil {
			t.Fatalf("Build(%s): %v", dir, err)
		}
		var found *graph.Capability
		for i := range g.Capabilities {
			if g.Capabilities[i].Name == "cross_file_echo" {
				found = &g.Capabilities[i]
			}
		}
		if found == nil {
			t.Fatalf("%s: cross_file_echo capability not found among %+v", dir, g.Capabilities)
		}
		if found.Handler == "" {
			t.Fatalf("%s: cross_file_echo handler did not resolve", dir)
		}
		sym := g.Symbols[found.Handler]
		if sym == nil {
			t.Fatalf("%s: resolved handler symbol missing from graph", dir)
		}
		if sym.File == found.File {
			t.Errorf("%s: expected the handler to live in a different file than the registration call, both are %q", dir, sym.File)
		}
	}
}

// TestDiscovery_AliasedImportCaptured checks that an aliased import is
// recorded with both its path and its alias
func TestDiscovery_AliasedImportCaptured(t *testing.T) {
	for _, tc := range []struct {
		dir, file, alias string
	}{
		{"../../testdata/source/discovery/go", "aliased_import.go", "mcpsdk"},
		{"../../testdata/source/discovery/python", "aliased_import.py", "server_sdk"},
	} {
		g, _, err := Build(context.Background(), tc.dir)
		if err != nil {
			t.Fatalf("Build(%s): %v", tc.dir, err)
		}
		f := g.Files[tc.file]
		if f == nil {
			t.Fatalf("%s: file %q not found in graph", tc.dir, tc.file)
		}
		found := false
		for _, imp := range f.Imports {
			if imp.Alias == tc.alias {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected an import aliased %q, got %+v", tc.dir, tc.alias, f.Imports)
		}
	}
}
