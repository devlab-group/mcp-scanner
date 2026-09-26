package main

import (
	"io"
	"testing"

	"github.com/revinand/mcp-scanner/internal/policy"
	"github.com/revinand/mcp-scanner/internal/testutil"
)

func TestParsePackageArgPositionalForm(t *testing.T) {
	eco, name, version, err := parsePackageArg([]string{"npm", "left-pad", "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if eco != "npm" || name != "left-pad" || version != "1.0.0" {
		t.Fatalf("got %q %q %q", eco, name, version)
	}
}

func TestParsePackageArgPositionalFormNoVersion(t *testing.T) {
	eco, name, version, err := parsePackageArg([]string{"pypi", "requests"})
	if err != nil {
		t.Fatal(err)
	}
	if eco != "pypi" || name != "requests" || version != "" {
		t.Fatalf("got %q %q %q", eco, name, version)
	}
}

// The README's documented form
func TestParsePackageArgColonForm(t *testing.T) {
	eco, name, version, err := parsePackageArg([]string{"npm:@example/mcp-server@1.4.0"})
	if err != nil {
		t.Fatal(err)
	}
	if eco != "npm" || name != "@example/mcp-server" || version != "1.4.0" {
		t.Fatalf("got %q %q %q, want npm, @example/mcp-server, 1.4.0", eco, name, version)
	}
}

func TestParsePackageArgColonFormUnscopedNoVersion(t *testing.T) {
	eco, name, version, err := parsePackageArg([]string{"pypi:requests"})
	if err != nil {
		t.Fatal(err)
	}
	if eco != "pypi" || name != "requests" || version != "" {
		t.Fatalf("got %q %q %q", eco, name, version)
	}
}

func TestParsePackageArgColonFormScopedNoVersion(t *testing.T) {
	eco, name, version, err := parsePackageArg([]string{"npm:@example/mcp-server"})
	if err != nil {
		t.Fatal(err)
	}
	if eco != "npm" || name != "@example/mcp-server" || version != "" {
		t.Fatalf("got %q %q %q, want npm, @example/mcp-server, \"\"", eco, name, version)
	}
}

func TestParsePackageArgInvalidSingleArg(t *testing.T) {
	if _, _, _, err := parsePackageArg([]string{"not-a-valid-spec"}); err == nil {
		t.Fatal("expected an error for a single argument with no colon")
	}
}

func TestPackageCmdRemovesExtractionDirectoryOnResolveFailure(t *testing.T) {
	// Isolate the temp directory from concurrent API package tests that use the same prefix
	t.Setenv("TMPDIR", t.TempDir())

	exitCode = policy.ExitOK
	root := newRootCmd()
	root.SetArgs([]string{"package", "npm:whatever", "--analyzers", "nosuchanalyzer"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err == nil {
		t.Fatal("expected an error for an unknown analyzer")
	}
	if exitCode != policy.ExitUsage {
		t.Errorf("exitCode = %d, want ExitUsage", exitCode)
	}

	if n := testutil.CountPackageExtractionDirs(t); n != 0 {
		t.Fatalf("extraction directory leaked: %d left", n)
	}
}
