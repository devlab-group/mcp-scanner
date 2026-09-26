package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runConfigCmd captures the config command's direct stdout output
func runConfigCmd(t *testing.T, args ...string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	real := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = real })

	cmd := newConfigCmd()
	cmd.SetArgs(args)
	execErr := cmd.Execute()
	w.Close()
	os.Stdout = real

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if execErr != nil {
		t.Fatalf("config command failed: %v (output so far: %s)", execErr, out)
	}
	return string(out)
}

// Config output preserves token case names but hides their values
func TestConfigCommandRedactsLiteralTokens(t *testing.T) {
	const secret = "sk-live-SECRET-TOKEN-123"
	path := filepath.Join(t.TempDir(), "scanner.yaml")
	body := "analyzer_options:\n" +
		"  auth:\n" +
		"    tokens:\n" +
		"      valid: " + secret + "\n" +
		"      user_b: sk-live-OTHER-456\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	out := runConfigCmd(t, "--config", path)

	if strings.Contains(out, secret) {
		t.Fatalf("config output contains the literal token:\n%s", out)
	}
	if strings.Contains(out, "sk-live-OTHER-456") {
		t.Fatalf("config output contains the second literal token:\n%s", out)
	}
	if !strings.Contains(out, "valid:") || !strings.Contains(out, "user_b:") {
		t.Fatalf("config output no longer names which token cases are configured:\n%s", out)
	}
	if !strings.Contains(out, redactedTokenValue) {
		t.Fatalf("config output does not show the redaction placeholder:\n%s", out)
	}
}

// Redaction must return a copy. Mutating the loaded map would give analyzers a placeholder
// instead of the configured token.
func TestRedactTokensLeavesItsInputAlone(t *testing.T) {
	const secret = "sk-live-SECRET-TOKEN-123"
	opts := map[string]map[string]any{"auth": {"tokens": map[string]any{"valid": secret}}}

	out := redactTokens(opts)
	if got := out["auth"]["tokens"].(map[string]any)["valid"]; got != redactedTokenValue {
		t.Fatalf("redacted copy holds %v, want %q", got, redactedTokenValue)
	}
	if got := opts["auth"]["tokens"].(map[string]any)["valid"]; got != secret {
		t.Fatalf("redaction changed the input: %v", got)
	}
}
