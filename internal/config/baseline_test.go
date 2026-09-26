package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigBaselineNeedsAReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scanner.yaml")
	if err := os.WriteFile(path, []byte("baseline:\n  f_0123456789abcdef: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a baseline entry with no reason loaded without complaint")
	}

	if err := os.WriteFile(path, []byte("baseline:\n  f_0123456789abcdef: \"triaged, fix scheduled\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("a baseline entry with a reason was refused: %v", err)
	}
}

func TestValidateBaselineRejectsWhitespaceOnlyReason(t *testing.T) {
	if err := ValidateBaseline(map[string]string{"f_1": "   "}); err == nil {
		t.Fatal("a whitespace-only reason is not a reason")
	}
	if err := ValidateBaseline(nil); err != nil {
		t.Fatalf("no baseline at all is fine: %v", err)
	}
}
