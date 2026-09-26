package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestResolvedConfigShowsTheSwitchesThatAreOff(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, key := range []string{
		"tolerate_unknown: false",
		"allow_private_networks: false",
		"read_resources: false",
		"get_prompts: false",
	} {
		if !strings.Contains(string(out), key) {
			t.Errorf("resolved configuration does not mention %q:\n%s", key, out)
		}
	}
}

func TestLLMInsecureEndpointIsReachableFromConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scanner.yaml")
	body := "llm:\n  provider: openai\n  base_url: http://gateway.internal:8000/v1\n  allow_insecure_endpoint: true\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.LLM.AllowInsecureEndpoint {
		t.Fatalf("allow_insecure_endpoint did not survive loading: %+v", cfg.LLM)
	}
}

func TestRuntimeNetworkKeyStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scanner.yaml")
	if err := os.WriteFile(path, []byte("runtime:\n  enabled: true\n  network: deny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("a configuration written by our own config command stopped loading: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("runtime.network: deny rejected: %v", err)
	}
}

func TestReadResourcesNeedsActiveProbesSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scanner.yaml")
	if err := os.WriteFile(path, []byte("active_probes: none\nread_resources: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("read_resources with active_probes: none was accepted")
	}

	pathOK := filepath.Join(t.TempDir(), "scanner.yaml")
	if err := os.WriteFile(pathOK, []byte("active_probes: safe\nread_resources: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(pathOK); err != nil {
		t.Fatalf("read_resources with active_probes: safe was rejected: %v", err)
	}

	// The default active_probes (no key in the file at all) is safe, so
	// read_resources alone must not need the key spelled out
	pathDefault := filepath.Join(t.TempDir(), "scanner.yaml")
	if err := os.WriteFile(pathDefault, []byte("read_resources: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(pathDefault); err != nil {
		t.Fatalf("read_resources with the default active_probes was rejected: %v", err)
	}
}

func TestRuntimeNetworkCanaryIsRefused(t *testing.T) {
	cfg := Defaults()
	cfg.Runtime.Enabled = true
	cfg.Runtime.Network = "canary"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("canary was accepted; it does nothing and it opens the sandbox up")
	}
	if !strings.Contains(err.Error(), "runtime.network") {
		t.Fatalf("the error does not name the setting: %v", err)
	}
}

func TestAuthTokensEnvLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scanner.yaml")
	body := "analyzer_options:\n" +
		"  auth:\n" +
		"    tokens_env:\n" +
		"      valid: MCP_SCANNER_TEST_AUTH_TOKEN_VALID\n" +
		"      user_b: MCP_SCANNER_TEST_AUTH_TOKEN_USER_B\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, ok := asStringMap(cfg.AnalyzerOptions["auth"]["tokens_env"])
	if !ok {
		t.Fatalf("analyzer_options.auth.tokens_env did not decode to a string map: %#v", cfg.AnalyzerOptions["auth"]["tokens_env"])
	}
	if got["valid"] != "MCP_SCANNER_TEST_AUTH_TOKEN_VALID" || got["user_b"] != "MCP_SCANNER_TEST_AUTH_TOKEN_USER_B" {
		t.Fatalf("tokens_env did not round-trip: %#v", got)
	}
}

func TestAuthTokensEnvRejectsEmptyVariableName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scanner.yaml")
	body := "analyzer_options:\n  auth:\n    tokens_env:\n      valid: \"\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("tokens_env with an empty environment variable name was accepted")
	}
	if !strings.Contains(err.Error(), "tokens_env") {
		t.Fatalf("the error does not name the setting: %v", err)
	}
}

func TestAuthTokensEnvResolvesThroughSecret(t *testing.T) {
	const env = "MCP_SCANNER_TEST_AUTH_TOKEN_RESOLVE"
	t.Setenv(env, "sk-live-should-never-be-in-the-config-file")

	path := filepath.Join(t.TempDir(), "scanner.yaml")
	body := "analyzer_options:\n  auth:\n    tokens_env:\n      valid: " + env + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	entries, ok := asStringMap(cfg.AnalyzerOptions["auth"]["tokens_env"])
	if !ok {
		t.Fatalf("tokens_env did not decode to a string map: %#v", cfg.AnalyzerOptions["auth"]["tokens_env"])
	}
	if got := Secret(entries["valid"]); got != "sk-live-should-never-be-in-the-config-file" {
		t.Fatalf("Secret(%q) = %q, want the value of %s", entries["valid"], got, env)
	}
}

// Reject configuration that would silently run a different scan than the file describes
func TestLoadRefusesMisleadingConfig(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"misspelled key", "fial_on: high\n", "fial_on"},
		{"unknown fail_on", "fail_on: severe\n", "fail_on"},
		{"unknown blocking severity", "blocking_severity: bad\n", "blocking_severity"},
		{"unknown probe level", "active_probes: aggressive\n", "active_probes"},
		{"tool calls with no allowlist", "active_probes: tool-calls\n", "allow_tool_calls"},
		{"fetching content with probes off", "active_probes: none\nread_resources: true\n", "read_resources"},
		{"negative concurrency", "concurrency: -1\n", "concurrency"},
		{"negative timeout", "timeout: -5s\n", "timeout"},
		{"negative analyzer timeout", "analyzer_timeout: -5s\n", "analyzer_timeout"},
		{"unsupported runtime backend", "runtime:\n  enabled: true\n  backend: podman\n", "runtime.backend"},
		{"unknown runtime network", "runtime:\n  network: open\n", "runtime.network"},
		{"missing rules directory", "rules:\n  yara_dir: /nonexistent/mcp-scanner-rules\n", "rules.yara_dir"},
		{"baseline entry with no reason", "baseline:\n  f_0123456789abcdef: \"\"\n", "baseline"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load = %v, want an error naming %s", err, tc.want)
			}
		})
	}
}

// Parse duration strings without changing their values
func TestLoadReadsDurations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("timeout: 30s\nanalyzer_timeout: 45s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout.Std() != 30*time.Second || cfg.AnalyzerTimeout.Std() != 45*time.Second {
		t.Fatalf("timeout = %s, analyzer_timeout = %s, want 30s and 45s", cfg.Timeout.Std(), cfg.AnalyzerTimeout.Std())
	}
}
