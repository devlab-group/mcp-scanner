// Package config loads and validates scanner configuration.
//
// Structural settings resolve from built-in defaults, a config file, and command-line flags in
// increasing precedence. Fields ending in _env name environment variables read at the point of
// use; Prepare checks that an opted-in LLM key is present without retaining its value.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Config is the on-disk configuration. Operator-facing YAML keeps explicit false switches
// visible where omitting them would hide resolved behavior.
type Config struct {
	// Analyzers to run. Empty means every applicable analyzer in the build
	Analyzers []string `yaml:"analyzers,omitempty" json:"analyzers,omitempty"`
	// BestEffort analyzers do not block the verdict when they fail
	BestEffort []string `yaml:"best_effort,omitempty" json:"best_effort,omitempty"`

	FailOn           string `yaml:"fail_on,omitempty" json:"fail_on,omitempty"`
	BlockingSeverity string `yaml:"blocking_severity,omitempty" json:"blocking_severity,omitempty"`
	// TolerateUnknown lets a scan that could not finish pass anyway. Off by
	// default: a scan that could not determine an answer is not a pass, and
	// exit code 3 exists to say so. Turning it on is a deliberate choice to
	// treat an incomplete scan as acceptable.
	TolerateUnknown bool `yaml:"tolerate_unknown" json:"tolerate_unknown,omitempty"`

	ActiveProbes string `yaml:"active_probes,omitempty" json:"active_probes,omitempty"`

	// AllowPrivateNetworks lets the scanner connect to loopback, link-local
	// and private-range destinations. Off by default, because the usual
	// target is untrusted and the interesting destination for a hostile
	// server is the network the scanner runs on. Turn it on to scan a server
	// on localhost or inside your own network.
	AllowPrivateNetworks bool `yaml:"allow_private_networks" json:"allow_private_networks,omitempty"`

	// ReadResources and GetPrompts fetch what a server would hand a model, not only declarations.
	// Both make target calls, so they require active_probes safe or higher.
	ReadResources  bool     `yaml:"read_resources" json:"read_resources,omitempty"`
	GetPrompts     bool     `yaml:"get_prompts" json:"get_prompts,omitempty"`
	AllowToolCalls []string `yaml:"allow_tool_calls,omitempty" json:"allow_tool_calls,omitempty"`

	Timeout         Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	AnalyzerTimeout Duration `yaml:"analyzer_timeout,omitempty" json:"analyzer_timeout,omitempty"`
	Concurrency     int      `yaml:"concurrency,omitempty" json:"concurrency,omitempty"`

	// AnalyzerOptions holds per-analyzer settings, keyed by analyzer name
	AnalyzerOptions map[string]map[string]any `yaml:"analyzer_options,omitempty" json:"analyzer_options,omitempty"`

	// Baseline maps accepted finding IDs to the reason they are accepted
	Baseline map[string]string `yaml:"baseline,omitempty" json:"baseline,omitempty"`

	LLM   LLMConfig   `yaml:"llm,omitempty" json:"llm"`
	Cisco CiscoConfig `yaml:"cisco,omitempty" json:"cisco"`
	VT    VTConfig    `yaml:"virustotal,omitempty" json:"virustotal"`

	Runtime RuntimeConfig `yaml:"runtime,omitempty" json:"runtime"`

	Rules RulesConfig `yaml:"rules,omitempty" json:"rules"`
}

// LLMConfig configures the semantic-analysis backend. API keys are read from
// the environment variable named by APIKeyEnv, never stored in the file, so a
// config can be committed.
type LLMConfig struct {
	Provider  string   `yaml:"provider,omitempty" json:"provider,omitempty"` // openai | anthropic | bedrock
	Model     string   `yaml:"model,omitempty" json:"model,omitempty"`
	BaseURL   string   `yaml:"base_url,omitempty" json:"base_url,omitempty"`
	APIKeyEnv string   `yaml:"api_key_env,omitempty" json:"api_key_env,omitempty"`
	MaxTokens int      `yaml:"max_tokens,omitempty" json:"max_tokens,omitempty"`
	Timeout   Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// AllowInsecureEndpoint permits a plain http base_url. Off by default: the request carries
	// an API key and whatever surface or source text is being analyzed, so plaintext exposes
	// both to anything on the path.
	AllowInsecureEndpoint bool `yaml:"allow_insecure_endpoint,omitempty" json:"allow_insecure_endpoint,omitempty"`
}

type CiscoConfig struct {
	Endpoint  string   `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	APIKeyEnv string   `yaml:"api_key_env,omitempty" json:"api_key_env,omitempty"`
	Timeout   Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

type VTConfig struct {
	APIKeyEnv string   `yaml:"api_key_env,omitempty" json:"api_key_env,omitempty"`
	Timeout   Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// AllowUpload sends unknown files to VirusTotal. Off by default: the file
	// being scanned may be someone's proprietary source.
	AllowUpload bool `yaml:"allow_upload,omitempty" json:"allow_upload,omitempty"`
}

// RuntimeConfig configures sandboxed execution
type RuntimeConfig struct {
	Enabled bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Backend string `yaml:"backend,omitempty" json:"backend,omitempty"` // docker
	Image   string `yaml:"image,omitempty" json:"image,omitempty"`
	// Network only accepts "deny", which leaves loopback but no external network access
	Network  string   `yaml:"network,omitempty" json:"network,omitempty"` // deny
	Timeout  Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	MemoryMB int      `yaml:"memory_mb,omitempty" json:"memory_mb,omitempty"`
	CPUs     float64  `yaml:"cpus,omitempty" json:"cpus,omitempty"`
	PIDLimit int      `yaml:"pid_limit,omitempty" json:"pid_limit,omitempty"`
}

// RulesConfig points at rule directories
type RulesConfig struct {
	YARADir          string `yaml:"yara_dir,omitempty" json:"yara_dir,omitempty"`
	PromptDefenseDir string `yaml:"prompt_defense_dir,omitempty" json:"prompt_defense_dir,omitempty"`
}

// Duration is a time.Duration that reads "30s" from YAML and JSON
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }
func (d Duration) Std() time.Duration        { return time.Duration(d) }

// Defaults returns the configuration used when nothing is specified
func Defaults() Config {
	return Config{
		BlockingSeverity: string(model.DefaultBlockingSeverity),
		ActiveProbes:     string(analyzer.ProbeSafe),
		Timeout:          Duration(10 * time.Minute),
		AnalyzerTimeout:  Duration(2 * time.Minute),
		Concurrency:      4,
		Runtime: RuntimeConfig{
			Backend:  "docker",
			Network:  "deny",
			Timeout:  Duration(30 * time.Second),
			MemoryMB: 512,
			CPUs:     1,
			PIDLimit: 128,
		},
		LLM:   LLMConfig{MaxTokens: 2048, Timeout: Duration(60 * time.Second)},
		Cisco: CiscoConfig{Timeout: Duration(30 * time.Second)},
		VT:    VTConfig{Timeout: Duration(30 * time.Second)},
	}
}

// Load reads a config file, filling unset fields from the defaults. An empty
// path returns the defaults.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a misspelled key is a configuration bug, not a no-op
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate rejects configurations that would produce misleading scans
func (c Config) Validate() error {
	if c.FailOn != "" && !strings.EqualFold(c.FailOn, "none") {
		if _, err := model.ParseSeverity(c.FailOn); err != nil {
			return fmt.Errorf("fail_on: %w (or \"none\" to turn the gate off)", err)
		}
	}
	if c.BlockingSeverity != "" {
		if _, err := model.ParseSeverity(c.BlockingSeverity); err != nil {
			return fmt.Errorf("blocking_severity: %w", err)
		}
	}
	if c.ActiveProbes != "" && !analyzer.ProbeLevel(c.ActiveProbes).Valid() {
		return fmt.Errorf("active_probes: want none, safe or tool-calls, got %q", c.ActiveProbes)
	}
	if analyzer.ProbeLevel(c.ActiveProbes) == analyzer.ProbeToolCalls && len(c.AllowToolCalls) == 0 {
		return fmt.Errorf("active_probes: tool-calls needs at least one allow_tool_calls entry")
	}
	if c.ReadResources || c.GetPrompts {
		// Resource and prompt fetches are active behavior. Validate here so the
		// CLI and API enforce the same probe level.
		probes := analyzer.ProbeSafe
		if c.ActiveProbes != "" {
			probes = analyzer.ProbeLevel(c.ActiveProbes)
		}
		if !probes.AtLeast(analyzer.ProbeSafe) {
			return fmt.Errorf(
				"read_resources and get_prompts fetch from the target, so they need active_probes safe or higher, got %q",
				c.ActiveProbes)
		}
	}
	if c.Concurrency < 0 {
		return fmt.Errorf("concurrency must not be negative")
	}
	// A negative timeout was accepted and then substituted with ten
	// minutes by the scanner - while client.Options received the negative
	// value as written, which is a deadline already in the past
	if c.Timeout < 0 {
		return fmt.Errorf("timeout must not be negative")
	}
	if c.AnalyzerTimeout < 0 {
		return fmt.Errorf("analyzer_timeout must not be negative")
	}
	if c.Runtime.Enabled && c.Runtime.Backend != "docker" {
		return fmt.Errorf("runtime.backend: only docker is supported, got %q", c.Runtime.Backend)
	}
	switch c.Runtime.Network {
	case "", "deny":
	default:
		return fmt.Errorf("runtime.network: want deny, got %q", c.Runtime.Network)
	}
	if err := ValidateBaseline(c.Baseline); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	for name, dir := range map[string]string{"rules.yara_dir": c.Rules.YARADir, "rules.prompt_defense_dir": c.Rules.PromptDefenseDir} {
		if dir == "" {
			continue
		}
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return fmt.Errorf("%s: %s is not a readable directory", name, filepath.Clean(dir))
		}
	}
	if err := validateAuthTokensEnv(c.AnalyzerOptions); err != nil {
		return err
	}
	return nil
}

// validateAuthTokensEnv checks the shape of analyzer_options.auth.tokens_env, the
// environment-variable form of the auth analyzer's test tokens: a case name (the same names
// accepted under tokens, e.g. "valid", "user_b") mapped to the name of an environment
// variable to read the value from at the point of use, through Secret
func validateAuthTokensEnv(opts map[string]map[string]any) error {
	v, ok := opts["auth"]["tokens_env"]
	if !ok {
		return nil
	}
	entries, ok := asStringMap(v)
	if !ok {
		return fmt.Errorf("analyzer_options.auth.tokens_env: want a map of case name to environment variable name")
	}
	for k, env := range entries {
		if env == "" {
			return fmt.Errorf("analyzer_options.auth.tokens_env.%s: environment variable name must not be empty", k)
		}
	}
	return nil
}

// asStringMap normalizes the two shapes a YAML-decoded string-to-string mapping can take
// once it has passed through the generic analyzer_options map[string]any: map[string]any
// decoded from a file (the normal case), or map[string]string built directly by Go code
// (tests, the API)
func asStringMap(v any) (map[string]string, bool) {
	switch m := v.(type) {
	case map[string]string:
		return m, true
	case map[string]any:
		out := make(map[string]string, len(m))
		for k, val := range m {
			s, ok := val.(string)
			if !ok {
				return nil, false
			}
			out[k] = s
		}
		return out, true
	default:
		return nil, false
	}
}

// ValidateBaseline rejects an accepted finding with no reason recorded. A suppression is an
// audit decision, and an empty reason makes that decision impossible to review later.
func ValidateBaseline(b map[string]string) error {
	for id, reason := range b {
		if strings.TrimSpace(reason) == "" {
			return fmt.Errorf("entry %q has no reason; every accepted finding needs one", id)
		}
	}
	return nil
}

// Secret reads an API key from the environment variable named by env.
// Returning the value only here keeps keys out of the config struct, and so
// out of anything that serializes it.
func Secret(env string) string {
	if env == "" {
		return ""
	}
	return os.Getenv(env)
}

// RulesDirBesideExecutable finds rules/<name> next to the running binary, the fallback when no
// rules directory is configured. It never looks in the working directory, where a scanned target
// could plant rules that weaken analysis.
func RulesDirBesideExecutable(name string) (string, bool) {
	exe, err := os.Executable()
	if err != nil {
		return "", false
	}
	p := filepath.Join(filepath.Dir(exe), "rules", name)
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		return p, true
	}
	return "", false
}
