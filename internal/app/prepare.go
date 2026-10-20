package app

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/devlab-group/mcp-scanner/internal/config"
	"github.com/devlab-group/mcp-scanner/internal/llm"
	"github.com/devlab-group/mcp-scanner/internal/llm/anthropic"
	"github.com/devlab-group/mcp-scanner/internal/llm/bedrock"
	"github.com/devlab-group/mcp-scanner/internal/llm/openai"
	"github.com/devlab-group/mcp-scanner/internal/mcp/client"
	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/internal/supplychain"
	"github.com/devlab-group/mcp-scanner/internal/supplychain/npm"
	"github.com/devlab-group/mcp-scanner/internal/supplychain/pypi"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/pkg/scanner"
)

// Preparer builds the shared analysis context for each target kind, then attaches optional LLM
// and runtime backends. Scanner options, not the preparer, set the target-specific filesystem root.
type Preparer struct {
	cfg config.Config

	// noLaunch ensures only the runtime sandbox can start a stdio target
	noLaunch     bool
	snapshotPath string
}

// NewPreparer builds the preparer for a configuration
func NewPreparer(cfg config.Config) *Preparer { return &Preparer{cfg: cfg} }

// NewSandboxOnlyPreparer prevents host execution. An optional snapshot supplies
// the declared surface without starting the target.
func NewSandboxOnlyPreparer(cfg config.Config, snapshotPath string) *Preparer {
	return &Preparer{cfg: cfg, noLaunch: true, snapshotPath: snapshotPath}
}

// clientOptions keeps connection settings consistent across paths
func (p *Preparer) clientOptions() client.Options { return ClientOptions(p.cfg) }

// ClientOptions converts scanner configuration into connection settings. Snapshot capture and
// full scans share it so timeouts and private-network policy cannot drift between commands.
func ClientOptions(cfg config.Config) client.Options {
	return client.Options{
		Timeout:              cfg.Timeout.Std(),
		AllowPrivateNetworks: cfg.AllowPrivateNetworks,
		ReadResources:        cfg.ReadResources,
		GetPrompts:           cfg.GetPrompts,
		// The session and scanner must enforce the same tool-call policy
		Probes:           probeLevel(cfg),
		AllowedToolCalls: cfg.AllowToolCalls,
	}
}

// probeLevel keeps probe policy consistent between the scanner and connection layer
func probeLevel(cfg config.Config) analyzer.ProbeLevel {
	if cfg.ActiveProbes == "" {
		return analyzer.ProbeSafe
	}
	return analyzer.ProbeLevel(cfg.ActiveProbes)
}

func (p *Preparer) Prepare(ctx context.Context, target model.Target) (*analyzer.AnalysisContext, func(), error) {
	var ac *analyzer.AnalysisContext
	var cleanup func()

	// Sandbox-only stdio targets must never reach the live connection layer
	if p.noLaunch && target.Kind == model.TargetStdio {
		ac = &analyzer.AnalysisContext{}
		if p.snapshotPath != "" {
			data, err := ReadCapped(p.snapshotPath, MaxStaticSnapshotBytes)
			if err != nil {
				return nil, nil, fmt.Errorf("read snapshot %s: %w", p.snapshotPath, err)
			}
			snap, err := client.LoadSnapshotBytes(data, p.snapshotPath)
			if err != nil {
				return nil, nil, fmt.Errorf("read snapshot %s: %w", p.snapshotPath, err)
			}
			ac.Snapshot = snap
		}
		return p.finishContext(ac), func() {}, nil
	}

	switch target.Kind {
	case model.TargetRemote, model.TargetStdio:
		prep := client.NewPreparer(p.clientOptions())
		var err error
		ac, cleanup, err = prep.Prepare(ctx, target)
		if err != nil {
			return nil, cleanup, err
		}
		if ac == nil {
			ac = &analyzer.AnalysisContext{}
		}

	case model.TargetStatic:
		data, err := ReadCapped(target.Path, MaxStaticSnapshotBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("read static target %s: %w", target.Path, err)
		}
		// Use the shared loader rather than unmarshalling into the scanner shape. Some wire fields,
		// including inputSchema, do not share its JSON tags and would otherwise disappear silently.
		snap, err := client.LoadSnapshotBytes(data, target.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("parse static target %s as a snapshot: %w", target.Path, err)
		}
		ac = &analyzer.AnalysisContext{Snapshot: snap}

	case model.TargetPackage:
		// The caller creates target.Path; preparation downloads into it so failures
		// use the scanner's normal fail-closed path
		dest := target.Path
		if dest == "" {
			return nil, nil, fmt.Errorf("package target has no extraction directory set")
		}
		// Never delete caller-owned content. Package extraction requires an empty directory
		entries, err := os.ReadDir(dest)
		if err != nil {
			return nil, nil, fmt.Errorf("open package extraction directory %s: %w", dest, err)
		}
		if len(entries) > 0 {
			return nil, nil, fmt.Errorf("package extraction directory %s is not empty", dest)
		}
		cleanup = func() { os.RemoveAll(dest) }
		resolved, err := downloadPackage(ctx, target, dest)
		if err != nil {
			return nil, cleanup, err
		}
		ac = prepareSourceTree(ctx, dest)
		// Preserve the resolved version so OSV does not return unrelated advisories
		if resolved != "" {
			ac.Artifacts.Set(supplychain.ResolvedVersionKey, resolved)
		}

	case model.TargetSource:
		root, err := source.ResolveRoot(target.Path, "")
		if err != nil {
			return nil, nil, err
		}
		ac = prepareSourceTree(ctx, root)

	default:
		return nil, nil, fmt.Errorf("no preparer for target kind %q", target.Kind)
	}

	return p.finishContext(ac), cleanup, nil
}

// finishContext attaches target-independent analysis backends
func (p *Preparer) finishContext(ac *analyzer.AnalysisContext) *analyzer.AnalysisContext {
	ac.LLM = BuildLLMClient(p.cfg.LLM, p.cfg.Analyzers)
	if !p.noLaunch {
		// A dialer could run stdio targets on the host, so sandbox-only mode gets none
		ac.Dialer = client.NewDialer(p.clientOptions())
	}
	if p.cfg.Runtime.Enabled {
		// A nil executor makes the runtime analyzer report SKIPPED as "not enabled". Construction
		// errors are discarded here rather than exposed as UNAVAILABLE.
		if exec, err := NewRuntimeExecutor(p.cfg.Runtime); err == nil {
			ac.Runtime = exec
		}
	}
	return ac
}

// MaxStaticSnapshotBytes caps snapshots, baselines, and client configs that are read whole.
// It is a variable so tests can exercise the boundary without creating a 100 MiB fixture.
var MaxStaticSnapshotBytes int64 = 100 << 20

// ReadCapped reads a whole file and rejects content larger than max
func ReadCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("input file exceeds the %d byte limit", max)
	}
	return data, nil
}

// prepareSourceTree builds the shared graph and declared-surface snapshot once.
// Analyzers retry and report their own coverage if the build fails.
func prepareSourceTree(ctx context.Context, root string) *analyzer.AnalysisContext {
	ac := &analyzer.AnalysisContext{Artifacts: analyzer.NewArtifacts()}

	g, walkCov, err := source.Build(ctx, root)
	if err != nil || g == nil {
		return ac
	}
	// Consumers need walk coverage so unread files cannot appear clean
	source.Publish(ac.Artifacts, g, walkCov)

	// Keep empty snapshots so analyzers report missing registration coverage
	snap, snapCov := source.Synthesize(g)
	if snap != nil {
		ac.Snapshot = snap
		// Synthesis coverage distinguishes absent descriptions from unresolved ones
		ac.Artifacts.Set(source.SynthesizeCoverageKey, snapCov)
	}
	return ac
}

var _ scanner.Preparer = (*Preparer)(nil)

// downloadPackage extracts a package without running its scripts and returns
// the version selected by the registry
func downloadPackage(ctx context.Context, target model.Target, dest string) (resolved string, err error) {
	switch strings.ToLower(target.Ecosystem) {
	case "npm":
		_, resolved, err = npm.New().Download(ctx, target.Package, target.Version, dest)
		return resolved, err
	case "pypi":
		_, resolved, err = pypi.New().Download(ctx, target.Package, target.Version, dest)
		return resolved, err
	default:
		return "", fmt.Errorf("unsupported package ecosystem %q (want npm or pypi)", target.Ecosystem)
	}
}

func defaultAPIKeyEnv(provider string) string {
	switch provider {
	case "openai":
		return "OPENAI_API_KEY"
	case "bedrock":
		return "AWS_SECRET_ACCESS_KEY"
	default:
		return "ANTHROPIC_API_KEY"
	}
}

// Keep this literal aligned with internal/analyzers/llm.Analyzer.Name()
const llmAnalyzerName = "llm"

// The API builds one client per scan, but should warn only once per process
var llmOptInWarningOnce sync.Once

// BuildLLMClient returns nil until configuration or analyzer selection opts in.
// Environment credentials alone never enable billed calls. After opt-in, missing
// credentials return a client that makes the required analyzer fail explicitly.
func BuildLLMClient(cfg config.LLMConfig, selectedAnalyzers []string) analyzer.LLMClient {
	optedIn := cfg.Provider != "" || cfg.APIKeyEnv != "" || slices.Contains(selectedAnalyzers, llmAnalyzerName)
	if !optedIn {
		return nil
	}

	provider := strings.ToLower(cfg.Provider)
	if provider == "" {
		provider = "anthropic"
	}
	keyEnv := cfg.APIKeyEnv
	if keyEnv == "" {
		keyEnv = defaultAPIKeyEnv(provider)
	}
	missingKey := config.Secret(keyEnv) == ""
	if provider == "bedrock" {
		missingKey = missingKey || config.Secret("AWS_ACCESS_KEY_ID") == ""
	}
	if missingKey {
		return missingKeyClient{provider: provider, keyEnv: keyEnv}
	}

	base := llm.Config{
		Model: cfg.Model, BaseURL: cfg.BaseURL, APIKeyEnv: keyEnv,
		MaxTokens: cfg.MaxTokens, Timeout: cfg.Timeout.Std(),
		AllowInsecureEndpoint: cfg.AllowInsecureEndpoint,
	}
	var client analyzer.LLMClient
	switch provider {
	case "openai":
		client = openai.New(base)
	case "bedrock":
		client = bedrock.New(base)
	default:
		client = anthropic.New(base)
	}

	// Warn once before sending declared MCP data to a third party
	llmOptInWarningOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "warning: the declared MCP surface will be sent to %s (%s) for analysis\n", client.Name(), client.Model())
	})

	return client
}

// missingKeyClient turns an opted-in provider's missing credential into an error. Otherwise the
// LLM analyzer would see no client, excuse itself, and weaken an explicitly requested scan.
type missingKeyClient struct {
	provider string
	keyEnv   string
}

func (m missingKeyClient) Name() string  { return m.provider }
func (m missingKeyClient) Model() string { return "" }
func (m missingKeyClient) Capabilities() analyzer.ModelCapabilities {
	return analyzer.ModelCapabilities{}
}
func (m missingKeyClient) Complete(context.Context, analyzer.LLMRequest) (analyzer.LLMResponse, error) {
	return analyzer.LLMResponse{}, &llm.Error{
		Provider: m.provider,
		Kind:     llm.ErrAuth,
		Message:  fmt.Sprintf("%s is not set", m.keyEnv),
	}
}

// ScanOptions builds shared scanner options from configuration. The caller sets
// the target-specific root and build-time scanner version.
func ScanOptions(cfg config.Config) (scanner.Options, error) {
	blocking := model.DefaultBlockingSeverity
	if cfg.BlockingSeverity != "" {
		var err error
		blocking, err = model.ParseSeverity(cfg.BlockingSeverity)
		if err != nil {
			return scanner.Options{}, err
		}
	}
	probes := probeLevel(cfg)
	return scanner.Options{
		Analyzers:        cfg.Analyzers,
		BestEffort:       cfg.BestEffort,
		BlockingSeverity: blocking,
		Probes:           probes,
		AllowedToolCalls: cfg.AllowToolCalls,
		Timeout:          cfg.Timeout.Std(),
		AnalyzerTimeout:  cfg.AnalyzerTimeout.Std(),
		Concurrency:      cfg.Concurrency,
		Options:          AnalyzerOptions(cfg),
	}, nil
}

// AnalyzerOptions builds each analyzer's option map. Generic analyzer_options
// override values from typed sections.
func AnalyzerOptions(cfg config.Config) map[string]map[string]any {
	out := map[string]map[string]any{}
	// Analyzers read typed rule directories through the generic option map
	if cfg.Rules.PromptDefenseDir != "" {
		out["promptdefense"] = map[string]any{"rules_dir": cfg.Rules.PromptDefenseDir}
	}
	if cfg.Rules.YARADir != "" {
		out["yara"] = map[string]any{"rules_dir": cfg.Rules.YARADir}
	}
	if cfg.Cisco.Endpoint != "" || cfg.Cisco.APIKeyEnv != "" {
		m := map[string]any{}
		if cfg.Cisco.Endpoint != "" {
			m["endpoint"] = cfg.Cisco.Endpoint
		}
		if cfg.Cisco.APIKeyEnv != "" {
			m["api_key_env"] = cfg.Cisco.APIKeyEnv
		}
		if cfg.Cisco.Timeout > 0 {
			m["timeout"] = cfg.Cisco.Timeout.Std()
		}
		out["cisco"] = m
	}
	if cfg.VT.APIKeyEnv != "" || cfg.VT.AllowUpload {
		m := map[string]any{"allow_upload": cfg.VT.AllowUpload}
		if cfg.VT.APIKeyEnv != "" {
			m["api_key_env"] = cfg.VT.APIKeyEnv
		}
		if cfg.VT.Timeout > 0 {
			m["timeout"] = cfg.VT.Timeout.Std()
		}
		out["virustotal"] = m
	}
	for name, opts := range cfg.AnalyzerOptions {
		if out[name] == nil {
			out[name] = map[string]any{}
		}
		maps.Copy(out[name], opts)
	}
	return out
}
