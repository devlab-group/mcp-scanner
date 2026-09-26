package main

import (
	"fmt"
	"maps"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/revinand/mcp-scanner/internal/app"
	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/policy"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/scanner"
)

// scanVersion is set at build time with -ldflags and written to every report
var scanVersion = "dev"

// commonFlags holds persistent scan flags
type commonFlags struct {
	format        string
	output        string
	failOn        string
	analyzers     []string
	bestEffort    []string
	configPath    string
	activeProbes  string
	allowToolCall []string
	timeout       time.Duration
	concurrency   int
	baseline      string

	allowPrivateNetworks bool
	readResources        bool
	getPrompts           bool
}

func (f *commonFlags) register(fs flagSet) {
	fs.StringVar(&f.format, "format", "summary", "output format: summary|table|json|sarif")
	fs.StringVar(&f.output, "output", "", "write the report to a file")
	fs.StringVar(&f.failOn, "fail-on", "", "lowest severity that fails the run (exit 2): low|medium|high|critical|none (default high)")
	fs.StringSliceVar(&f.analyzers, "analyzers", nil, "analyzers to run (default: every applicable analyzer in the build)")
	fs.StringSliceVar(&f.bestEffort, "best-effort", nil, "analyzers whose failure must not block the verdict")
	fs.StringVar(&f.configPath, "config", "", "path to a scanner config file")
	fs.StringVar(&f.activeProbes, "active-probes", "", "live probe level: none|safe|tool-calls (default safe)")
	fs.StringSliceVar(&f.allowToolCall, "allow-tool-call", nil, "tool name allowed to be invoked at --active-probes=tool-calls (repeatable, or \"*\")")
	fs.DurationVar(&f.timeout, "timeout", 0, "maximum scan duration")
	fs.IntVar(&f.concurrency, "concurrency", 0, "analyzers to run at once")
	fs.StringVar(&f.baseline, "baseline", "", "path to a YAML file of accepted finding IDs (id: reason)")
	fs.BoolVar(&f.allowPrivateNetworks, "allow-private-networks", false, "let the scanner connect to loopback, link-local and private addresses")
	fs.BoolVar(&f.readResources, "read-resources", false, "fetch and analyze resource contents")
	fs.BoolVar(&f.getPrompts, "get-prompts", false, "render and analyze declared prompts")
}

// flagSet is the testable subset of pflag used by register
type flagSet interface {
	StringVar(p *string, name string, value string, usage string)
	StringSliceVar(p *[]string, name string, value []string, usage string)
	DurationVar(p *time.Duration, name string, value time.Duration, usage string)
	IntVar(p *int, name string, value int, usage string)
	BoolVar(p *bool, name string, value bool, usage string)
}

// resolved contains the settings needed to scan and report
type resolved struct {
	cfg    config.Config
	sopts  scanner.Options
	pol    policy.Policy
	format string
	output string
}

// resolve merges defaults, config, and flags in ascending precedence
func resolve(f *commonFlags) (resolved, error) {
	cfg, err := config.Load(f.configPath)
	if err != nil {
		return resolved{}, err
	}

	if len(f.analyzers) > 0 {
		cfg.Analyzers = f.analyzers
	}
	if len(f.bestEffort) > 0 {
		cfg.BestEffort = f.bestEffort
	}
	// Validate best-effort names instead of silently leaving misspellings required
	if len(cfg.BestEffort) > 0 {
		if _, err := analyzer.Default.Select(cfg.BestEffort, ""); err != nil {
			return resolved{}, fmt.Errorf("--best-effort: %w", err)
		}
	}
	if f.allowPrivateNetworks {
		cfg.AllowPrivateNetworks = true
	}
	if cfg.AllowPrivateNetworks {
		// Make the disabled network guard visible in the transcript
		fmt.Fprintln(os.Stderr, "warning: private and loopback destinations are allowed for this scan")
	}
	if f.failOn != "" {
		cfg.FailOn = f.failOn
	}
	if f.activeProbes != "" {
		cfg.ActiveProbes = f.activeProbes
	}
	if len(f.allowToolCall) > 0 {
		cfg.AllowToolCalls = f.allowToolCall
	}
	if f.timeout > 0 {
		cfg.Timeout = config.Duration(f.timeout)
	}
	if f.concurrency > 0 {
		cfg.Concurrency = f.concurrency
	}
	if f.readResources {
		cfg.ReadResources = true
	}
	if f.getPrompts {
		cfg.GetPrompts = true
	}
	// Merge every flag before the shared CLI/API validation
	if err := cfg.Validate(); err != nil {
		return resolved{}, err
	}

	sopts, err := app.ScanOptions(cfg)
	if err != nil {
		return resolved{}, err
	}
	sopts.ScannerVersion = scanVersion

	pol := policy.Default()
	// Incomplete scans fail unless explicitly tolerated
	if cfg.TolerateUnknown {
		pol.FailOnUnknown = false
	}
	if cfg.FailOn != "" {
		pol.FailOn, err = policy.ParseFailOn(cfg.FailOn)
		if err != nil {
			return resolved{}, err
		}
	}
	pol.Baseline = cfg.Baseline
	if f.baseline != "" {
		fileBaseline, err := loadBaseline(f.baseline)
		if err != nil {
			return resolved{}, err
		}
		if pol.Baseline == nil {
			pol.Baseline = map[string]string{}
		}
		maps.Copy(pol.Baseline, fileBaseline)
	}

	// Apply one baseline to both verdict and policy
	sopts.Baseline = pol.Baseline

	format := f.format
	if format == "" {
		format = "summary"
	}
	switch format {
	case "summary", "table", "json", "sarif":
	default:
		return resolved{}, fmt.Errorf("unknown --format %q (want summary, table, json or sarif)", format)
	}

	return resolved{cfg: cfg, sopts: sopts, pol: pol, format: format, output: f.output}, nil
}

func loadBaseline(path string) (map[string]string, error) {
	data, err := app.ReadCapped(path, app.MaxStaticSnapshotBytes)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var out map[string]string
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if err := config.ValidateBaseline(out); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	return out, nil
}
