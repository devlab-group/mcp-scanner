// Package scanner runs analyzers against a target and turns their results
// into a single verdict. It is the shared service layer behind both the CLI
// and the HTTP API, so the two can never disagree about what a scan means.
package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Options configures one scan
type Options struct {
	// Analyzers to run. Empty means every registered analyzer that applies to
	// the target kind.
	Analyzers []string

	// BestEffort lists analyzers whose failure must not block the verdict.
	// Everything else is required: enabling an analyzer means you want its
	// answer, and not getting it is a reason to say UNKNOWN.
	BestEffort []string

	// Required names analyzers that are required whatever they return, without narrowing the
	// selection to them. BestEffort takes precedence when an analyzer appears in both lists.
	Required []string

	// BlockingSeverity is the lowest severity that turns a completed scan
	// UNSAFE
	BlockingSeverity model.Severity

	Probes           analyzer.ProbeLevel
	AllowedToolCalls []string

	// Timeout bounds the whole scan; AnalyzerTimeout bounds each analyzer
	Timeout         time.Duration
	AnalyzerTimeout time.Duration

	// Concurrency caps analyzers running at once. Zero and one both mean
	// serial. The command line defaults it to 4; a scan against a live
	// server that cannot take the parallelism should lower it.
	Concurrency int

	// Root is the filesystem boundary analyzers must stay inside
	Root string

	Options map[string]map[string]any

	// Baseline maps accepted finding IDs to the reason they were accepted.
	// Applied before the verdict is computed, so the verdict, the exit code
	// and every serialized copy of a finding agree about what was suppressed.
	Baseline map[string]string

	ScannerVersion string
}

// DiscoveryFailedPrefix starts per-analyzer Scan errors when target preparation fails. API
// frontends use it to recognize messages that may contain host or caller-supplied paths.
const DiscoveryFailedPrefix = "target discovery failed:"

func (o *Options) defaults() {
	if !o.BlockingSeverity.Valid() {
		o.BlockingSeverity = model.DefaultBlockingSeverity
	}
	if !o.Probes.Valid() {
		o.Probes = analyzer.ProbeSafe
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Minute
	}
	if o.AnalyzerTimeout <= 0 {
		o.AnalyzerTimeout = 2 * time.Minute
	}
	if o.Concurrency < 1 {
		o.Concurrency = 1
	}
}

// Preparer builds the live connection and discovery snapshot for a target.
// The scanner does not know how to speak MCP; it is handed an implementation.
type Preparer interface {
	Prepare(ctx context.Context, target model.Target) (*analyzer.AnalysisContext, func(), error)
}

// Scanner runs scans
type Scanner struct {
	registry *analyzer.Registry
	prepare  Preparer
	log      *slog.Logger
}

// New builds a scanner. A nil registry uses the default one, a nil preparer
// means offline scans only, and a nil logger discards output.
func New(reg *analyzer.Registry, prep Preparer, log *slog.Logger) *Scanner {
	if reg == nil {
		reg = analyzer.Default
	}
	if log == nil {
		log = slog.New(discardHandler{})
	}
	return &Scanner{registry: reg, prepare: prep, log: log}
}

// Scan runs the configured analyzers against one target.
//
// Every failure path here produces a result, never a bare error: a scan that
// could not run is a security answer of its own (UNKNOWN) and callers must see
// it in the report rather than as a message on stderr.
func (s *Scanner) Scan(ctx context.Context, target model.Target, opts Options) (*model.ScanResult, error) {
	opts.defaults()

	scanID, err := newScanID()
	if err != nil {
		return nil, fmt.Errorf("generate scan id: %w", err)
	}

	res := &model.ScanResult{
		SchemaVersion:  model.SchemaVersion,
		ScanID:         scanID,
		ScannerVersion: opts.ScannerVersion,
		Target:         target,
		StartedAt:      time.Now().UTC(),
	}
	finish := func() *model.ScanResult {
		res.FinishedAt = time.Now().UTC()
		res.Duration = res.FinishedAt.Sub(res.StartedAt)
		res.Aggregate(opts.BlockingSeverity)
		return res
	}

	if err := target.Validate(); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	// Built once, up front, so every return path below marks Required the same way. An analyzer
	// the operator named is required even if it turns out it cannot run: asking for it and not
	// getting it is a reason to say UNKNOWN.
	bestEffort := map[string]bool{}
	for _, n := range opts.BestEffort {
		bestEffort[n] = true
	}
	named := map[string]bool{}
	for _, n := range opts.Analyzers {
		named[n] = true
	}
	for _, n := range opts.Required {
		named[n] = true
	}

	selected, inapplicable, err := s.resolve(opts.Analyzers, target.Kind)
	if err != nil {
		return nil, err
	}
	// Recorded whether or not anything else runs, so the reason an analyzer
	// produced nothing is in the report rather than absent from it
	notApplicable := make([]model.AnalyzerResult, 0, len(inapplicable))
	for _, a := range inapplicable {
		notApplicable = append(notApplicable, model.Skipped(a.Name(),
			fmt.Sprintf("this analyzer does not apply to a %s target", target.Kind)))
	}
	if len(selected) == 0 {
		res.Analyzers = notApplicable
		assignRequired(res.Analyzers, named, bestEffort)
		res.Warnings = append(res.Warnings, "no analyzer applies to this target kind")
		return finish(), nil
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	ac := &analyzer.AnalysisContext{
		Log:              s.log,
		Root:             opts.Root,
		Probes:           opts.Probes,
		AllowedToolCalls: opts.AllowedToolCalls,
		Options:          opts.Options,
		Artifacts:        analyzer.NewArtifacts(),
	}

	if s.prepare != nil {
		prepared, cleanup, err := s.prepare.Prepare(ctx, target)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			// Discovery failed. Every analyzer that needed the connection is reported as failed, so
			// this can never read as a clean scan.
			for _, a := range selected {
				res.Analyzers = append(res.Analyzers,
					model.Errorf(a.Name(), "network", DiscoveryFailedPrefix+" %v", err))
			}
			res.Analyzers = append(res.Analyzers, notApplicable...)
			assignRequired(res.Analyzers, named, bestEffort)
			return finish(), nil
		}
		if prepared != nil {
			prepared.Log = s.log
			prepared.Root = opts.Root
			prepared.Probes = opts.Probes
			prepared.AllowedToolCalls = opts.AllowedToolCalls
			if prepared.Options == nil {
				prepared.Options = opts.Options
			}
			if prepared.Artifacts == nil {
				prepared.Artifacts = analyzer.NewArtifacts()
			}
			ac = prepared
		}
		res.Snapshot = ac.Snapshot
	}

	results := append(s.run(ctx, selected, target, ac, opts), notApplicable...)
	assignRequired(results, named, bestEffort)
	// Suppression is applied to the analyzers' own findings, before those
	// are copied up and the verdict is decided. Marking only the top-level
	// copy afterwards left three readers of the same report disagreeing: a
	// verdict naming an accepted finding, an exit code saying pass, and an
	// unsuppressed duplicate under the analyzer that produced it.
	applyBaseline(results, opts.Baseline, model.FingerprintScope(target))
	res.Analyzers = results

	return finish(), nil
}

// resolve splits the selection into the analyzers that apply to this target kind and the
// ones that do not. The inapplicable half is returned so an analyzer the operator explicitly
// requested cannot disappear from the result and leave a clean-looking omission.
func (s *Scanner) resolve(names []string, kind model.TargetKind) (run, skip []analyzer.Analyzer, err error) {
	var candidates []analyzer.Analyzer
	if len(names) == 0 {
		candidates = s.registry.All()
	} else {
		candidates, err = s.registry.Select(names, kind)
		if err != nil {
			return nil, nil, err
		}
	}
	run, skip = analyzer.Applicables(candidates, kind)
	return run, skip, nil
}

func (s *Scanner) run(ctx context.Context, as []analyzer.Analyzer, target model.Target, ac *analyzer.AnalysisContext, opts Options) []model.AnalyzerResult {
	out := make([]model.AnalyzerResult, len(as))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for i, a := range as {
		wg.Add(1)
		go func(i int, a analyzer.Analyzer) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = s.runOne(ctx, a, target, ac, opts.AnalyzerTimeout)
		}(i, a)
	}
	wg.Wait()
	return out
}

// runOne isolates a single analyzer: it gets its own timeout, its own logger,
// and its panics become an ERROR result instead of taking the scan down
func (s *Scanner) runOne(ctx context.Context, a analyzer.Analyzer, target model.Target, ac *analyzer.AnalysisContext, timeout time.Duration) (res model.AnalyzerResult) {
	name := a.Name()
	started := time.Now().UTC()

	defer func() {
		if r := recover(); r != nil {
			s.log.Error("analyzer panicked", "analyzer", name, "panic", r, "stack", string(debug.Stack()))
			res = model.Errorf(name, "internal", "analyzer panicked: %v", r)
		}
		res.Analyzer = name
		if res.Status == "" {
			res.Status = model.AnalyzerFailed
			res.Errors = append(res.Errors, model.AnalyzerError{
				Kind:    "internal",
				Message: "analyzer returned no status",
				Fatal:   true,
			})
		}
		scope := model.FingerprintScope(target)
		for i := range res.Findings {
			res.Findings[i].Analyzer = name
			res.Findings[i].EnsureID(scope)
		}
		res.StartedAt = started
		res.FinishedAt = time.Now().UTC()
		res.Duration = res.FinishedAt.Sub(started)
	}()

	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	scoped := *ac
	scoped.Log = s.log.With("analyzer", name)

	res = a.Analyze(actx, target, &scoped)

	// An analyzer that swallowed a cancellation and reported success would
	// hide an incomplete scan, so the deadline overrides its own opinion.
	// Excusing itself is the same swallowing: an analyzer cut off by the
	// deadline did not decide the analysis was unnecessary, so SKIPPED and
	// UNAVAILABLE are overridden too, or the deadline excuses itself.
	if actx.Err() != nil && (res.Status == model.AnalyzerCompleted || selfExcused(res.Status)) {
		res.Status = model.AnalyzerPartial
		res.Warnings = append(res.Warnings, "analyzer deadline reached before it finished")
	}
	return res
}

// selfExcused reports whether an analyzer opted out rather than failed.
// A failure is never excused: only SKIPPED and UNAVAILABLE are, and both
// carry a reason.
func selfExcused(st model.AnalyzerStatus) bool {
	return st == model.AnalyzerSkipped || st == model.AnalyzerUnavailable
}

// assignRequired uses one rule on every Scan return path. BestEffort wins over an explicit
// selection; otherwise named analyzers are required, while default-selected SKIPPED or
// UNAVAILABLE analyzers excuse themselves.
func assignRequired(results []model.AnalyzerResult, named, bestEffort map[string]bool) {
	for i := range results {
		r := &results[i]
		switch {
		case bestEffort[r.Analyzer]:
			r.Required = false
		case named[r.Analyzer]:
			r.Required = true
		default:
			r.Required = !selfExcused(r.Status)
		}
	}
}

// applyBaseline marks accepted findings on the analyzer results themselves
func applyBaseline(results []model.AnalyzerResult, baseline map[string]string, scope string) {
	if len(baseline) == 0 {
		return
	}
	for i := range results {
		for j := range results[i].Findings {
			f := &results[i].Findings[j]
			f.EnsureID(scope)
			if reason, ok := baseline[f.ID]; ok {
				f.Suppressed = true
				// SuppressionReason is omitempty, so an empty reason would serialize as if none were
				// recorded, which is the part that makes a baseline reviewable months later
				if strings.TrimSpace(reason) == "" {
					reason = "accepted by baseline with no reason recorded"
				}
				f.SuppressionReason = reason
			}
		}
	}
}

// randRead is crypto/rand.Read, indirected so tests can return an error. Go 1.26 does not return
// entropy-source errors here, but newScanID still propagates an injected error and never falls back
// to a predictable identifier.
var randRead = rand.Read

// newScanID returns a random scan identifier. It refuses rather than
// falling back to a predictable one: a scan id derived from the clock
// instead of entropy is a weaker identifier than the random one it would
// replace.
func newScanID() (string, error) {
	var b [8]byte
	if _, err := randRead(b[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return "scan_" + hex.EncodeToString(b[:]), nil
}

type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h discardHandler) WithGroup(string) slog.Handler           { return h }
