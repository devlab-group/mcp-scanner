// Package analyzer defines the contract every security analyzer implements.
//
// The contract is deliberately narrow: an analyzer is handed a target and a
// read-mostly context, and must return a result that states what it managed to
// do. There is no way to signal success by omission.
package analyzer

import (
	"context"
	"log/slog"
	"sync"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Analyzer inspects a target and reports findings.
//
// Implementations must not panic; the scanner recovers panics and turns them
// into an ERROR result, but a panic loses the coverage accounting.
type Analyzer interface {
	// Name is the stable identifier used in results, config and policy
	Name() string

	// Analyze runs the check. It must honour ctx cancellation and must always
	// return a result with a non-empty Status.
	Analyze(ctx context.Context, target model.Target, ac *AnalysisContext) model.AnalyzerResult
}

// Applicable is implemented by analyzers that only make sense for some target
// kinds. An analyzer that does not implement it runs for every target.
type Applicable interface {
	AppliesTo(kind model.TargetKind) bool
}

// Describer lets an analyzer document itself for `mcp-scanner analyzers`
type Describer interface {
	Describe() Description
}

// Description is the self-documentation every analyzer should provide:
// what it detects, how strong its evidence is, and where it is blind
type Description struct {
	Name        string                `json:"name"`
	Purpose     string                `json:"purpose"`
	Threats     []string              `json:"threats,omitempty"`
	Evidence    []model.EvidenceLevel `json:"evidence_levels,omitempty"`
	Active      bool                  `json:"active"` // true if it sends anything the target can observe as a probe
	Limitations []string              `json:"limitations,omitempty"`
	// RequiresNetwork, RequiresDocker and RequiresCredentials let the CLI
	// explain why an analyzer is unavailable instead of silently skipping it
	RequiresNetwork     bool `json:"requires_network,omitempty"`
	RequiresDocker      bool `json:"requires_docker,omitempty"`
	RequiresCredentials bool `json:"requires_credentials,omitempty"`
}

// ProbeLevel controls how much the scanner is allowed to poke at a live target
type ProbeLevel string

const (
	// ProbeNone: connect and read declarations only
	ProbeNone ProbeLevel = "none"
	// ProbeSafe: additionally send malformed or unsupported protocol messages
	// that a correct server must reject without side effects
	ProbeSafe ProbeLevel = "safe"
	// ProbeToolCalls: additionally invoke explicitly allowlisted tools
	ProbeToolCalls ProbeLevel = "tool-calls"
)

func (p ProbeLevel) Valid() bool {
	switch p {
	case ProbeNone, ProbeSafe, ProbeToolCalls:
		return true
	}
	return false
}

// AtLeast reports whether the configured level permits the requested level
func (p ProbeLevel) AtLeast(want ProbeLevel) bool {
	rank := map[ProbeLevel]int{ProbeNone: 0, ProbeSafe: 1, ProbeToolCalls: 2}
	return rank[p] >= rank[want]
}

// AnalysisContext carries shared scan state. Each analyzer receives a shallow copy, so Options,
// Session, Artifacts, and Snapshot still point at values used concurrently by other analyzers.
// Treat them as read-only; only Artifacts may be mutated because it provides its own locking.
// Writing Options or mutating Snapshot is a data race, not a compile-time error.
type AnalysisContext struct {
	// Log is scoped to the running analyzer
	Log *slog.Logger

	// Root is the filesystem boundary for the scan. Analyzers must not read
	// outside it.
	Root string

	// Snapshot is the discovered MCP surface. Nil for source-only scans
	Snapshot *model.Snapshot

	// Session gives protocol-level analyzers access to the live connection.
	// Nil for offline scans.
	Session Session

	// Dialer opens additional sessions. Auth and session checks need to
	// reconnect with different credentials. Nil for offline scans.
	Dialer Dialer

	// AllowPrivateNetworks mirrors the scan's --allow-private-networks setting for an analyzer
	// that opens its own outbound connection rather than going through Session or Dialer
	AllowPrivateNetworks bool

	// Probes is the active-probe policy for this scan
	Probes ProbeLevel

	// AllowedToolCalls lists the tools that may actually be invoked. Empty
	// means none, regardless of Probes.
	AllowedToolCalls []string

	// Runtime executes payloads in a sandbox. Nil when runtime confirmation
	// is not enabled or not available.
	Runtime RuntimeExecutor

	// LLM is the optional semantic-analysis backend
	LLM LLMClient

	// Options holds per-analyzer settings, keyed by analyzer name. Shared
	// across concurrently running analyzers and read-only to all of them;
	// read it through Option rather than reaching into the map.
	Options map[string]map[string]any

	// Artifacts is the hand-off between analyzers, for example the source
	// graph produced by the inventory pass and consumed by taint analysis
	Artifacts *Artifacts
}

// ToolCallAllowed reports whether invoking the named tool is permitted
func (ac *AnalysisContext) ToolCallAllowed(name string) bool {
	if ac == nil {
		return false
	}
	return ToolCallAllowed(ac.Probes, ac.AllowedToolCalls, name)
}

// ToolCallAllowed is the rule behind AnalysisContext.ToolCallAllowed,
// exported so a session built outside an AnalysisContext (internal/mcp/client
// dials sessions from its own Options, not from one) can enforce the same
// allowlist rather than trusting a caller's own check
func ToolCallAllowed(probes ProbeLevel, allowedToolCalls []string, name string) bool {
	if !probes.AtLeast(ProbeToolCalls) {
		return false
	}
	for _, allowed := range allowedToolCalls {
		if allowed == name || allowed == "*" {
			return true
		}
	}
	return false
}

// Option returns a setting for the named analyzer
func (ac *AnalysisContext) Option(analyzer, key string) (any, bool) {
	if ac == nil || ac.Options == nil {
		return nil, false
	}
	v, ok := ac.Options[analyzer][key]
	return v, ok
}

// Artifacts is a concurrency-safe hand-off between analyzers
type Artifacts struct {
	mu sync.RWMutex
	m  map[string]any
}

func NewArtifacts() *Artifacts { return &Artifacts{m: map[string]any{}} }

func (a *Artifacts) Set(key string, v any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[string]any{}
	}
	a.m[key] = v
}

func (a *Artifacts) Get(key string) (any, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	v, ok := a.m[key]
	return v, ok
}

// Get is the typed accessor. It returns the zero value when the artifact is
// absent or has a different type.
func Get[T any](a *Artifacts, key string) (T, bool) {
	var zero T
	if a == nil {
		return zero, false
	}
	v, ok := a.Get(key)
	if !ok {
		return zero, false
	}
	t, ok := v.(T)
	if !ok {
		return zero, false
	}
	return t, true
}
