package analyzer

import (
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Registry holds analyzers registered by imported packages in this build
type Registry struct {
	mu sync.RWMutex
	m  map[string]Analyzer
}

// Default is the process-wide registry
var Default = NewRegistry()

func NewRegistry() *Registry { return &Registry{m: map[string]Analyzer{}} }

// Register adds an analyzer. Empty or duplicate names panic because they are
// initialization errors that would make results ambiguous.
func (r *Registry) Register(a Analyzer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := a.Name()
	if name == "" {
		panic("analyzer registered with an empty name")
	}
	if _, dup := r.m[name]; dup {
		panic("analyzer registered twice: " + name)
	}
	r.m[name] = a
}

// Register adds an analyzer to the default registry
func Register(a Analyzer) { Default.Register(a) }

func (r *Registry) Get(name string) (Analyzer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.m[name]
	return a, ok
}

// Names lists registered analyzers in name order
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := slices.Sorted(maps.Keys(r.m))
	return names
}

// All returns registered analyzers in name order
func (r *Registry) All() []Analyzer {
	names := r.Names()
	out := make([]Analyzer, 0, len(names))
	for _, n := range names {
		a, _ := r.Get(n)
		out = append(out, a)
	}
	return out
}

// Select resolves the requested analyzer names for a target kind.
//
// Unknown names are errors so CI cannot silently omit a requested analyzer.
func (r *Registry) Select(names []string, kind model.TargetKind) ([]Analyzer, error) {
	var out []Analyzer
	var unknown []string
	for _, n := range names {
		a, ok := r.Get(n)
		if !ok {
			unknown = append(unknown, n)
			continue
		}
		out = append(out, a)
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown analyzer(s): %v (available: %v)", unknown, r.Names())
	}
	return out, nil
}

// Applicables separates analyzers that support kind from those that do not
func Applicables(as []Analyzer, kind model.TargetKind) (run, skip []Analyzer) {
	for _, a := range as {
		if app, ok := a.(Applicable); ok && !app.AppliesTo(kind) {
			skip = append(skip, a)
			continue
		}
		run = append(run, a)
	}
	return run, skip
}
