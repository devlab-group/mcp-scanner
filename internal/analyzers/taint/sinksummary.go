package taint

import (
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Sink summaries: whether a project function hands what a call passes it to a sink, read by
// walking its body once with the call's taint, silently - no findings are emitted and no further
// call is followed, as for a return summary. A call that matched a library sink by its name but
// is the project's own method (factoryInstanceMethod) keeps its finding at the call when the
// method's body reaches a sink of the same kind: backend.write_text(key, text) whose body joins
// key to a root and writes the file is the file write it looked like.

// sinkHit is a sink a summary walk reached
type sinkHit struct {
	category string
	severity model.Severity
	callee   string
	info     taintInfo
	file     string
	line     int
}

// sinkSummary walks sym's body seeded with seed and returns the first sink of category it
// reaches. It is not run inside another summary walk.
func (c *ctx) sinkSummary(sym *graph.Symbol, seed map[string]taintInfo, category string) (sinkHit, bool) {
	if sym == nil || len(seed) == 0 || c.summaryDepth > 0 {
		return sinkHit{}, false
	}
	params := make([]string, 0, len(seed))
	for p := range seed {
		params = append(params, p)
	}
	sort.Strings(params)
	key := string(sym.ID) + "|" + category + "|" + strings.Join(params, ",")
	if v, ok := c.sinkSummaries[key]; ok {
		if v == nil {
			return sinkHit{}, false
		}
		return *v, true
	}
	if c.sinkSummaries == nil {
		c.sinkSummaries = map[string]*sinkHit{}
	}
	c.sinkSummaries[key] = nil
	pf, def := c.defNodeFor(sym)
	if pf == nil || def == nil {
		return sinkHit{}, false
	}
	body := def.ChildByFieldName("body")
	if body == nil {
		return sinkHit{}, false
	}
	tainted := make(map[string]taintInfo, len(seed))
	for k, v := range seed {
		tainted[k] = v
	}
	prevHits := c.sinkHits
	var hits []sinkHit
	c.sinkHits = &hits
	c.summaryDepth++
	c.walk(pf, sym.File, tainted, body, 0, false)
	c.summaryDepth--
	c.sinkHits = prevHits
	for _, h := range hits {
		if h.category == category {
			c.sinkSummaries[key] = &h
			return h, true
		}
	}
	return sinkHit{}, false
}
