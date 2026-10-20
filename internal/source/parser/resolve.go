package parser

import (
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
)

// Resolve matches a call's final identifier without receiver-type information. A unique candidate
// wins; among several, one same-file definition wins. Other ambiguous calls stay unresolved.
func Resolve(g *graph.Graph) {
	byName := map[string][]graph.SymbolID{}
	for id, sym := range g.Symbols {
		byName[sym.Name] = append(byName[sym.Name], id)
	}

	for i := range g.Calls {
		c := &g.Calls[i]
		if c.Resolved {
			continue
		}
		candidates := byName[LastSegment(c.CalleeText)]
		switch len(candidates) {
		case 0:
			continue
		case 1:
			c.Callee, c.Resolved = candidates[0], true
			continue
		}
		// Ambiguous by name alone: prefer the one candidate defined in the
		// same file as the call site, if there is exactly one
		var sameFile graph.SymbolID
		n := 0
		for _, cand := range candidates {
			if g.Symbols[cand].File == c.File {
				sameFile = cand
				n++
			}
		}
		if n == 1 {
			c.Callee, c.Resolved = sameFile, true
		}
	}
}
