package runtime

import (
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// candidate is one tool this analyzer considers sandboxing, scored so the
// runs most likely to confirm something real happen first
type candidate struct {
	tool     model.ToolInfo
	priority int
	reasons  []string
}

// keywordScores prioritize name, description, and schema-property words. Each class contributes
// its weight at most once.
var keywordScores = []struct {
	weight int
	class  string
	words  []string
}{
	{3, "command execution", []string{"cmd", "command", "exec", "shell", "run", "script", "eval"}},
	{2, "file path handling", []string{"path", "file", "dir", "directory", "folder"}},
	{2, "outbound network requests", []string{"url", "uri", "fetch", "request", "http", "download", "webhook", "proxy"}},
}

// discoverCandidates builds the tool list from the prepared snapshot. For runtime stdio, the
// snapshot comes from live discovery or --snapshot.
func discoverCandidates(ac *analyzer.AnalysisContext) []candidate {
	byName := map[string]*candidate{}
	order := []string{}
	add := func(t model.ToolInfo) *candidate {
		if c, ok := byName[t.Name]; ok {
			return c
		}
		c := &candidate{tool: t}
		byName[t.Name] = c
		order = append(order, t.Name)
		return c
	}

	if ac.Snapshot != nil {
		for _, t := range ac.Snapshot.Tools {
			add(t)
		}
	}

	out := make([]candidate, 0, len(order))
	for _, name := range order {
		c := byName[name]
		w, reasons := keywordScore(c.tool)
		c.priority += w
		c.reasons = append(c.reasons, reasons...)
		out = append(out, *c)
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].priority > out[j].priority })
	return out
}

func keywordScore(tool model.ToolInfo) (int, []string) {
	text := strings.ToLower(tool.Name + " " + tool.Title + " " + tool.Description + " " + schemaPropertyNames(tool.InputSchema))
	score := 0
	var reasons []string
	for _, ks := range keywordScores {
		for _, w := range ks.words {
			if strings.Contains(text, w) {
				score += ks.weight
				reasons = append(reasons, "name/description/schema suggests "+ks.class)
				break
			}
		}
	}
	return score, reasons
}

func schemaPropertyNames(schema map[string]any) string {
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return ""
	}
	return strings.Join(slices.Sorted(maps.Keys(props)), " ")
}
