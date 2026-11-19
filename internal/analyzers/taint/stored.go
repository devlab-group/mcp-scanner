package taint

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Deferred execution: one call stores the caller's value in module state and a later one uses it.
//
//	TASKS[name] = command                 # add_task, a tool
//	for cmd in TASKS.values(): subprocess.run(cmd, shell=True)   # scheduler, run later
//
// The walk of a handler leaves the module-level container tainted; storedSeed hands that taint to
// the functions that read the container - another tool, a scheduler loop - so the flow through the
// shared state is traced. Only containers count (a dict, list, set, Map or array literal at the top
// level of the file): a module object such as config or a logger is not followed this way.

// moduleContainerDecl matches a top-level container declaration in Python, JavaScript, TypeScript
// or Go
var moduleContainerDecl = regexp.MustCompile(`(?m)^(?:export\s+)?(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=\s*(?:\{|\[|dict\(|list\(|set\(|defaultdict\(|deque\(|OrderedDict\(|new\s+(?:Map|Set|Array)\b|map\[|make\(\s*(?:map|\[\]))`)

type storeKey struct {
	file, name string
}

// moduleContainers are the names of file's top-level containers
func (c *ctx) moduleContainers(file string) map[string]bool {
	if m, ok := c.containers[file]; ok {
		return m
	}
	m := map[string]bool{}
	if data, err := os.ReadFile(filepath.Join(c.g.Root, file)); err == nil {
		for _, sm := range moduleContainerDecl.FindAllStringSubmatch(string(data), -1) {
			m[sm[1]] = true
		}
	}
	c.containers[file] = m
	return m
}

// recordStored keeps, after a walk seeded with MCP input, the taint the walk left on the file's
// module-level containers. The first store of a container wins, so the result does not depend on
// which later walk reaches it.
func (c *ctx) recordStored(sym *graph.Symbol, seed, tainted map[string]taintInfo) {
	if len(seed) == 0 {
		return
	}
	containers := c.moduleContainers(sym.File)
	for name, info := range tainted {
		if !containers[name] || len(info.chain) == 0 || sourceClass(info.chain[0].Detail) != sourceMCPInput {
			continue
		}
		if _, isSeed := seed[name]; isSeed {
			continue
		}
		k := storeKey{sym.File, name}
		if _, have := c.stored[k]; !have {
			c.stored[k] = info.extend(model.FlowStep{
				Kind: "transform", Symbol: name, File: sym.File, Line: sym.Line, Resolved: true,
				Detail: "stored in module state " + name + " by " + sym.Name,
			}, 1)
		}
	}
}

// storedSeed is the stored taint of the containers of sym's file that sym's body reads, or nil
func (c *ctx) storedSeed(sym *graph.Symbol) map[string]taintInfo {
	if len(c.stored) == 0 {
		return nil
	}
	pf, node := c.defNodeFor(sym)
	if pf == nil || node == nil {
		return nil
	}
	body := node.Utf8Text(pf.src)
	var names []string
	for k := range c.stored {
		if k.file == sym.File && strings.Contains(body, k.name) && wordRegexp(k.name).MatchString(body) {
			names = append(names, k.name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	seed := make(map[string]taintInfo, len(names))
	for _, n := range names {
		seed[n] = c.stored[storeKey{sym.File, n}].extend(model.FlowStep{
			Kind: "transform", Symbol: n, File: sym.File, Line: sym.Line, Resolved: true,
			Detail: "read back from module state " + n + " in " + sym.Name,
		}, 1)
	}
	return seed
}
