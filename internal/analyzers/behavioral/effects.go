package behavioral

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
)

// Effects is what the calls a handler reaches change or send, read from the names of the calls.
// Every list holds "file:line callee" and is empty when the names show nothing of the kind.
type Effects struct {
	WritesFiles  []string `json:"writes_files,omitempty"`
	RunsPrograms []string `json:"runs_programs,omitempty"`
	SendsData    []string `json:"sends_data,omitempty"`
	// ReadsText: the handler reaches a request or reads a file, so what it returns may carry text
	// from outside the server: "network", "files"
	ReadsText []string `json:"reads_text,omitempty"`
}

const maxEffects = 20

var (
	// file operations that change the tree, by the last part of the callee
	fileWriters = map[string]bool{"writeFile": true, "writeFileSync": true, "appendFile": true, "appendFileSync": true,
		"createWriteStream": true, "unlink": true, "unlinkSync": true, "rmSync": true, "rmdir": true, "rmdirSync": true,
		"rename": true, "renameSync": true, "copyFile": true, "copyFileSync": true, "cpSync": true, "mkdir": true, "mkdirSync": true,
		"write_text": true, "write_bytes": true, "rmtree": true, "makedirs": true, "WriteFile": true, "RemoveAll": true,
		"MkdirAll": true, "copyfile": true, "copy2": true, "copytree": true}
	// names other libraries use for other things; they count only on these modules
	fileWriterModules = map[string]bool{"os": true, "shutil": true, "fs": true, "fsp": true, "fse": true, "promises": true, "fsPromises": true}
	fileGeneric       = map[string]bool{"remove": true, "rm": true, "unlink": true, "rename": true, "mkdir": true, "Remove": true, "Rename": true, "Create": true, "Mkdir": true, "move": true}
	openMode          = regexp.MustCompile(`["']([rwxabt+]{1,3})["']`)
	sendMethod        = regexp.MustCompile(`(?i)\.(post|put|patch|delete)$|^http\.Post`)
	fetchMethod       = regexp.MustCompile(`(?i)method["']?\s*:\s*["'` + "`" + `](POST|PUT|PATCH|DELETE)`)
)

// EffectsOf reads what the calls handler reaches change or send. The call graph follows only
// project functions, so a library's own effects do not show.
func EffectsOf(g *graph.Graph, handler graph.SymbolID) Effects {
	reached, _ := g.Reachable(handler)
	reached[handler] = true
	var e Effects
	seen := map[string]bool{}
	add := func(list *[]string, kind, what string) {
		if k := kind + what; !seen[k] && len(*list) < maxEffects {
			seen[k] = true
			*list = append(*list, what)
		}
	}
	for id := range reached {
		for _, c := range g.CallsFrom(id) {
			if c.Callee != "" {
				continue // a project function, followed
			}
			where := fmt.Sprintf("%s:%d %s", c.File, c.Line, strings.TrimSpace(c.CalleeText))
			last := lastPart(c.CalleeText)
			mod := firstPart(c.CalleeText)
			var text []string
			for _, a := range c.Args {
				text = append(text, a.Text)
			}
			all := strings.Join(text, ", ")
			switch {
			case fileWriters[last] || fileGeneric[last] && fileWriterModules[mod]:
				add(&e.WritesFiles, "w", where)
			case last == "open" && (mod == "open" || mod == "os"):
				if m := openMode.FindStringSubmatch(all); m != nil && strings.ContainsAny(m[1], "wxa+") {
					add(&e.WritesFiles, "w", where)
				} else {
					add(&e.ReadsText, "t", "files")
				}
			}
			if cat, ok := categoryOf(c.CalleeText); ok {
				switch {
				case cat == catProcess:
					add(&e.RunsPrograms, "p", where)
				case cat == catNetwork && requestCall(c):
					if sendMethod.MatchString(strings.TrimSpace(c.CalleeText)) || last == "fetch" && fetchMethod.MatchString(all) {
						add(&e.SendsData, "s", where)
					}
					add(&e.ReadsText, "t", "network")
				case cat == catFilesystem && !fileWriters[last]:
					add(&e.ReadsText, "t", "files")
				}
			}
		}
	}
	sort.Strings(e.WritesFiles)
	sort.Strings(e.RunsPrograms)
	sort.Strings(e.SendsData)
	sort.Strings(e.ReadsText)
	return e
}

// Empty reports whether the effects show nothing
func (e Effects) Empty() bool {
	return len(e.WritesFiles)+len(e.RunsPrograms)+len(e.SendsData)+len(e.ReadsText) == 0
}

func lastPart(callee string) string {
	c := strings.TrimSpace(callee)
	if i := strings.LastIndexAny(c, ".:"); i >= 0 {
		return c[i+1:]
	}
	return c
}

func firstPart(callee string) string {
	c := strings.TrimSpace(callee)
	if i := strings.IndexAny(c, ".:"); i >= 0 {
		return c[:i]
	}
	return c
}

// LoopbackHosts are the fixed hosts of an egress that name this machine: work a handler hands to
// the server's own backend or daemon, which the scanner does not follow
func (e *Egress) LoopbackHosts() []string {
	if e == nil {
		return nil
	}
	var out []string
	for _, h := range e.FixedHosts {
		name := strings.ToLower(h)
		if i := strings.LastIndexByte(name, ':'); i > 0 && !strings.Contains(name[i+1:], ".") {
			name = name[:i]
		}
		switch name {
		case "localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "::1", "[::1]":
			out = append(out, h)
		}
	}
	return out
}
