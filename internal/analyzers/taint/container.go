package taint

import (
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

var (
	// jsContainerCtor is a built-in keyed container: new Map(), new Set<string>(), new WeakMap()
	jsContainerCtor = regexp.MustCompile(`^\s*new\s+(Map|Set|WeakMap|WeakSet)\s*(?:<.*>)?\s*\(`)
	// pyContainerCtor is a built-in Python container: a dict, set or list display or
	// comprehension, or a call of dict/set/list or collections' defaultdict/OrderedDict/Counter
	pyContainerCtor = regexp.MustCompile(`^\s*(?:[{\[]|(?:collections\.)?(?:dict|set|list|defaultdict|OrderedDict|Counter)\s*\()`)
)

// builtinContainerReceiver reports whether the receiver of a method call is, by every binding the
// file gives it, a built-in container: `private clients = new Map<string, Client>()` with
// this.clients.delete(name), `SESSIONS: dict[str, S] = {}` with SESSIONS.get(sid). Its methods
// are then the language's own (Map.prototype.delete, dict.get), never a project function that
// happens to share the name, and none of them is a sink. Any binding that is not such a
// container (a None placeholder, an assignment from a call) and a project class named like the
// built-in make the answer false.
func (c *ctx) builtinContainerReceiver(src []byte, lang language.ID, recv string) bool {
	recv = strings.TrimSpace(recv)
	if recv == "" {
		return false
	}
	var ctor *regexp.Regexp
	switch lang {
	case language.TypeScript, language.JavaScript:
		ctor = jsContainerCtor
		for _, n := range []string{"Map", "Set", "WeakMap", "WeakSet"} {
			if len(c.idx[n]) > 0 {
				return false // the project defines its own Map or Set
			}
		}
	case language.Python:
		ctor = pyContainerCtor
		for _, n := range []string{"dict", "set", "list", "defaultdict", "OrderedDict", "Counter"} {
			if len(c.idx[n]) > 0 {
				return false
			}
		}
	default:
		return false
	}
	var binds []*regexp.Regexp
	switch {
	case isGuardIdent(recv):
		q := regexp.QuoteMeta(recv)
		binds = append(binds, regexp.MustCompile(`(?m)^[ \t]*(?:export\s+)?(?:const|let|var)?\s*`+q+`\s*(?::[^=\n]+)?=([^=].*)$`))
		if lang == language.Python {
			// global NAME; NAME = ...: the same line shape; a walrus or a for target rebinds too
			binds = append(binds, regexp.MustCompile(`\b(?:for|as)\s+`+q+`\b()`), regexp.MustCompile(`\b`+q+`\s*:=()`))
		}
	case strings.HasPrefix(recv, "this.") && isGuardIdent(recv[5:]) && lang != language.Python:
		q := regexp.QuoteMeta(recv[5:])
		binds = append(binds,
			regexp.MustCompile(`(?m)^[ \t]*(?:(?:private|public|protected|readonly|static|declare|override|#)\s*)*`+q+`\s*[?!]?\s*(?::[^=;\n]+)?=([^=>].*)$`),
			regexp.MustCompile(`\bthis\.`+q+`\s*(?:\?\?|\|\|)?=([^=].*)$`))
	case strings.HasPrefix(recv, "self.") && isGuardIdent(recv[5:]) && lang == language.Python:
		q := regexp.QuoteMeta(recv[5:])
		binds = append(binds, regexp.MustCompile(`(?m)\bself\.`+q+`\s*(?::[^=\n]+)?=([^=].*)$`))
	default:
		return false
	}
	text := string(src)
	n := 0
	for _, re := range binds {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if !ctor.MatchString(m[1]) {
				return false
			}
			n++
		}
	}
	return n > 0
}
