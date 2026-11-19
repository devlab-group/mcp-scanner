package behavioral

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
)

// category is one of the deterministic signals a handler's reachable calls
// are checked against, and the same vocabulary a description is checked
// against - the comparison is only meaningful because both sides use the
// same small, fixed set of categories
type category string

const (
	catFilesystem  category = "filesystem"
	catNetwork     category = "network"
	catProcess     category = "process"
	catCredentials category = "credentials"
)

// capSet is which categories a capability's declared text implies, or which
// ones its handler's reachable calls actually touch
type capSet struct {
	Filesystem  bool
	Network     bool
	Process     bool
	Credentials bool

	// SensitiveHits are the literal sensitive-path fragments actually found
	// in a reached call's arguments - the concrete evidence for a
	// Credentials hit that came from a file path rather than an env read
	SensitiveHits []string
}

func (c capSet) any() bool { return c.Filesystem || c.Network || c.Process || c.Credentials }

var callCategories = []struct {
	text string
	cat  category
}{
	{"os.ReadFile", catFilesystem}, {"os.Open", catFilesystem}, {"os.WriteFile", catFilesystem},
	{"ioutil.ReadFile", catFilesystem}, {"ioutil.WriteFile", catFilesystem},
	{"readFileSync", catFilesystem}, {"writeFileSync", catFilesystem}, {"fs.readFile", catFilesystem},
	{"Files.readAllBytes", catFilesystem}, {"Files.write", catFilesystem},
	{"std::fs::read", catFilesystem}, {"std::fs::write", catFilesystem}, {"open", catFilesystem},
	// pathlib.Path methods: names no other common library uses for something else
	{".read_text", catFilesystem}, {".read_bytes", catFilesystem}, {".write_text", catFilesystem}, {".write_bytes", catFilesystem},

	{"http.Get", catNetwork}, {"http.Post", catNetwork}, {"http.NewRequest", catNetwork},
	{"requests.get", catNetwork}, {"requests.post", catNetwork}, {"requests.put", catNetwork},
	{"fetch", catNetwork}, {"reqwest::get", catNetwork}, {"reqwest::post", catNetwork},
	{"net.Dial", catNetwork}, {"socket.socket", catNetwork}, {"Socket::connect", catNetwork},
	{"URLConnection", catNetwork}, {"HttpClient", catNetwork},

	{"exec.Command", catProcess}, {"os.system", catProcess}, {"os.popen", catProcess},
	{"subprocess.run", catProcess}, {"subprocess.Popen", catProcess}, {"subprocess.call", catProcess},
	{"child_process.exec", catProcess}, {"Runtime.exec", catProcess}, {"ProcessBuilder", catProcess},
	{"Command::new", catProcess},

	// Environment variable reads are deliberately not in this table: which
	// variable is read matters (DEBUG vs AWS_SECRET_KEY), and that needs
	// looking at the call's own argument, not just its callee name - see
	// envReadFuncs and credentialLikeName below
}

// envReadFuncs are callees that read one environment variable by name. The read is treated as
// credential access only when its argument also looks like a credential-bearing variable.
var envReadFuncs = []string{
	"os.Getenv", "os.LookupEnv", "os.getenv", "os.environ", "System.getenv", "env::var", "process.env",
}

// envAccess matches environment reads that are not calls, so the call graph never sees them:
// Python's os.environ["NAME"] and JavaScript's process.env.NAME / process.env["NAME"]
var envAccess = regexp.MustCompile("\\bos\\.environ\\[\\s*[\"']([A-Za-z_]\\w*)[\"']\\s*\\]|\\bprocess\\.env\\.([A-Za-z_]\\w*)|\\bprocess\\.env\\[\\s*[\"'`]([A-Za-z_]\\w*)[\"'`]\\s*\\]")

// sourceEnvReads lists the environment variables the reached functions read by subscript or
// member access, from the lines of each function's own source
func sourceEnvReads(g *graph.Graph, reached map[graph.SymbolID]bool) []string {
	if g == nil || g.Root == "" {
		return nil
	}
	files := map[string][]string{}
	seen := map[string]bool{}
	var out []string
	for id := range reached {
		sym := g.Symbols[id]
		if sym == nil || sym.File == "" || sym.Line <= 0 {
			continue
		}
		lines, ok := files[sym.File]
		if !ok {
			b, err := os.ReadFile(filepath.Join(g.Root, sym.File))
			if err == nil {
				lines = strings.Split(string(b), "\n")
			}
			files[sym.File] = lines
		}
		end := sym.EndLine
		if end < sym.Line || end > len(lines) {
			end = min(len(lines), sym.Line)
		}
		for i := sym.Line - 1; i < end && i < len(lines); i++ {
			for _, m := range envAccess.FindAllStringSubmatch(lines[i], -1) {
				name := m[1] + m[2] + m[3]
				if name != "" && !seen[name] {
					seen[name] = true
					out = append(out, name)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func isEnvRead(calleeText string) bool {
	for _, f := range envReadFuncs {
		if strings.Contains(calleeText, f) {
			return true
		}
	}
	return false
}

// credentialWords is the vocabulary a variable name is checked against to
// decide whether reading it counts as touching a credential
var credentialWords = []string{"key", "secret", "token", "password", "credential", "auth", "apikey"}

func credentialLikeName(name string) bool {
	lower := strings.ToLower(name)
	for _, w := range credentialWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

func categoryOf(calleeText string) (category, bool) {
	for _, cc := range callCategories {
		if strings.Contains(calleeText, cc.text) {
			return cc.cat, true
		}
	}
	return "", false
}

// sensitivePathFragments are the paths the readiness/behavioral literature
// (and the task this analyzer targets) call out by name: SSH keys, cloud
// credential files, .env, and the cloud metadata endpoints that hand out
// instance credentials over plain HTTP
var sensitivePathFragments = []string{
	".ssh/", ".ssh\\", "id_rsa", "id_ed25519", ".pem",
	".aws/credentials", ".aws/config", ".azure/credentials", ".gcloud",
	".env", ".netrc", ".npmrc", ".kube/config", "credentials.json", "token.json",
	"169.254.169.254", "metadata.google.internal",
}

// dotfileFragments name a file or directory by its whole dotted name, so the dot must start a path
// component: ".env" in "./.env" or ".env.local", not in process.env, os.environ or import.meta.env,
// which read environment variables rather than a file
var dotfileFragments = map[string]bool{".env": true, ".netrc": true, ".npmrc": true, ".gcloud": true}

// extensionFragments are file extensions, so they must end a name: "server.pem", not ".pembroke"
var extensionFragments = map[string]bool{".pem": true}

func sensitiveFragment(text string) (string, bool) {
	lower := strings.ToLower(text)
	for _, frag := range sensitivePathFragments {
		f := strings.ToLower(frag)
		for from := 0; ; {
			i := strings.Index(lower[from:], f)
			if i < 0 {
				break
			}
			i += from
			end := i + len(f)
			ok := true
			if dotfileFragments[frag] && i > 0 && isNameByte(lower[i-1]) {
				ok = false
			}
			if dotfileFragments[frag] && end < len(lower) && isNameByte(lower[end]) {
				ok = false
			}
			if extensionFragments[frag] && end < len(lower) && isNameByte(lower[end]) {
				ok = false
			}
			if ok {
				return frag, true
			}
			from = i + 1
		}
	}
	return "", false
}

func isNameByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// declaredWords is the controlled vocabulary a description is matched
// against. It is deliberately small and literal - this is pattern
// matching against a fixed list, not language understanding - so what it
// does and does not catch is easy to state.
var declaredWords = map[category][]string{
	// Whole-word matching requires each supported inflection to be listed
	catNetwork:    {"network", "internet", "http", "https", "request", "requests", "api", "apis", "fetch", "fetches", "download", "downloads", "upload", "uploads", "post", "posts", "web", "remote", "url", "urls", "endpoint", "endpoints", "cloud", "sync", "syncs"},
	catFilesystem: {"file", "files", "read", "reads", "write", "writes", "disk", "path", "paths", "directory", "directories", "folder", "folders"},
	// Broad and stem-based on purpose: an undeclared-process finding is only useful when the
	// description genuinely says nothing about running anything, and most honest tool
	// descriptions describe what they do ("archive", "install", "report the version") rather
	// than how (naming "process" or "subprocess" outright)
	catProcess: {
		"exec", "run", "command", "shell", "process", "subprocess", "spawn", "invoke",
		"build", "compil", "install", "launch", "start", "version",
		"archiv", "compress", "extract", "packag", "deploy", "convert", "generat",
	},
	catCredentials: {"credential", "credentials", "secret", "secrets", "key", "keys", "token", "tokens", "password", "passwords", "auth"},
}

// containsAny is the stem-matching form, for the narrow-scope vocabulary:
// "local" has to reach "locally", and every entry there is a word no other
// word begins with
func containsAny(text string, words []string) bool {
	for _, w := range words {
		if containsWordPrefix(text, w) {
			return true
		}
	}
	return false
}

// negators precede a category word to explicitly deny it rather than
// declare it: "this tool never makes a network request" must not count as
// declaring the network category the way "this tool makes network
// requests" does - that pairing (the word present, but negated) is exactly
// what let a description talk its way out of behavioral.undeclared_network
// while the handler kept using the network anyway
var negators = []string{"no", "not", "never", "without", "doesn't", "does not"}

// negationWindow is how many words before a matched category word are checked for a
// negator. The narrow window prevents an unrelated earlier negation from cancelling a later
// claim; this is a bounded heuristic, not a grammar parse.
const negationWindow = 6

// sentences splits description text on sentence-ending punctuation, so a
// negator only cancels a category word in the same sentence, never
// somewhere else in the description
func sentences(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		return r == '.' || r == '!' || r == '?' || r == '\n'
	})
}

// negatedBefore reports whether a negator appears in the negationWindow
// words at the end of head, the sentence text before one occurrence of a
// category word
func negatedBefore(head string) bool {
	// A negator in an earlier clause negates that clause: "if refs is empty or not provided,
	// fetches all resources" does not deny fetching
	if i := strings.LastIndexAny(head, ",;:"); i >= 0 {
		head = head[i+1:]
	}
	before := strings.Fields(head)
	if len(before) > negationWindow {
		before = before[len(before)-negationWindow:]
	}
	window := strings.Join(before, " ")
	for _, n := range negators {
		if containsWord(window, n) {
			return true
		}
	}
	return false
}

// containsWord is a word-boundary-aware version of strings.Contains, used
// for negator matching: a plain substring check would read "note" as
// containing the negator "no" and misfire on an ordinary sentence that
// never negated anything
func containsWord(text, word string) bool {
	return matchWord(text, word, false)
}

// containsWordPrefix requires only the left boundary. containsAny uses it for narrow-scope stems
// such as "local"; containsWord callers require both boundaries.
func containsWordPrefix(text, word string) bool {
	return matchWord(text, word, true)
}

func matchWord(text, word string, prefixOnly bool) bool {
	return len(wordOccurrences(text, word, prefixOnly)) > 0
}

// wordOccurrences returns the byte offset of every occurrence of word in text that matchWord
// would accept: whole words, or with prefixOnly, words that begin with it
func wordOccurrences(text, word string, prefixOnly bool) []int {
	if word == "" {
		return nil
	}
	var out []int
	for idx := strings.Index(text, word); idx != -1; {
		before := idx == 0 || !isWordByte(text[idx-1])
		end := idx + len(word)
		after := prefixOnly || end >= len(text) || !isWordByte(text[end])
		if before && after {
			out = append(out, idx)
		}
		next := strings.Index(text[idx+1:], word)
		if next == -1 {
			break
		}
		idx += 1 + next
	}
	return out
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// matchCategory reports whether any of words appears in description as a plain, undenied
// claim (declared), and separately whether any appears explicitly denied (contradicted) -
// "never touches the network" and "touches the network" both mention the word, but only one
// of them is declaring the capability.
//
// Every occurrence is judged at the position it was matched. A word that a sentence both
// negates and uses plainly is not a denial there: "you did not have internet access, ... this
// tool now grants you internet access" is about having it. Other words of the same category do
// not lift a denial, so "never contacts the network or any web api" still denies the network.
func matchCategory(description string, words []string, stems bool) (declared, contradicted bool) {
	for _, sentence := range sentences(strings.ToLower(description)) {
		for _, w := range words {
			var negated, plain bool
			for _, idx := range wordOccurrences(sentence, w, stems) {
				if negatedBefore(sentence[:idx]) {
					negated = true
				} else {
					plain = true
				}
			}
			if plain {
				declared = true
			} else if negated {
				contradicted = true
			}
		}
	}
	return declared, contradicted
}

// declaredCapabilities reads what a description claims, split into what it
// affirmatively declares and what it explicitly denies. The two are not
// complements of each other: a description can leave a category
// unmentioned (neither), claim it (declared), or deny it outright
// (contradicted) - see matchCategory.
func declaredCapabilities(description string) (declared, contradicted capSet) {
	nd, nc := matchCategory(description, declaredWords[catNetwork], false)
	fd, fc := matchCategory(description, declaredWords[catFilesystem], false)
	pd, pc := matchCategory(description, declaredWords[catProcess], true)
	cd, cc := matchCategory(description, declaredWords[catCredentials], false)
	return capSet{Network: nd, Filesystem: fd, Process: pd, Credentials: cd},
		capSet{Network: nc, Filesystem: fc, Process: pc, Credentials: cc}
}

// claimsLocalOnly reports whether the description's own words imply a scope that excludes
// the network: "local", "project" or "metadata" without actually declaring network access
// alongside them. It is what makes "read local project metadata" a claim the scanner can
// check a handler against.
func claimsLocalOnly(description string) bool {
	d := strings.ToLower(description)
	narrow := containsAny(d, []string{"local", "project", "metadata", "offline", "workspace", "machine", "computer", "device"})
	declaredNetwork, _ := matchCategory(description, declaredWords[catNetwork], false)
	return narrow && !declaredNetwork
}

// Declared reports which capability categories a description affirmatively claims, with the
// same vocabulary and negation handling the mismatch checks use. Other analyzers use it to tell a
// tool's stated purpose from an injection into it.
func Declared(description string) (filesystem, network, process bool) {
	d, _ := declaredCapabilities(description)
	return d.Filesystem, d.Network, d.Process
}

// HandlerBehavior is what a capability's handler can reach through the call graph: the categories
// the behavioral checks compare against the description, and the concrete evidence behind them
type HandlerBehavior struct {
	Network           bool     `json:"network"`
	Filesystem        bool     `json:"filesystem"`
	Process           bool     `json:"process"`
	Credentials       bool     `json:"credentials"`
	SensitivePaths    []string `json:"sensitive_paths,omitempty"`
	EnvVars           []string `json:"env_vars,omitempty"`
	URLs              []string `json:"urls,omitempty"`
	ReachedFunctions  int      `json:"reached_functions"`
	ReachesUnresolved bool     `json:"reaches_unresolved_calls"`
}

// Behavior summarizes what handler can reach, with the same reachability and catalogue the
// mismatch checks use
func Behavior(g *graph.Graph, handler graph.SymbolID) HandlerBehavior {
	cs, unknown := actualCapabilities(g, handler)
	b := HandlerBehavior{Network: cs.Network, Filesystem: cs.Filesystem, Process: cs.Process, Credentials: cs.Credentials, ReachesUnresolved: unknown}
	seen := map[string]bool{}
	for _, h := range cs.SensitiveHits {
		if !seen["s:"+h] {
			seen["s:"+h] = true
			b.SensitivePaths = append(b.SensitivePaths, h)
		}
	}
	reached, _ := g.Reachable(handler)
	reached[handler] = true
	b.ReachedFunctions = len(reached)
	for _, v := range sourceEnvReads(g, reached) {
		if !seen["e:"+v] {
			seen["e:"+v] = true
			b.EnvVars = append(b.EnvVars, v)
		}
	}
	for id := range reached {
		for _, call := range g.CallsFrom(id) {
			for _, a := range call.Args {
				v := a.Value
				if isEnvRead(call.CalleeText) && a.Literal && v != "" && !seen["e:"+v] {
					seen["e:"+v] = true
					b.EnvVars = append(b.EnvVars, v)
				}
				if a.Literal && (strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "ws://") || strings.HasPrefix(v, "wss://")) && !seen["u:"+v] && len(b.URLs) < 50 {
					seen["u:"+v] = true
					b.URLs = append(b.URLs, v)
				}
			}
		}
	}
	sort.Strings(b.EnvVars)
	sort.Strings(b.URLs)
	sort.Strings(b.SensitivePaths)
	return b
}
