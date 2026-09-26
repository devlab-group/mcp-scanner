package behavioral

import "strings"

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

func sensitiveFragment(text string) (string, bool) {
	lower := strings.ToLower(text)
	for _, frag := range sensitivePathFragments {
		if strings.Contains(lower, strings.ToLower(frag)) {
			return frag, true
		}
	}
	return "", false
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

// negatedNear reports whether a negator appears in the negationWindow
// words immediately before word's occurrence in sentence
func negatedNear(sentence, word string) bool {
	head, _, ok := strings.Cut(sentence, word)
	if !ok {
		return false
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
	for idx := strings.Index(text, word); idx != -1; {
		before := idx == 0 || !isWordByte(text[idx-1])
		end := idx + len(word)
		after := prefixOnly || end >= len(text) || !isWordByte(text[end])
		if before && after {
			return true
		}
		next := strings.Index(text[idx+1:], word)
		if next == -1 {
			return false
		}
		idx += 1 + next
	}
	return false
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// matchCategory reports whether any of words appears in description as a plain, undenied
// claim (declared), and separately whether any appears explicitly denied (contradicted) -
// "never touches the network" and "touches the network" both mention the word, but only one
// of them is declaring the capability
func matchCategory(description string, words []string, stems bool) (declared, contradicted bool) {
	for _, sentence := range sentences(strings.ToLower(description)) {
		for _, w := range words {
			if !matchWord(sentence, w, stems) {
				continue
			}
			if negatedNear(sentence, w) {
				contradicted = true
			} else {
				declared = true
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
