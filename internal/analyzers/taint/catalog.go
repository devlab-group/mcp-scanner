package taint

import (
	"slices"
	"strings"

	"github.com/revinand/mcp-scanner/internal/source/graph"
	"github.com/revinand/mcp-scanner/internal/source/language"
	"github.com/revinand/mcp-scanner/internal/source/parser"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// Most pattern tables use whole-identifier matching anywhere in callee text, so a dotted entry can
// also match inside a longer qualified callee. Receiver-method tables compare the final segment
// exactly. Prefix siblings such as os.Open and os.OpenFile need separate entries;
// catalog_prefix_test.go catches known overlaps but cannot discover missing APIs.

// sourcePattern describes one MCP-side origin of untrusted data. Handler
// parameters are seeded directly from the graph's discovered capabilities;
// everything else is recognized by the callee it reads from.
type sourcePattern struct {
	text   string
	detail string
}

var sourcePatterns = []sourcePattern{
	{"os.Getenv", "environment variable"},
	{"os.LookupEnv", "environment variable"},
	{"os.environ", "environment variable"},
	{"os.getenv", "environment variable"},
	{"System.getenv", "environment variable"},
	{"env::var", "environment variable"},
	{"process.env", "environment variable"},

	{"os.ReadFile", "file contents"},
	{"ioutil.ReadFile", "file contents"},
	{"readFileSync", "file contents"},
	{"Files.readAllBytes", "file contents"},
	{"std::fs::read", "file contents"},
	{"fs.readFile", "file contents"},

	{"http.Get", "HTTP response body"},
	{"requests.get", "HTTP response body"},
	{"requests.post", "HTTP response body"},
	{"fetch", "HTTP response body"},
	{"reqwest::get", "HTTP response body"},
}

func matchSource(calleeText string) (string, bool) {
	for _, p := range sourcePatterns {
		if mentionsIdent(calleeText, p.text) {
			return p.detail, true
		}
	}
	return "", false
}

// sinkPattern is one dangerous operation. argIndex is -1 for taint in any argument, or a fixed
// position when later arguments are safe parameters rather than executable text.
type sinkPattern struct {
	text     string
	category string
	severity model.Severity
	argIndex int
}

var sinkPatterns = []sinkPattern{
	// exec.Command, subprocess.run/Popen/call, Command::new and
	// ProcessBuilder take their command as separate argv elements rather
	// than one shell string; see argvSinks below for why they are not
	// listed here as plain "taint anywhere" sinks
	{"os.system", "command_injection", model.SeverityHigh, -1},
	{"os.popen", "command_injection", model.SeverityHigh, -1},
	// asyncio.create_subprocess_shell is os.system's exact analogue for
	// async code: one string handed to a shell. It is also the only way to
	// launch a subprocess without blocking the event loop, which is why an
	// async def handler - the shape every FastMCP tool handler takes -
	// reaches it instead of os.system in practice.
	{"asyncio.create_subprocess_shell", "command_injection", model.SeverityHigh, -1},
	{"child_process.exec", "command_injection", model.SeverityHigh, -1},
	{"execSync", "command_injection", model.SeverityHigh, -1},
	// execa is argv-style by default and shell-style with {shell: true}. execaCommand splits its
	// command string into argv without a shell unless that option is set.
	{"execa", "command_injection", model.SeverityHigh, -1},
	{"execaCommand", "command_injection", model.SeverityHigh, -1},
	// A bare "exec" catches `import { exec } from "child_process"` used
	// without the module prefix - mentionsIdent's word-boundary check
	// keeps this from also matching execSync/execFileSync/execute, which
	// all have "exec" as a prefix of a longer identifier, not the whole
	// name
	{"exec", "command_injection", model.SeverityHigh, -1},
	{"Runtime.exec", "command_injection", model.SeverityHigh, -1},
	{"commands.getoutput", "command_injection", model.SeverityHigh, -1}, // Python 2's shell-based commands module
	// subprocess.getoutput/getstatusoutput are commands.getoutput's Python 3
	// replacement: one string handed straight to a shell, output returned -
	// exactly the shape a tool handler wants, and os.system's closest match
	// for code that also wants the command's output back
	{"subprocess.getoutput", "command_injection", model.SeverityHigh, -1},
	{"subprocess.getstatusoutput", "command_injection", model.SeverityHigh, -1},

	// Treat all os.spawn variants conservatively as process-launch sinks
	{"os.spawnl", "command_injection", model.SeverityHigh, -1},
	{"os.spawnle", "command_injection", model.SeverityHigh, -1},
	{"os.spawnlp", "command_injection", model.SeverityHigh, -1},
	{"os.spawnlpe", "command_injection", model.SeverityHigh, -1},
	{"os.spawnv", "command_injection", model.SeverityHigh, -1},
	{"os.spawnve", "command_injection", model.SeverityHigh, -1},
	{"os.spawnvp", "command_injection", model.SeverityHigh, -1},
	{"os.spawnvpe", "command_injection", model.SeverityHigh, -1},

	{"eval", "eval", model.SeverityHigh, -1},
	{"vm.runInNewContext", "eval", model.SeverityHigh, -1},
	{"vm.runInThisContext", "eval", model.SeverityHigh, -1},
	{"vm.compileFunction", "eval", model.SeverityHigh, -1},
	{"new Function", "eval", model.SeverityHigh, -1},
	{"plugin.Open", "eval", model.SeverityHigh, -1}, // Go's nearest equivalent to dynamic code loading

	{"os.ReadFile", "path_traversal", model.SeverityHigh, -1},
	{"ioutil.ReadFile", "path_traversal", model.SeverityHigh, -1},
	{"os.WriteFile", "path_traversal", model.SeverityMedium, -1},
	{"ioutil.WriteFile", "path_traversal", model.SeverityMedium, -1},
	{"os.Open", "path_traversal", model.SeverityHigh, -1},
	// os.Open above matches only the exact call "os.Open(...)": mentionsIdent requires a word
	// boundary right after "Open", and "F" is an identifier byte, so "os.OpenFile(...)" falls
	// through as a different name entirely rather than as a covered variant - the same gap a
	// shorter entry that happens to be a real identifier's prefix always has in a language
	// without separators between words
	{"os.OpenFile", "path_traversal", model.SeverityHigh, -1},
	{"os.Remove", "path_traversal", model.SeverityHigh, -1},
	{"os.RemoveAll", "path_traversal", model.SeverityHigh, -1},
	{"os.Create", "path_traversal", model.SeverityMedium, -1},
	// os.CreateTemp(dir, pattern) creates a file inside dir - the same
	// os.Create/os.OpenFile boundary gap: a caller-supplied dir is exactly
	// as dangerous here as one passed to os.Create itself
	{"os.CreateTemp", "path_traversal", model.SeverityMedium, -1},
	{"os.MkdirAll", "path_traversal", model.SeverityMedium, -1},
	{"readFileSync", "path_traversal", model.SeverityHigh, -1},
	{"writeFileSync", "path_traversal", model.SeverityMedium, -1},
	{"Files.readAllBytes", "path_traversal", model.SeverityHigh, -1},
	{"Files.write", "path_traversal", model.SeverityMedium, -1},
	// Files.writeString(path, content, ...) is Files.write's Java 11+
	// sibling, taking a CharSequence instead of a byte array - the same
	// call otherwise, and just as often what real code reaches for
	{"Files.writeString", "path_traversal", model.SeverityMedium, -1},
	{"std::fs::read", "path_traversal", model.SeverityHigh, -1},
	// std::fs::read_to_string(path) is std::fs::read's own sibling for
	// text files - arguably the more common of the two in real Rust code
	// - and was invisible for the same reason os.OpenFile was
	{"std::fs::read_to_string", "path_traversal", model.SeverityHigh, -1},
	{"std::fs::write", "path_traversal", model.SeverityMedium, -1},

	// Python's os/shutil/glob module-level path operations. "open" is not listed here: matched
	// as bare text via mentionsIdent's word-boundary search, it would also match any receiver's
	// ".open()" method, bypassing methodSinkPatterns' resolvedInRepo guard - it lives there
	// instead, next to the other receiver-blind method names.
	{"shutil.copy", "path_traversal", model.SeverityMedium, -1},
	{"shutil.copy2", "path_traversal", model.SeverityMedium, -1},       // copy, preserving metadata
	{"shutil.copyfile", "path_traversal", model.SeverityMedium, -1},    // copy without metadata, no directory destination
	{"shutil.copytree", "path_traversal", model.SeverityMedium, -1},    // recursive directory copy
	{"shutil.copyfileobj", "path_traversal", model.SeverityMedium, -1}, // copies into an already-open file object; the object itself, not this call, resolves the path, but a caller-built path reaching the open() that produced it is exactly as dangerous
	{"shutil.move", "path_traversal", model.SeverityMedium, -1},
	{"shutil.rmtree", "path_traversal", model.SeverityHigh, -1},
	{"os.remove", "path_traversal", model.SeverityHigh, -1},
	// os.removedirs(name) is os.remove's own sibling for a directory (and
	// removes now-empty parents recursively) - same gap, same fix
	{"os.removedirs", "path_traversal", model.SeverityHigh, -1},
	{"os.rename", "path_traversal", model.SeverityMedium, -1},
	// os.renames(old, new) is os.rename's own sibling: creates any missing
	// intermediate directories in new, then removes any now-empty ones
	// left behind under old
	{"os.renames", "path_traversal", model.SeverityMedium, -1},
	{"os.listdir", "path_traversal", model.SeverityMedium, -1},
	{"os.walk", "path_traversal", model.SeverityMedium, -1},
	{"glob.glob", "path_traversal", model.SeverityMedium, -1},

	{"http.Get", "ssrf", model.SeverityHigh, -1},
	{"http.Post", "ssrf", model.SeverityHigh, -1},
	{"http.NewRequest", "ssrf", model.SeverityHigh, -1},
	// http.NewRequestWithContext(ctx, method, url, body) is
	// http.NewRequest's own sibling - the form every Go linter recommends
	// over it since 1.13 - and just as invisible to the shorter entry
	{"http.NewRequestWithContext", "ssrf", model.SeverityHigh, -1},
	{"requests.get", "ssrf", model.SeverityHigh, -1},
	{"requests.post", "ssrf", model.SeverityHigh, -1},
	{"fetch", "ssrf", model.SeverityHigh, -1},
	{"reqwest::get", "ssrf", model.SeverityHigh, -1},
	{"URLConnection", "ssrf", model.SeverityHigh, -1},

	{"socket.socket", "raw_socket", model.SeverityMedium, -1},
	{"net.Dial", "raw_socket", model.SeverityMedium, -1},
	// net.DialTimeout is net.Dial's own sibling - a caller-controlled host reaches the network
	// exactly the same way
	{"net.DialTimeout", "raw_socket", model.SeverityMedium, -1},
	{"Socket::connect", "raw_socket", model.SeverityMedium, -1},

	// Receiver-blind SQL methods belong in methodSinkPatterns below
	{"createStatement", "sql_injection", model.SeverityHigh, 0},
	{"sqlx::query", "sql_injection", model.SeverityHigh, 0},

	{"render_template_string", "template_injection", model.SeverityHigh, 0},
	{"template.New", "template_injection", model.SeverityMedium, 0},
	{"Template::new", "template_injection", model.SeverityMedium, 0},

	{"pickle.loads", "deserialization", model.SeverityHigh, -1},
	{"yaml.load", "deserialization", model.SeverityHigh, -1},
	// yaml.load_all(stream) is yaml.load's own sibling for a stream of
	// multiple documents - same unsafe-constructor risk, same gap
	{"yaml.load_all", "deserialization", model.SeverityHigh, -1},
	{"ObjectInputStream", "deserialization", model.SeverityHigh, -1},
	{"marshal.loads", "deserialization", model.SeverityHigh, -1},

	// The rest of this table is the cross-language sweep below: Python's
	// os/shutil siblings that weren't caught by the family-siblings pass
	// above, urllib's stdlib request function, and one entry per
	// list/rename/create-directory/change-mode/symlink operation for every
	// language that did not already have one, matched against a checked-in
	// module-API list (catalog_api_test.go) and a checked-in
	// language-parity table (catalog_parity_test.go) rather than left to
	// be noticed by hand

	{"os.scandir", "path_traversal", model.SeverityMedium, -1},
	{"os.mkdir", "path_traversal", model.SeverityMedium, -1},
	// os.makedirs(name) is os.mkdir's own sibling: creates every missing
	// intermediate directory too, the same os.Create/os.CreateTemp-shaped
	// gap - a caller-supplied path is exactly as dangerous through either
	{"os.makedirs", "path_traversal", model.SeverityMedium, -1},
	{"os.chmod", "path_traversal", model.SeverityMedium, -1},
	{"os.symlink", "path_traversal", model.SeverityMedium, -1},
	// shutil.unpack_archive(filename, extract_dir) is shutil's own wrapper
	// around zipfile/tarfile's extractall (see "extractall" in
	// methodSinkPatterns below) - same zip-slip risk, one call instead of
	// two
	{"shutil.unpack_archive", "path_traversal", model.SeverityHigh, -1},
	// urllib.request.urlopen is the standard-library request call for code
	// with no third-party HTTP dependency at all - requests/httpx/aiohttp
	// above assume one is installed, urllib never does
	{"urllib.request.urlopen", "ssrf", model.SeverityHigh, -1},

	{"os.ReadDir", "path_traversal", model.SeverityMedium, -1},
	{"os.Rename", "path_traversal", model.SeverityMedium, -1},
	{"os.Symlink", "path_traversal", model.SeverityMedium, -1},
	{"os.Mkdir", "path_traversal", model.SeverityMedium, -1},
	// os.Mkdir above matches only the exact call "os.Mkdir(...)" - the
	// same os.Open/os.OpenFile word-boundary gap - so its recursive
	// sibling os.MkdirAll (already catalogued, see above) needs its own
	// entry rather than being covered by this one
	{"os.Chmod", "path_traversal", model.SeverityMedium, -1},
	{"os.Truncate", "path_traversal", model.SeverityMedium, -1},
	{"filepath.Walk", "path_traversal", model.SeverityMedium, -1},
	// filepath.WalkDir is filepath.Walk's own Go 1.16+ replacement (a
	// faster fs.DirEntry-based callback instead of os.FileInfo) - same
	// word-boundary gap, needs its own entry
	{"filepath.WalkDir", "path_traversal", model.SeverityMedium, -1},

	// Node's synchronous fs API, alongside readFileSync/writeFileSync
	// above - the same bare-name convention, since these are commonly
	// imported directly (`const { readdirSync } = require("fs")`) rather
	// than through a receiver a project names itself
	{"readdirSync", "path_traversal", model.SeverityMedium, -1},
	{"appendFileSync", "path_traversal", model.SeverityMedium, -1},
	{"chmodSync", "path_traversal", model.SeverityMedium, -1},
	{"symlinkSync", "path_traversal", model.SeverityMedium, -1},
	// The mutating half of the same API. A Sync name is not reached by its promise twin in
	// methodSinkPatterns: that table matches the callee's last segment exactly, so "unlink"
	// never covers "unlinkSync".
	{"unlinkSync", "path_traversal", model.SeverityHigh, -1},
	{"rmSync", "path_traversal", model.SeverityHigh, -1},
	{"rmdirSync", "path_traversal", model.SeverityHigh, -1},
	{"mkdirSync", "path_traversal", model.SeverityMedium, -1},
	{"renameSync", "path_traversal", model.SeverityMedium, -1},
	{"copyFileSync", "path_traversal", model.SeverityMedium, -1},
	{"cpSync", "path_traversal", model.SeverityMedium, -1},
	{"openSync", "path_traversal", model.SeverityMedium, -1},
	{"truncateSync", "path_traversal", model.SeverityMedium, -1},
	{"opendirSync", "path_traversal", model.SeverityMedium, -1},
	{"utimesSync", "path_traversal", model.SeverityMedium, -1},

	// java.nio.file.Files' own remaining path-relevant methods, alongside
	// Files.write/Files.writeString/Files.readAllBytes above
	{"Files.list", "path_traversal", model.SeverityMedium, -1},
	{"Files.move", "path_traversal", model.SeverityMedium, -1},
	{"Files.createDirectory", "path_traversal", model.SeverityMedium, -1},
	// Files.createDirectories is Files.createDirectory's own sibling -
	// creates every missing intermediate directory too, the same
	// os.Mkdir/os.MkdirAll-shaped gap
	{"Files.createDirectories", "path_traversal", model.SeverityMedium, -1},
	{"Files.setPosixFilePermissions", "path_traversal", model.SeverityMedium, -1},
	{"Files.createSymbolicLink", "path_traversal", model.SeverityMedium, -1},

	// std::fs' own remaining path-relevant functions, alongside
	// std::fs::read/read_to_string/write above
	{"std::fs::read_dir", "path_traversal", model.SeverityMedium, -1},
	{"std::fs::rename", "path_traversal", model.SeverityMedium, -1},
	{"std::fs::create_dir", "path_traversal", model.SeverityMedium, -1},
	// std::fs::create_dir_all is std::fs::create_dir's own sibling - same
	// recursive-creation shape as os.Mkdir/os.MkdirAll
	{"std::fs::create_dir_all", "path_traversal", model.SeverityMedium, -1},
	{"std::fs::set_permissions", "path_traversal", model.SeverityMedium, -1},
	// The Unix form only - std::os::windows::fs::symlink_file/symlink_dir
	// are a separate, platform-gated pair this catalogue does not model,
	// the same judgment call already made against Windows-only APIs
	// elsewhere in this package
	{"std::os::unix::fs::symlink", "path_traversal", model.SeverityMedium, -1},
}

// methodSinkPatterns match on the callee's final method name alone (parser.LastSegment), never the
// receiver - unlike sinkPatterns above, which match a literal dotted (or fully-qualified
// free-function) name. These are calls made on a receiver a project names itself: a cursor,
// a db handle, a filesystem import.
var methodSinkPatterns = []sinkPattern{
	{"execute", "sql_injection", model.SeverityHigh, 0},
	{"executemany", "sql_injection", model.SeverityHigh, 0},
	{"executescript", "sql_injection", model.SeverityHigh, 0},
	{"executeQuery", "sql_injection", model.SeverityHigh, 0},
	{"Query", "sql_injection", model.SeverityHigh, 0},
	{"QueryRow", "sql_injection", model.SeverityHigh, 0},
	{"Exec", "sql_injection", model.SeverityHigh, 0},
	// The *Context variants take a context.Context as their first
	// argument (db.QueryContext(ctx, query, args...)), so the query text
	// itself is argument index 1, not 0
	{"QueryContext", "sql_injection", model.SeverityHigh, 1},
	{"QueryRowContext", "sql_injection", model.SeverityHigh, 1},
	{"ExecContext", "sql_injection", model.SeverityHigh, 1},
	// query covers Node pg and mysql client or pool methods. SQL text is argument zero;
	// bound values arrive later, as in pool.query("...", values).
	{"query", "sql_injection", model.SeverityHigh, 0},
	// prepare is better-sqlite3's and node:sqlite's compile step, and also JDBC's
	// prepareStatement counterpart in shape: the SQL text is argument 0, and the values arrive
	// later through the returned statement's own run/get/all
	{"prepare", "sql_injection", model.SeverityHigh, 0},

	// node:fs/promises' method names: fs.promises.readFile,
	// fsPromises.readFile, a destructured `import { readFile } from
	// "fs/promises"` - whatever the receiver (or lack of one) is called
	{"readFile", "path_traversal", model.SeverityHigh, -1},
	{"writeFile", "path_traversal", model.SeverityMedium, -1},
	{"appendFile", "path_traversal", model.SeverityMedium, -1},
	{"unlink", "path_traversal", model.SeverityHigh, -1},
	{"rm", "path_traversal", model.SeverityHigh, -1},
	{"rename", "path_traversal", model.SeverityMedium, -1},
	{"copyFile", "path_traversal", model.SeverityMedium, -1},
	{"createReadStream", "path_traversal", model.SeverityHigh, -1},

	// pathlib.Path's own methods: the tainted value is normally the
	// receiver itself (`target = DOCS / name; target.read_text()`), not an
	// argument, which taintedArgOrReceiver (walk.go) checks once no argument
	// matches - argIndex -1 here means "any
	// argument, or the receiver" rather than "any argument only"
	{"read_text", "path_traversal", model.SeverityHigh, -1},
	{"read_bytes", "path_traversal", model.SeverityHigh, -1},
	{"write_text", "path_traversal", model.SeverityMedium, -1},
	{"write_bytes", "path_traversal", model.SeverityMedium, -1},
	// "open" is also Python's builtin open(name) - a bare, no-receiver call - which this same
	// method-name match still catches, since parser.LastSegment("open") is "open" whether or not there
	// was a dot in front of it
	{"open", "path_traversal", model.SeverityHigh, -1},
	// unlink is already listed above for fs/promises; the match is
	// receiver-blind either way, so pathlib's Path.unlink() is already
	// covered by that entry - nothing to add here
	{"rmdir", "path_traversal", model.SeverityHigh, -1},
	{"iterdir", "path_traversal", model.SeverityMedium, -1},
	{"glob", "path_traversal", model.SeverityMedium, -1},
	{"rglob", "path_traversal", model.SeverityMedium, -1},
	{"touch", "path_traversal", model.SeverityMedium, -1},
	{"mkdir", "path_traversal", model.SeverityMedium, -1},
	// Path.replace(target) (rename) is deliberately not listed: "replace" is also the ordinary
	// string/dict replace method, already registered in methodSanitizerPatterns as a weak
	// sanitizer, and matchMethodSink is checked before sanitizerFor in handleCall - a sink
	// entry here would win that race and silently stop text.replace(bad, good) from ever being
	// recognized as a sanitizer at all

	// A configured HTTP client - a package-level *http.Client, an axios/httpx/aiohttp instance
	// - calls its verb as a method on a receiver; sinkPatterns' http.Get/requests.get/fetch
	// only match the free-function spellings
	{"Get", "ssrf", model.SeverityHigh, -1},
	{"Post", "ssrf", model.SeverityHigh, -1},
	{"Do", "ssrf", model.SeverityHigh, -1},

	// (*net.Dialer).DialContext has no free-function form at all - unlike
	// net.Dial/net.DialTimeout, it only ever exists as a method on a
	// Dialer value a project configures and names itself, so it belongs
	// here rather than in sinkPatterns' dotted list
	{"DialContext", "raw_socket", model.SeverityMedium, -1},

	// extractall is zipfile.ZipFile's and tarfile.TarFile's own extraction
	// method - Python's two archive modules happen to share the exact same
	// method name for it, so one receiver-blind entry catches
	// zipfile.ZipFile(...).extractall(dest) and
	// tarfile.open(...).extractall(dest) alike: a path built from an
	// archive member's own name (Zip Slip) or from a tainted destination
	// argument can write anywhere on disk
	{"extractall", "path_traversal", model.SeverityHigh, -1},

	// node:fs/promises' remaining method names, alongside
	// readFile/writeFile/appendFile/unlink/rm/rename/copyFile/
	// createReadStream above - same receiver-blind reasoning
	{"readdir", "path_traversal", model.SeverityMedium, -1},
	// cp (fs.cp/fs.promises.cp, Node 16.7+) is copyFile's own recursive
	// sibling. "cp" is a short, generic-looking name - the same tradeoff
	// already accepted for "rm" above - but the resolvedInRepo guard this
	// whole table shares still saves a project's own function or variable
	// of that name.
	{"cp", "path_traversal", model.SeverityMedium, -1},
	{"opendir", "path_traversal", model.SeverityMedium, -1},
	{"createWriteStream", "path_traversal", model.SeverityMedium, -1},
	{"chmod", "path_traversal", model.SeverityMedium, -1},
	{"symlink", "path_traversal", model.SeverityMedium, -1},
}

// receiverConstructors names calls whose return value is built from exactly the arguments
// passed to it, like a binary expression's operands: pathlib's path constructors and
// joinpath, plus join/resolve - the join-shaped call every language here has (Go's
// filepath.Join, Node's path.join/path.resolve, Java's Path.resolve, Rust's Path::join)
var receiverConstructors = map[string]bool{
	"Path": true, "PurePath": true, "PurePosixPath": true, "PureWindowsPath": true,
	"joinpath": true, "join": true, "resolve": true,
}

// matchReceiverConstructor checks receiverConstructors by the callee's
// final method/function name, the same parser.LastSegment matching
// matchMethodSink uses
func matchReceiverConstructor(calleeText string) bool {
	return receiverConstructors[parser.LastSegment(calleeText)]
}

// gatedMethodSinkPatterns require a recognized HTTP client import. Bare get/post names are too
// common to match receiver-blind without that file-level evidence.
var gatedMethodSinkPatterns = []sinkPattern{
	{"get", "ssrf", model.SeverityHigh, -1},
	{"post", "ssrf", model.SeverityHigh, -1},
}

// httpClientImports are the module paths fileImportsHTTPClient looks for
var httpClientImports = []string{"axios", "httpx", "aiohttp", "requests"}

// fileImportsHTTPClient reports whether file imports one of httpClientImports - a plain
// match, a submodule of one ("aiohttp.web"), or a name imported from one ("from httpx
// import AsyncClient" records the import path as "httpx.AsyncClient")
func fileImportsHTTPClient(g *graph.Graph, file string) bool {
	f := g.Files[file]
	if f == nil {
		return false
	}
	for _, imp := range f.Imports {
		for _, name := range httpClientImports {
			if imp.Path == name || strings.HasPrefix(imp.Path, name+".") {
				return true
			}
		}
	}
	return false
}

// matchGatedMethodSink is matchMethodSink's counterpart for
// gatedMethodSinkPatterns - see there for why "get"/"post" cannot be
// matched unconditionally
func matchGatedMethodSink(calleeText string) (sinkPattern, bool) {
	last := parser.LastSegment(calleeText)
	for _, p := range gatedMethodSinkPatterns {
		if last == p.text {
			return p, true
		}
	}
	return sinkPattern{}, false
}

func matchSink(calleeText string) (sinkPattern, bool) {
	for _, p := range sinkPatterns {
		if mentionsIdent(calleeText, p.text) {
			return p, true
		}
	}
	return sinkPattern{}, false
}

// matchMethodSink checks methodSinkPatterns by the callee's final method name. Callers use it
// only after ruling out an in-repository function, so an ordinary helper named execute is followed.
func matchMethodSink(calleeText string) (sinkPattern, bool) {
	last := parser.LastSegment(calleeText)
	for _, p := range methodSinkPatterns {
		if last == p.text {
			return p, true
		}
	}
	return sinkPattern{}, false
}

// argvKind is the shape one argv-style process API takes its command in: which call carries
// the program name, and how the rest of the argv is found from there
type argvKind int

const (
	argvGo         argvKind = iota // exec.Command(prog, arg1, arg2, ...): all argv as this call's own args, args[0] = program
	argvJava                       // new ProcessBuilder(prog, arg1, arg2, ...): same shape as Go
	argvPythonExec                 // asyncio.create_subprocess_exec(prog, arg1, arg2, ...): same shape as Go; unlike subprocess.run it has no shell=True, since it never goes through a shell to begin with
	argvPython                     // subprocess.run/Popen/call/check_output/check_call(prog_or_list, ...): argv may be args[0] itself or a list literal in args[0]; shell=True overrides everything
	argvRustNew                    // Command::new(program): this call's one argument is the program; the rest of the argv is added by later, separate .arg()/.args() calls
	argvRustArg                    // .arg(x) / .args([...]) chained onto a Command: a later argv element; the program set by Command::new is not visible from here
	// execFileSync(file, args, options) / spawnSync/spawn/execFile/fork(command, args,
	// options): args[0] is the program, the rest of the argv is the array literal in args[1],
	// not this call's own remaining arguments
	argvNodeFile
)

type argvSink struct {
	text string
	kind argvKind
}

// argvSinks build commands from separate argv elements. They need positional classification so a
// tainted program, shell command, and later option value do not receive the same severity.
var argvSinks = []argvSink{
	{"exec.Command", argvGo},
	{"ProcessBuilder", argvJava},
	{"asyncio.create_subprocess_exec", argvPythonExec},
	{"subprocess.run", argvPython},
	{"subprocess.Popen", argvPython},
	{"subprocess.call", argvPython},
	{"subprocess.check_output", argvPython},
	{"subprocess.check_call", argvPython},
	{"Command::new", argvRustNew},
	{"execFileSync", argvNodeFile},
	{"spawnSync", argvNodeFile},
	// Bare async Node names improve coverage but can match unrelated helpers
	{"spawn", argvNodeFile},
	{"execFile", argvNodeFile},
	{"fork", argvNodeFile},
	{"os.execv", argvNodeFile},
	{"os.execvp", argvNodeFile},
	// os.execl/execle/execlp/execlpe are os.execv/execvp's own l-variant
	// siblings: the same "replace this process" call, with argv passed as
	// individual positional arguments (os.execl(path, arg0, arg1, ...))
	// instead of a list in a second argument - argvPythonExec's shape
	// (this call's own remaining arguments are the argv, args[0] is the
	// program), not argvNodeFile's
	{"os.execl", argvPythonExec},
	{"os.execle", argvPythonExec},
	{"os.execlp", argvPythonExec},
	{"os.execlpe", argvPythonExec},
}

func matchArgvSink(id language.ID, calleeText string, args []graph.Arg) (argvSink, []graph.Arg, bool) {
	if id == language.Go && mentionsIdent(calleeText, "exec.CommandContext") {
		// exec.CommandContext(ctx, prog, arg1, ...) takes a
		// context.Context first; mentionsIdent's whole-word match means
		// the plain "exec.Command" entry below never matches this longer
		// identifier at all, so without this it was invisible to argv
		// classification entirely - every argument, including the program
		// name, read as one position later than it actually is
		rest := args
		if len(rest) > 0 {
			rest = rest[1:]
		}
		return argvSink{text: calleeText, kind: argvGo}, rest, true
	}
	for _, s := range argvSinks {
		if mentionsIdent(calleeText, s.text) {
			return s, args, true
		}
	}
	// A Rust builder continuation - .arg(...) or .args([...]) chained onto a Command - is
	// recognized by the method name alone: the program that started the chain is a different
	// call node and is not visible from here
	if id == language.Rust {
		switch parser.LastSegment(calleeText) {
		case "arg", "args":
			return argvSink{text: calleeText, kind: argvRustArg}, args, true
		}
	}
	return argvSink{}, nil, false
}

// shellInterpreters are the program names that, when run with an inline command flag, hand
// their argument straight to a shell rather than treating it as a plain argv element
var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true,
	"cmd": true, "powershell": true, "pwsh": true,
}

var shellInlineFlags = map[string]bool{
	"-c": true, "/c": true, "-command": true,
}

// sanitizerPattern describes category-specific clearing or weakening. covers lists categories a
// strong sanitizer clears; for all other categories it acts as a weak sanitizer. normalizes marks
// a path transformation suitable for a later containment check. Weak sanitizers keep the flow
// visible with lower confidence because cleaning syntax alone does not prove containment.
type sanitizerPattern struct {
	text       string
	weak       bool
	covers     []string
	detail     string
	normalizes bool
}

var sanitizerPatterns = []sanitizerPattern{
	{"filepath.Clean", true, nil, "filepath.Clean does not stop traversal outside the base directory", true},
	{"filepath.Abs", true, nil, "filepath.Abs does not stop traversal outside the base directory", true},
	{"filepath.EvalSymlinks", true, nil, "filepath.EvalSymlinks does not stop traversal outside the base directory", true},
	{"filepath.Join", true, nil, "filepath.Join does not stop traversal outside the base directory", true},
	{"path.Clean", true, nil, "path.Clean does not stop traversal outside the base directory", true},
	// os.path.join must precede path.join: mentionsIdent finds "path.join" inside
	// "os.path.join" (the byte before it is a "."), and matchSanitizer takes the first match
	{"os.path.join", true, nil, "os.path.join does not remove traversal segments or stop traversal outside the base directory", false},
	{"path.join", true, nil, "path.join does not stop traversal outside the base directory", true},
	{"os.path.normpath", true, nil, "normpath does not stop traversal outside the base directory", true},
	{"os.path.realpath", true, nil, "realpath does not stop traversal outside the base directory", true},
	{"canonicalize", true, nil, "canonicalize does not stop traversal outside the base directory", true},
	{"strings.Replace", true, nil, "a string replace does not stop command injection", false},
	{"str.replace", true, nil, "a string replace does not stop command injection", false},
	{"url.Parse", true, nil, "url.Parse validates syntax, not the destination host", false},
	{"urlparse", true, nil, "urlparse validates syntax, not the destination host", false},

	{"filepath.Base", false, []string{"path_traversal"}, "stripping to the base filename discards any traversal segments", false},
	{"os.path.basename", false, []string{"path_traversal"}, "stripping to the base filename discards any traversal segments", false},
	{"path.Base", false, []string{"path_traversal"}, "stripping to the base filename discards any traversal segments", false},
	{"shlex.quote", false, []string{"command_injection"}, "quotes the whole argument for a single shell token", false},
}

// methodSanitizerPatterns match by final method name. maskStrongSanitizerCalls also applies strong
// entries inline without checking whether the callee resolves to an in-repo function, so a local
// same-named helper can mask taint.
var methodSanitizerPatterns = []sanitizerPattern{
	{"basename", false, []string{"path_traversal"}, "stripping to the base filename discards any traversal segments", false},
	{"resolve", true, nil, "resolving against a root does not stop a large enough .. sequence from walking outside it", true},
	{"replace", true, nil, "a string replace does not stop command injection", false},
	{"normalize", true, nil, "normalize does not stop traversal outside the base directory", true},
	{"toRealPath", true, nil, "toRealPath does not stop traversal outside the base directory", true},
}

func matchSanitizer(calleeText string) (sanitizerPattern, bool) {
	for _, p := range sanitizerPatterns {
		if mentionsIdent(calleeText, p.text) {
			return p, true
		}
	}
	return sanitizerPattern{}, false
}

// strongSanitizers is every strong (category-clearing) sanitizer, dotted and bare alike -
// used by maskStrongSanitizerCalls (walk.go) to blank out a strong sanitizer's arguments
// wherever its call appears inline inside a larger expression, not just when it is the
// direct right-hand side of an assignment
var strongSanitizers = collectStrongSanitizers()

func collectStrongSanitizers() []sanitizerPattern {
	var out []sanitizerPattern
	for _, p := range sanitizerPatterns {
		if !p.weak {
			out = append(out, p)
		}
	}
	for _, p := range methodSanitizerPatterns {
		if !p.weak {
			out = append(out, p)
		}
	}
	return out
}

func matchMethodSanitizer(calleeText string) (sanitizerPattern, bool) {
	last := parser.LastSegment(calleeText)
	for _, p := range methodSanitizerPatterns {
		if last == p.text {
			return p, true
		}
	}
	return sanitizerPattern{}, false
}

// sanitizerFor is the combined lookup handleAssign and handleCall both
// use: a dotted/qualified match always applies; a method-name-only match
// only applies once the callee is confirmed not to resolve to an in-repo
// symbol - see methodSanitizerPatterns
func sanitizerFor(calleeText string, resolvedInRepo bool) (sanitizerPattern, bool) {
	if san, ok := matchSanitizer(calleeText); ok {
		return san, true
	}
	if !resolvedInRepo {
		return matchMethodSanitizer(calleeText)
	}
	return sanitizerPattern{}, false
}

// decodingCalls turn escaped text back into path syntax. They are named exactly rather than
// matched by last segment on a generic name: a bare "decode" is bytes.decode, a JSON decode
// and a codec on every other line of ordinary code, and none of those reintroduce a
// traversal.
var decodingCalls = []string{
	"decodeURIComponent",
	"decodeURI",
	"unescape",
	"unquote",
	"unquote_plus",
	"QueryUnescape",
	"PathUnescape",
	"percent_decode",
}

// reintroducesPathSyntax reports whether calleeText is one of the decoders
// whose output can contain path syntax its input did not. Whatever a
// containment guard proved about the value before the call, it did not
// prove about the value after it.
func reintroducesPathSyntax(calleeText string) bool {
	last := parser.LastSegment(calleeText)
	return slices.Contains(decodingCalls, last)
}
