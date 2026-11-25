package taint

import (
	"fmt"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// classifyArgv distinguishes tainted program names, shell execution, and
// separate arguments. Unknown programs or option bags stay conservative at
// reduced confidence. A literal "--" protects later non-shell arguments.
func (c *ctx) classifyArgv(file string, kind argvKind, chain string, args []graph.Arg, tainted map[string]taintInfo) (category string, severity model.Severity, mult float64, note string, hit taintInfo, ok bool) {
	if kind == argvRustArg {
		// Command::new("markitdown").arg(source): when this call's own receiver chain starts at
		// Command::new with a literal program, the whole argv is readable here and is classified
		// like any other argv
		if argv, found := rustBuilderArgv(chain, args); found {
			return c.classifyArgv(file, argvGo, "", argv, tainted)
		}
		// The program that started this builder chain is a different call
		// node and is not visible from here
		if _, info, found := taintedArgIndex(args, tainted, ""); found {
			return "command_injection", model.SeverityHigh, 0.6,
				"the program name set earlier in the builder chain could not be resolved from this call, so shell-vs-argv could not be determined; treated conservatively",
				info, true
		}
		return "", "", 0, "", taintInfo{}, false
	}

	if len(args) == 0 {
		return "", "", 0, "", taintInfo{}, false
	}
	program, rest := args[0], args[1:]
	// Set when the argv array was handed over as a variable rather than
	// written out at the call site, so rest holds the array itself rather
	// than its elements. What is in it cannot be read here.
	opaqueArgv := false

	if kind == argvPython {
		if elems := bracketedListElements(program.Text); elems != nil {
			if len(elems) == 0 {
				return "", "", 0, "", taintInfo{}, false
			}
			program, rest = elems[0], elems[1:]
		}
		if hasShellTrue(args) {
			all := append([]graph.Arg{program}, rest...)
			if _, info, found := taintedArgIndex(all, tainted, ""); found {
				return "command_injection", model.SeverityHigh, 1,
					"shell=True hands the whole command to a shell interpreter", info, true
			}
			return "", "", 0, "", taintInfo{}, false
		}
	}

	if kind == argvNodeFile {
		// execFileSync(file, args, options) / spawnSync/spawn/execFile/fork(command, args,
		// options): the rest of the argv is the array in the second argument, not this call's own
		// remaining arguments
		rest = nil
		if len(args) > 1 {
			rest = bracketedListElements(args[1].Text)
			if rest == nil && !c.looksLikeOptionsBag(file, args[1]) {
				rest, opaqueArgv = []graph.Arg{args[1]}, true
			}
		}
		// spawn/execFile's options object can carry `shell: true` as a
		// field rather than a keyword argument - Node's counterpart to
		// Python's shell=True, hidden inside a positional literal instead
		// of named. hasShellTrue (which reads Arg.Keyword) cannot see it
		switch c.shellOptionOf(file, args) {
		case shellSet:
			all := append([]graph.Arg{program}, rest...)
			if _, info, found := taintedArgIndex(all, tainted, ""); found {
				return "command_injection", model.SeverityHigh, 1,
					"the shell option hands the whole command to a shell interpreter", info, true
			}
			return "", "", 0, "", taintInfo{}, false
		case shellUnreadable:
			all := append([]graph.Arg{program}, rest...)
			if _, info, found := taintedArgIndex(all, tainted, ""); found {
				return "command_injection", model.SeverityHigh, 0.7,
					"the options bag is not readable at this call site, so a shell option in it cannot be ruled out; treated conservatively", info, true
			}
			return "", "", 0, "", taintInfo{}, false
		}
	}

	program, rest = unwrapEnvPrefix(program, rest)
	if !program.Literal {
		// SHELL = "/bin/sh"; subprocess.run([SHELL, "-c", cmd]): a same-file string constant is as
		// good as the literal it holds
		if f := c.g.Files[file]; f != nil {
			if v, ok := f.Constants[strings.TrimSpace(program.Text)]; ok {
				program = graph.Arg{Text: program.Text, Literal: true, Value: v}
			}
		}
	}

	if info, found := mentionsAny(program.Text, tainted, ""); found {
		if spread := strings.TrimLeft(strings.TrimSpace(program.Text), "*."); spread != strings.TrimSpace(program.Text) && isPlainIdent(spread) {
			// create_subprocess_exec(*cmd), spawn(...argv): the whole argv arrives as one list built
			// elsewhere, so the tainted value may be the program, an option or a plain argument
			info.review = fmt.Sprintf("the argv list %s is unpacked into this call and built elsewhere, so whether the tainted value is the program, an option or a plain argument is unknown", spread)
			return "command_injection", model.SeverityHigh, 0.6,
				"the argv list is not written out at this call site; treated conservatively", info, true
		}
		if kind == argvPython && !program.Literal && isPlainIdent(strings.TrimSpace(program.Text)) && !strings.HasPrefix(strings.TrimSpace(program.Text), "[") {
			// subprocess.run(args) with args built where it could not be read: the tainted
			// value is somewhere in the list - the program, an option or a plain argument -
			// and which decides the issue
			info.review = fmt.Sprintf("the argv list %s is built where this call cannot read it, so whether the tainted value is the program, an option or a plain argument is unknown", strings.TrimSpace(program.Text))
			return "command_injection", model.SeverityHigh, 0.6,
				"the argv list is not written out at this call site; treated conservatively", info, true
		}
		return "command_injection", model.SeverityHigh, 1,
			"the program name itself is attacker-controlled", info, true
	}

	if program.Literal && shellInterpreters[programBasename(program.Value)] {
		if flagIdx := inlineCommandFlagIndex(rest); flagIdx >= 0 {
			if _, info, found := taintedArgIndex(rest, tainted, ""); found {
				return "command_injection", model.SeverityHigh, 1,
					fmt.Sprintf("%s runs an inline command through a shell", program.Value), info, true
			}
			return "", "", 0, "", taintInfo{}, false
		}
		if opaqueArgv {
			// The program is a shell and its argv cannot be read here, so
			// whether a "-c" sits in front of the tainted value is exactly
			// the thing that is unknown. Reporting the weaker category
			// would be picking the favourable half of that, the same way
			// an unreadable options bag is already treated.
			if _, info, found := taintedArgIndex(rest, tainted, ""); found {
				return "command_injection", model.SeverityHigh, 0.7,
					fmt.Sprintf("the argv handed to %s is not written out at this call site, so an inline-command flag in front of the tainted value cannot be ruled out; treated conservatively", program.Value),
					info, true
			}
			return "", "", 0, "", taintInfo{}, false
		}
	}

	if program.Literal && programBasename(program.Value) == "adb" {
		// adb [-s serial] shell <args...>: adb joins what follows "shell" into a command line for the
		// device's shell, the way ssh does on a remote host
		for i, a := range rest {
			if a.Literal && a.Value == "shell" {
				if _, info, found := taintedArgIndex(rest[i+1:], tainted, ""); found {
					return "command_injection", model.SeverityHigh, 1,
						"adb shell runs the arguments after it as a command line in the device's shell", info, true
				}
				break
			}
		}
	}

	if program.Literal && programBasename(program.Value) == "osascript" {
		// osascript -e <script>: each -e argument is one line of an AppleScript (or JXA) program,
		// and AppleScript runs shell commands with `do shell script`, so caller text inside it is
		// code, not an argument. A script file's own arguments (osascript f.scpt a b) stay
		// arguments and fall through.
		for i, a := range rest {
			if a.Literal && a.Value == "-e" && i+1 < len(rest) {
				if _, info, found := taintedArgIndex(rest[i+1:i+2], tainted, ""); found {
					// AppleScript text is usually built with its own string escaping (\ and ")
					// or JSON.stringify, which the scanner does not read as quoting for
					// AppleScript, so the finding goes to review rather than to potential
					if info.review == "" {
						info.review = "the caller's text is part of an AppleScript program run by osascript -e; whether it stays inside a correctly escaped AppleScript string literal (\\ and \" escaped) decides between code execution and a safe value"
					}
					return "command_injection", model.SeverityHigh, 1,
						"osascript -e runs its argument as AppleScript, which can run shell commands (do shell script)", info, true
				}
			}
		}
	}

	if program.Literal && programBasename(program.Value) == "ssh" {
		// ssh joins every argument after the destination into one string and hands it to a shell
		// on the remote host: those arguments are shell text there, whatever they look like here
		if _, info, found := taintedArgIndex(rest, tainted, ""); found {
			return "command_injection", model.SeverityHigh, 1,
				"ssh runs the arguments after the destination as a command line in a shell on the remote host", info, true
		}
		return "", "", 0, "", taintInfo{}, false
	}

	// A literal "--" ends option parsing for every POSIX-conventional program: nothing after it
	// can be read as a flag, no matter what it starts with, so a tainted value placed after one
	// cannot change the command's behavior by looking like one
	if ddIdx := literalDashDashIndex(rest); ddIdx >= 0 {
		rest = rest[:ddIdx]
	}

	if _, info, found := taintedArgIndex(rest, tainted, ""); found {
		if !program.Literal {
			// run(cmd, args) -> execFile(cmd, args): the program is a parameter or a variable the
			// caller fills. A shell with -c makes the tainted element a command line, any other
			// program an argument - which one decides the issue, and this call cannot tell
			if info.review == "" {
				info.review = fmt.Sprintf("the program %s is not written out at this call (a parameter or a variable): if it is a shell given -c, the tainted element is a command line, otherwise it is one argument to a program", strings.TrimSpace(program.Text))
			}
			return "command_injection", model.SeverityHigh, 0.6,
				"the program name was not statically resolvable, so it could not be ruled out as a shell asked to run an inline command",
				info, true
		}
		return "argument_injection", model.SeverityMedium, 1,
			fmt.Sprintf("the tainted value becomes a separate argument to %q, classified as argument injection rather than shell-interpreted text because %q is recognized as a non-shell program - not because shell metacharacters are inherently harmless in this position; a value beginning with \"-\" can still change the command's behavior", program.Value, program.Value),
			info, true
	}
	return "", "", 0, "", taintInfo{}, false
}

// rustCommandNew matches a builder chain that starts at Command::new with a literal program:
// Command::new("git"), std::process::Command::new("git"), tokio::process::Command::new("git")
var rustCommandNew = regexp.MustCompile(`^\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*Command::new\(`)

// rustBuilderArgv reads the argv of a Rust Command builder from the callee text of one of its
// .arg()/.args() calls - `Command::new("sh").arg("-c").arg` - plus that call's own arguments. It
// returns the program, every earlier .arg/.args element and this call's elements, in order. Other
// builder methods (current_dir, env, stdout, ...) add nothing to the argv and are skipped. It
// reports false when the chain does not start at Command::new with a literal program on this
// call's own receiver - a Command held in a variable, or a chain it cannot read.
func rustBuilderArgv(chain string, args []graph.Arg) ([]graph.Arg, bool) {
	loc := rustCommandNew.FindStringIndex(chain)
	if loc == nil {
		return nil, false
	}
	open := loc[1] - 1
	inner := bracketedParen(chain, open)
	prog, ok := parser.UnquoteString(strings.TrimSpace(inner))
	if !ok || prog == "" {
		return nil, false
	}
	argv := []graph.Arg{{Text: strings.TrimSpace(inner), Literal: true, Value: prog}}
	elems := func(method, text string) []graph.Arg {
		text = strings.TrimSpace(text)
		if method == "arg" {
			if v, ok := parser.UnquoteString(text); ok {
				return []graph.Arg{{Text: text, Literal: true, Value: v}}
			}
			return []graph.Arg{{Text: text}}
		}
		list := strings.TrimPrefix(strings.TrimPrefix(text, "&"), "vec!")
		if es := bracketedListElements(list); es != nil {
			return es
		}
		return []graph.Arg{{Text: text}}
	}
	// skip ")" closing Command::new(...)
	rest := chain[open+len(inner)+2:]
	for {
		rest = strings.TrimLeft(rest, " \t\r\n")
		if rest == "" {
			return nil, false
		}
		if rest[0] != '.' {
			return nil, false
		}
		i := 1
		for i < len(rest) && (rest[i] == '_' || rest[i] >= 'a' && rest[i] <= 'z' || rest[i] >= 'A' && rest[i] <= 'Z' || rest[i] >= '0' && rest[i] <= '9') {
			i++
		}
		method := rest[1:i]
		tail := strings.TrimLeft(rest[i:], " \t\r\n")
		if tail == "" {
			// the call this callee text belongs to: its own arguments end the argv
			if method != "arg" && method != "args" {
				return nil, false
			}
			for _, a := range args {
				argv = append(argv, elems(method, a.Text)...)
			}
			return argv, true
		}
		if tail[0] != '(' {
			return nil, false
		}
		in := bracketedParen(tail, 0)
		if method == "arg" || method == "args" {
			argv = append(argv, elems(method, in)...)
		}
		rest = tail[len(in)+2:]
	}
}

// programBasename reduces a program path to the bare name classification matches
// shellInterpreters against: "/bin/sh" and "sh" (and, on Windows,
// "C:\\Windows\\System32\\cmd.exe" and "cmd") all resolve to the same interpreter name
func programBasename(v string) string {
	v = strings.ToLower(v)
	if i := strings.LastIndexAny(v, `/\`); i >= 0 {
		v = v[i+1:]
	}
	return strings.TrimSuffix(v, ".exe")
}

// unwrapEnvPrefix treats a literal "env" program as transparent: env runs whatever program
// follows its own leading NAME=value assignments, so classification should look at that
// program, not at "env" itself
func unwrapEnvPrefix(program graph.Arg, rest []graph.Arg) (graph.Arg, []graph.Arg) {
	if !program.Literal || programBasename(program.Value) != "env" {
		return program, rest
	}
	i := 0
	for i < len(rest) && rest[i].Literal && isEnvAssignment(rest[i].Value) {
		i++
	}
	if i >= len(rest) {
		return program, rest
	}
	return rest[i], rest[i+1:]
}

func isEnvAssignment(v string) bool {
	eq := strings.IndexByte(v, '=')
	return eq > 0
}

// inlineCommandFlagIndex returns the index in rest of the first inline-command flag for a
// known shell - an exact flag (-c, /c, -command) or a clustered POSIX short-option group
// that includes c (-lc, -ec, -euc, the login/errexit/nounset-plus-c combinations real
// scripts actually write), scanning the whole argv rather than requiring it at position 0 -
// or -1 when rest carries none
func inlineCommandFlagIndex(rest []graph.Arg) int {
	for i, a := range rest {
		if !a.Literal {
			continue
		}
		if shellInlineFlags[strings.ToLower(a.Value)] || isClusteredCFlag(a.Value) {
			return i
		}
	}
	return -1
}

// isClusteredCFlag reports whether v is a POSIX clustered short-option
// group that includes "c" - "-lc", "-ec", "-euc" and similar. Shell flags
// are case-sensitive (bash's -c and -C mean different things), so unlike
// shellInlineFlags's exact-match lookup this does not lowercase v first.
func isClusteredCFlag(v string) bool {
	if len(v) < 2 || v[0] != '-' || v[1] == '-' {
		return false
	}
	hasC := false
	for _, r := range v[1:] {
		if r < 'a' || r > 'z' {
			return false
		}
		if r == 'c' {
			hasC = true
		}
	}
	return hasC
}

// literalDashDashIndex returns the index of a literal "--" element in
// args, or -1 when there is none
func literalDashDashIndex(args []graph.Arg) int {
	for i, a := range args {
		if a.Literal && a.Value == "--" {
			return i
		}
	}
	return -1
}

func hasShellTrue(args []graph.Arg) bool {
	for _, a := range args {
		if strings.EqualFold(a.Keyword, "shell") && strings.EqualFold(strings.TrimSpace(a.Text), "true") {
			return true
		}
	}
	return false
}

// shellOption is what an argv call's options bag says about running the
// command through a shell
type shellOption int

const (
	// shellNone is no options bag, or one whose shell field is explicitly
	// off
	shellNone shellOption = iota
	// shellSet is a shell field Node runs a shell for
	shellSet
	// shellUnreadable is an options bag whose contents are not at the call
	// site - a bare identifier that no file-level object literal defines
	shellUnreadable
)

// shellOptionOf reads the options bag of a Node spawn/execFile-style call. An unresolved options
// variable returns shellUnreadable so classification stays conservative instead of assuming no shell.
func (c *ctx) shellOptionOf(file string, args []graph.Arg) shellOption {
	if len(args) < 3 {
		return shellNone
	}
	out := shellNone
	for _, a := range args[2:] {
		t := strings.TrimSpace(a.Text)
		if !a.Literal && isIdentifierText(t) {
			if obj, ok := c.objects[fileAlias{file: file, name: t}]; ok {
				t = obj
			} else {
				out = shellUnreadable
				continue
			}
		}
		if len(t) < 2 || t[0] != '{' || t[len(t)-1] != '}' {
			continue
		}
		for _, part := range parser.SplitTopLevel(t[1 : len(t)-1]) {
			part = strings.TrimSpace(part)
			i := strings.IndexByte(part, ':')
			if i < 0 {
				continue
			}
			key := strings.Trim(strings.TrimSpace(part[:i]), `"'`)
			if key != "shell" {
				continue
			}
			switch strings.TrimSpace(part[i+1:]) {
			case "false", "undefined", "null":
			default:
				return shellSet
			}
		}
	}
	return out
}

// bracketedListElements splits a Python list literal's or a JS/TS array literal's raw
// source text ("[\"tar\", \"czf\", name]" - the two are close enough syntactically for one
// comma/bracket/quote-aware splitter to handle both) into one Arg per top-level element
func bracketedListElements(text string) []graph.Arg {
	t := strings.TrimSpace(text)
	if len(t) < 2 || t[0] != '[' || t[len(t)-1] != ']' {
		return nil
	}

	parts := parser.SplitTopLevel(t[1 : len(t)-1])
	out := make([]graph.Arg, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if v, ok := parser.UnquoteString(p); ok {
			out = append(out, graph.Arg{Text: p, Literal: true, Value: v})
		} else {
			out = append(out, graph.Arg{Text: p})
		}
	}
	return out
}

// looksLikeOptionsBag reports whether an argument is the options object of a child_process
// call rather than its argv array
func (c *ctx) looksLikeOptionsBag(file string, a graph.Arg) bool {
	t := strings.TrimSpace(a.Text)
	if !a.Literal && isIdentifierText(t) {
		if obj, ok := c.objects[fileAlias{file: file, name: t}]; ok {
			t = strings.TrimSpace(obj)
		}
	}
	return len(t) >= 2 && t[0] == '{' && t[len(t)-1] == '}'
}

// expandArgvVar reads a Python argv list handed to subprocess as a variable from the statements
// that build it earlier in the same function: args = [prog, "-x"], then args += [...],
// args.append(x), args.extend([...]). A literal "--" added inside a block deeper than the call is
// conditional, so it is not trusted to end option parsing. Anything else that changes the list
// (insert, a reassignment that is not a list literal) leaves the call as written.
func (c *ctx) expandArgvVar(pf *parsedFile, call *sitter.Node, kind argvKind, args []graph.Arg) []graph.Arg {
	if kind != argvPython || len(args) == 0 || call == nil {
		return args
	}
	name := strings.TrimSpace(args[0].Text)
	if !isPlainIdent(name) {
		return args
	}
	fn := call.Parent()
	for fn != nil && fn.Kind() != "function_definition" {
		fn = fn.Parent()
	}
	if fn == nil {
		return args
	}
	src := pf.src
	body := string(src[fn.StartByte():call.StartByte()])
	callLine := strings.LastIndexByte(string(src[:call.StartByte()]), '\n')
	callIndent := indentOf(string(src[callLine+1 : call.StartByte()]))
	q := regexp.QuoteMeta(name)
	stmt := regexp.MustCompile(`(?m)^([ \t]*)` + q + `\s*(=|\+=)\s*\[|^([ \t]*)` + q + `\.(append|extend|insert)\(|^[ \t]*` + q + `\s*=`)
	var elems []graph.Arg
	started := false
	for _, m := range stmt.FindAllStringSubmatchIndex(body, -1) {
		text := body[m[0]:m[1]]
		indent := ""
		if m[2] >= 0 {
			indent = body[m[2]:m[3]]
		} else if m[6] >= 0 {
			indent = body[m[6]:m[7]]
		}
		conditional := len(indent) > len(callIndent)
		switch {
		case strings.HasSuffix(strings.TrimSpace(text), "[") && strings.Contains(text, "+="):
			if !started {
				return args
			}
			list := bracketed(body, m[1]-1)
			if list == "" {
				return args
			}
			elems = append(elems, guardDashDash(bracketedListElements(list), conditional)...)
		case strings.HasSuffix(strings.TrimSpace(text), "["):
			list := bracketed(body, m[1]-1)
			if list == "" || conditional {
				return args
			}
			elems, started = bracketedListElements(list), true
		case strings.HasSuffix(text, ".append("):
			inner := bracketedParen(body, m[1]-1)
			if !started || inner == "" {
				return args
			}
			elems = append(elems, guardDashDash(bracketedListElements("["+inner+"]"), conditional)...)
		case strings.HasSuffix(text, ".extend("):
			inner := strings.TrimSpace(bracketedParen(body, m[1]-1))
			if !started || !strings.HasPrefix(inner, "[") {
				return args
			}
			elems = append(elems, guardDashDash(bracketedListElements(inner), conditional)...)
		default:
			// insert, or a reassignment that is not a list literal: the order is not readable
			return args
		}
	}
	if !started || len(elems) == 0 {
		return args
	}
	return append([]graph.Arg{{Text: "[" + joinArgText(elems) + "]"}}, args[1:]...)
}

func indentOf(s string) string {
	return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
}

// guardDashDash drops a conditional "--": it may not be there when the call runs
func guardDashDash(es []graph.Arg, conditional bool) []graph.Arg {
	if !conditional {
		return es
	}
	out := es[:0:0]
	for _, e := range es {
		if e.Literal && e.Value == "--" {
			continue
		}
		out = append(out, e)
	}
	return out
}

func joinArgText(es []graph.Arg) string {
	parts := make([]string, len(es))
	for i, e := range es {
		parts[i] = e.Text
	}
	return strings.Join(parts, ", ")
}

// bracketed returns the text of the [...] starting at open, or "" when it does not close
func bracketed(s string, open int) string { return balanced(s, open, '[', ']', true) }

// bracketedParen returns the text inside the (...) starting at open
func bracketedParen(s string, open int) string { return balanced(s, open, '(', ')', false) }

func balanced(s string, open int, l, r byte, keep bool) string {
	if open < 0 || open >= len(s) || s[open] != l {
		return ""
	}
	depth := 0
	var quote byte
	for i := open; i < len(s); i++ {
		ch := s[i]
		if quote != 0 {
			if ch == '\\' {
				i++
			} else if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '"', '\'':
			quote = ch
		case l:
			depth++
		case r:
			depth--
			if depth == 0 {
				if keep {
					return s[open : i+1]
				}
				return s[open+1 : i]
			}
		}
	}
	return ""
}
