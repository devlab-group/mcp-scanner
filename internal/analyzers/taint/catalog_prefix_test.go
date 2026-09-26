package taint

import "testing"

func isUnboundedPrefix(short, long string) bool {
	if len(long) <= len(short) || long[:len(short)] != short {
		return false
	}
	return isIdentByte(long[len(short)])
}

// prefixPairs finds every (short, long) pair within one catalogue table
// where short.text is an unbounded prefix of long.text
func prefixPairs(texts []string) map[[2]string]bool {
	pairs := map[[2]string]bool{}
	for _, a := range texts {
		for _, b := range texts {
			if a != b && isUnboundedPrefix(a, b) {
				pairs[[2]string{a, b}] = true
			}
		}
	}
	return pairs
}

func textsOf[T any](patterns []T, text func(T) string) []string {
	out := make([]string, len(patterns))
	for i, p := range patterns {
		out[i] = text(p)
	}
	return out
}

var knownSinkPatternPrefixPairs = map[[2]string]bool{
	{"exec", "execSync"}:                               true,
	{"exec", "execa"}:                                  true,
	{"exec", "execaCommand"}:                           true,
	{"execa", "execaCommand"}:                          true,
	{"os.spawnl", "os.spawnle"}:                        true,
	{"os.spawnl", "os.spawnlp"}:                        true,
	{"os.spawnl", "os.spawnlpe"}:                       true,
	{"os.spawnlp", "os.spawnlpe"}:                      true,
	{"os.spawnv", "os.spawnve"}:                        true,
	{"os.spawnv", "os.spawnvp"}:                        true,
	{"os.spawnv", "os.spawnvpe"}:                       true,
	{"os.spawnvp", "os.spawnvpe"}:                      true,
	{"os.Open", "os.OpenFile"}:                         true,
	{"os.Create", "os.CreateTemp"}:                     true,
	{"os.Remove", "os.RemoveAll"}:                      true,
	{"os.remove", "os.removedirs"}:                     true,
	{"os.rename", "os.renames"}:                        true,
	{"shutil.copy", "shutil.copy2"}:                    true,
	{"shutil.copy", "shutil.copyfile"}:                 true,
	{"shutil.copy", "shutil.copyfileobj"}:              true,
	{"shutil.copy", "shutil.copytree"}:                 true,
	{"shutil.copyfile", "shutil.copyfileobj"}:          true,
	{"std::fs::read", "std::fs::read_to_string"}:       true,
	{"http.NewRequest", "http.NewRequestWithContext"}:  true,
	{"net.Dial", "net.DialTimeout"}:                    true,
	{"Files.write", "Files.writeString"}:               true,
	{"yaml.load", "yaml.load_all"}:                     true,
	{"os.Mkdir", "os.MkdirAll"}:                        true,
	{"filepath.Walk", "filepath.WalkDir"}:              true,
	{"std::fs::read", "std::fs::read_dir"}:             true,
	{"std::fs::create_dir", "std::fs::create_dir_all"}: true,
}

var knownArgvSinkPrefixPairs = map[[2]string]bool{
	{"execFile", "execFileSync"}: true,
	{"os.execv", "os.execvp"}:    true,
	{"spawn", "spawnSync"}:       true,
	{"os.execl", "os.execle"}:    true,
	{"os.execl", "os.execlp"}:    true,
	{"os.execl", "os.execlpe"}:   true,
	{"os.execlp", "os.execlpe"}:  true,
}

func TestCatalog_KnownPrefixPairs(t *testing.T) {
	cases := []struct {
		name  string
		texts []string
		known map[[2]string]bool
	}{
		{"sinkPatterns", textsOf(sinkPatterns, func(p sinkPattern) string { return p.text }), knownSinkPatternPrefixPairs},
		{"sourcePatterns", textsOf(sourcePatterns, func(p sourcePattern) string { return p.text }), nil},
		{"sanitizerPatterns", textsOf(sanitizerPatterns, func(p sanitizerPattern) string { return p.text }), nil},
		{"argvSinks", textsOf(argvSinks, func(p argvSink) string { return p.text }), knownArgvSinkPrefixPairs},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := prefixPairs(c.texts)
			for pair := range got {
				if !c.known[pair] {
					t.Errorf("%q is an unacknowledged unbounded prefix of %q in %s: mentionsIdent's word boundary means %q never matches a call to %q at all. Add {%q, %q} to this test's known*PrefixPairs map once you have checked whether the same module has yet another sibling with this prefix that also needs its own entry too.",
						pair[0], pair[1], c.name, pair[0], pair[1], pair[0], pair[1])
				}
			}
			for pair := range c.known {
				if !got[pair] {
					t.Errorf("this test's known*PrefixPairs map has %q -> %q but %s no longer contains both texts; remove the stale entry", pair[0], pair[1], c.name)
				}
			}
		})
	}
}
