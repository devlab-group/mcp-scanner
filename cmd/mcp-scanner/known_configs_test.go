package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/revinand/mcp-scanner/internal/policy"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func TestParseClientConfigDirectShape(t *testing.T) {
	data := []byte(`{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "server-fs"]}, "remote": {"url": "https://example.com/mcp"}}}`)
	got, err := parseClientConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d servers, want 2", len(got))
	}
	if got["fs"].toTarget("fs").Kind != model.TargetStdio {
		t.Fatal("a command-only entry should become a stdio target")
	}
	if got["remote"].toTarget("remote").Kind != model.TargetRemote {
		t.Fatal("a url entry should become a remote target")
	}
}

// Preserve remote authorization headers without serializing them
func TestParseClientConfigCarriesHeadersToTarget(t *testing.T) {
	data := []byte(`{"mcpServers": {"remote": {"url": "https://example.com/mcp", "headers": {"Authorization": "Bearer secret"}}}}`)
	got, err := parseClientConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	target := got["remote"].toTarget("remote")
	if target.Headers["Authorization"] != "Bearer secret" {
		t.Fatalf("Headers = %v, want the declared Authorization header carried through", target.Headers)
	}
}

// Preserve a supported remote transport declared by the client
func TestToTargetMapsDeclaredTransport(t *testing.T) {
	cases := []struct {
		typ  string
		want string
	}{
		{"http", "streamable"},
		{"streamable-http", "streamable"},
		{"sse", "sse"},
		{"bogus", ""},
		{"", ""},
	}
	for _, c := range cases {
		s := rawServer{URL: "https://example.com/mcp", Type: c.typ}
		got := s.toTarget("remote").Transport
		if got != c.want {
			t.Errorf("type %q: Transport = %q, want %q", c.typ, got, c.want)
		}
	}
}

// An incompatible type on a URL target must fall back to automatic detection
func TestToTargetIgnoresStdioTypeOnAURLEntry(t *testing.T) {
	s := rawServer{URL: "https://example.com/mcp", Type: "stdio"}
	target := s.toTarget("remote")
	if target.Kind != model.TargetRemote {
		t.Fatalf("Kind = %v, want remote: a url entry stays remote regardless of type", target.Kind)
	}
	if target.Transport != "" {
		t.Fatalf("Transport = %q, want \"\" (auto): a stdio type cannot apply to a url-bearing entry", target.Transport)
	}
}

// A type field cannot move a command-only target away from stdio
func TestToTargetLeavesStdioEntryTransportEmpty(t *testing.T) {
	for _, typ := range []string{"stdio", "http", "sse", "streamable-http", "bogus", ""} {
		s := rawServer{Command: "npx", Type: typ}
		target := s.toTarget("fs")
		if target.Kind != model.TargetStdio {
			t.Fatalf("type %q: Kind = %v, want stdio", typ, target.Kind)
		}
		if target.Transport != "" {
			t.Fatalf("type %q: Transport = %q, want \"\": a stdio target's transport is decided by its Kind, not this field", typ, target.Transport)
		}
	}
}

func TestParseClientConfigNestedShape(t *testing.T) {
	data := []byte(`{"mcp": {"servers": {"fs": {"command": "node", "args": ["server.js"]}}}}`)
	got, err := parseClientConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d servers, want 1", len(got))
	}
}

// A valid config with no MCP section returns no servers and no error
func TestParseClientConfigNoMCPSectionIsNotAnError(t *testing.T) {
	got, err := parseClientConfig([]byte(`{"unrelated": true}`))
	if err != nil {
		t.Fatalf("expected no error for a file with no mcpServers/mcp.servers section, got %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d servers, want 0", len(got))
	}
}

// Strip JSONC comments and trailing commas without changing string content
func TestStripJSONCommentsHandlesVSCodeSettings(t *testing.T) {
	input := `{
  // a leading comment
  "mcp": {
    "servers": {
      "fs": {
        "url": "https://example.com/mcp", // trailing comment after a URL
        "args": ["-y", "server-fs",],
      },
    },
  },
  /* a block
     comment */
  "note": "contains /* not a real comment */ inside a string",
}`
	stripped := stripJSONComments([]byte(input))
	var out map[string]any
	if err := json.Unmarshal(stripped, &out); err != nil {
		t.Fatalf("stripped input did not parse as JSON: %v\n%s", err, stripped)
	}
	mcp, _ := out["mcp"].(map[string]any)
	servers, _ := mcp["servers"].(map[string]any)
	fs, _ := servers["fs"].(map[string]any)
	if fs["url"] != "https://example.com/mcp" {
		t.Fatalf("url = %v, want the URL with its // intact", fs["url"])
	}
	args, _ := fs["args"].([]any)
	if len(args) != 2 {
		t.Fatalf("args = %v, want 2 entries (trailing comma dropped)", args)
	}
	if out["note"] != "contains /* not a real comment */ inside a string" {
		t.Fatalf("note = %v, want the string's /* left alone", out["note"])
	}
}

// parseClientConfig expects strict JSON; discovery handles VS Code JSONC first
func TestParseClientConfigRejectsJSONCDirectly(t *testing.T) {
	_, err := parseClientConfig([]byte(`{"mcpServers": {"fs": {"command": "npx"}}, // comment
}`))
	if _, ok := errors.AsType[unreadableConfigError](err); !ok {
		t.Fatalf("expected an unreadableConfigError for unstripped JSONC, got %v (%T)", err, err)
	}
}

// Invalid JSON must be marked unreadable, not reported as an empty config
func TestParseClientConfigInvalidJSONIsUnreadable(t *testing.T) {
	_, err := parseClientConfig([]byte(`{"mcpServers": {"evil": {"command": "sh", "args": ["-c", "x`))
	if err == nil {
		t.Fatal("expected an error for a truncated file")
	}
	if _, ok := errors.AsType[unreadableConfigError](err); !ok {
		t.Fatalf("expected an unreadableConfigError, got %v (%T)", err, err)
	}
}

// A malformed MCP section is a parse failure, not an empty config
func TestParseClientConfigMalformedMCPServersIsUnreadable(t *testing.T) {
	_, err := parseClientConfig([]byte(`{"mcpServers": "not an object"}`))
	if err == nil {
		t.Fatal("expected an error for a malformed mcpServers entry")
	}
	if _, ok := errors.AsType[unreadableConfigError](err); !ok {
		t.Fatalf("expected an unreadableConfigError, got %v (%T)", err, err)
	}
}

// Sanitize config-controlled fields so they cannot forge output lines
func TestPrintDiscoveredSanitizesHostileFields(t *testing.T) {
	servers := []discoveredServer{{
		Name:   "evil\nskipped: nothing to see here",
		Source: "~/.config/Claude/claude_desktop_config.json\tINJECTED",
		Target: model.Target{Kind: model.TargetStdio, Command: "sh"},
	}}
	var buf bytes.Buffer
	printDiscovered(&buf, servers, nil)

	if strings.Contains(buf.String(), "\n\nskipped") || strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("hostile Name forged an extra line: %q", buf.String())
	}
	if !strings.Contains(buf.String(), `\x0a`) {
		t.Fatalf("expected the embedded newline to show up escaped: %q", buf.String())
	}
}

// One output file must retain results for every discovered server
func TestScanDiscoveredServersReportsEveryServerNotJustTheLast(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{
			Analyzer: "a", Status: model.AnalyzerCompleted, Required: true,
			Coverage: model.Coverage{CapabilitiesDiscovered: 1, CapabilitiesAnalyzed: 1},
		}
	}})
	servers := []discoveredServer{
		{Name: "one", Source: "cfg", Target: model.Target{Kind: model.TargetRemote, Name: "one", URL: "https://one.example/mcp"}},
		{Name: "two", Source: "cfg", Target: model.Target{Kind: model.TargetRemote, Name: "two", URL: "https://two.example/mcp"}},
	}

	t.Run("json", func(t *testing.T) {
		r := baseResolved(t)
		r.format = "json"
		r.output = filepath.Join(t.TempDir(), "out.json")

		code, err := scanDiscoveredServers(context.Background(), &bytes.Buffer{}, sc, r, servers, false, false)
		if err != nil {
			t.Fatal(err)
		}
		if code != policy.ExitOK {
			t.Fatalf("code = %d, want ExitOK", code)
		}

		data, err := os.ReadFile(r.output)
		if err != nil {
			t.Fatal(err)
		}
		var results []model.ScanResult
		if err := json.Unmarshal(data, &results); err != nil {
			t.Fatalf("output is not a JSON array: %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("report has %d results, want 2 (one per server): %s", len(results), data)
		}
	})

	t.Run("summary", func(t *testing.T) {
		r := baseResolved(t)
		r.format = "summary"
		r.output = filepath.Join(t.TempDir(), "out.txt")

		if _, err := scanDiscoveredServers(context.Background(), &bytes.Buffer{}, sc, r, servers, false, false); err != nil {
			t.Fatal(err)
		}

		data, err := os.ReadFile(r.output)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"one", "two"} {
			if !strings.Contains(string(data), name) {
				t.Fatalf("report is missing server %q, only one server's report survived:\n%s", name, data)
			}
		}
	})
}

// A fully skipped run is incomplete and must not truncate an existing report
func TestScanDiscoveredServersLeavesOutputAloneWhenNothingRuns(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{Analyzer: "a", Status: model.AnalyzerCompleted, Required: true}
	}})
	path := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(path, []byte("pre-existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := baseResolved(t)
	r.format = "json"
	r.output = path

	servers := []discoveredServer{
		{Name: "stdio-only", Source: "cfg", Target: model.Target{Kind: model.TargetStdio, Name: "stdio-only", Command: "sh"}},
	}
	code, err := scanDiscoveredServers(context.Background(), &bytes.Buffer{}, sc, r, servers, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if code != policy.ExitIncomplete {
		t.Fatalf("code = %d, want ExitIncomplete: nothing was scanned, which a pipeline must not read as OK", code)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "pre-existing" {
		t.Fatalf("output file was touched despite nothing being scanned: %q", data)
	}
}

// A valid config with no servers is complete and exits successfully
func TestScanDiscoveredServersExitsOKWhenTrulyNoServers(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{Analyzer: "a", Status: model.AnalyzerCompleted, Required: true}
	}})
	r := baseResolved(t)
	r.format = "json"
	r.output = filepath.Join(t.TempDir(), "out.json")

	code, err := scanDiscoveredServers(context.Background(), &bytes.Buffer{}, sc, r, nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if code != policy.ExitOK {
		t.Fatalf("code = %d, want ExitOK: an empty server list is not the same as a skipped one", code)
	}
}

// Any skipped stdio target makes the combined run incomplete
func TestScanDiscoveredServersExitIncompleteWhenSomeStdioSkippedAlongsideAScan(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{
			Analyzer: "a", Status: model.AnalyzerCompleted, Required: true,
			Coverage: model.Coverage{CapabilitiesDiscovered: 1, CapabilitiesAnalyzed: 1},
		}
	}})
	servers := []discoveredServer{
		{Name: "stdio-only", Source: "cfg", Target: model.Target{Kind: model.TargetStdio, Name: "stdio-only", Command: "sh"}},
		{Name: "remote-ok", Source: "cfg", Target: model.Target{Kind: model.TargetRemote, Name: "remote-ok", URL: "https://ok.example/mcp"}},
	}
	r := baseResolved(t)
	r.format = "json"
	r.output = filepath.Join(t.TempDir(), "out.json")

	code, err := scanDiscoveredServers(context.Background(), &bytes.Buffer{}, sc, r, servers, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if code != policy.ExitIncomplete {
		t.Fatalf("code = %d, want ExitIncomplete: a scanned server passing must not hide a skipped one", code)
	}
}

// Guard every config-controlled print site with report.Sanitize
func TestKnownConfigsSourcePrintsOnlySanitizedFields(t *testing.T) {
	src, err := os.ReadFile("cmd_known_configs.go")
	if err != nil {
		t.Fatal(err)
	}
	field := regexp.MustCompile(`\bs\.(Name|Source)\b`)
	for _, loc := range field.FindAllStringIndex(string(src), -1) {
		before := string(src[:loc[0]])
		if !strings.HasSuffix(before, "report.Sanitize(") {
			t.Fatalf("found a print site that does not wrap s.Name/s.Source in report.Sanitize: ...%s", src[max(0, loc[0]-40):loc[1]])
		}
	}
}

// Sanitize scan errors consistently with adjacent config-controlled output
func TestKnownConfigsScanErrorIsSanitized(t *testing.T) {
	src, err := os.ReadFile("cmd_known_configs.go")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`report\.Sanitize\(scanErr\.Error\(\)\)`).Match(src) {
		t.Fatal("expected scanErr to be printed through report.Sanitize, like every other value in this file")
	}
}

// Discovery must distinguish corrupt files from valid configs with servers
func TestDiscoverConfiguredServersReportsUnreadableConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	claudeDir := filepath.Join(home, ".config", "Claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "claude_desktop_config.json"),
		[]byte(`{"mcpServers": {"evil": {"command": "sh", "args": ["-c", "x`), 0o644); err != nil {
		t.Fatal(err)
	}
	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cursorDir, "mcp.json"),
		[]byte(`{"mcpServers": {"docs": {"command": "python3", "args": ["-m", "docs_server"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	servers, skipped, unreadable := discoverConfiguredServers()
	if !unreadable {
		t.Fatal("want unreadable=true: one of the two config files is not valid JSON")
	}
	if len(servers) != 1 || servers[0].Name != "docs" {
		t.Fatalf("servers = %+v, want the one server the valid file declares", servers)
	}
	named := false
	for _, s := range skipped {
		if strings.Contains(s, "claude_desktop_config.json") {
			named = true
		}
	}
	if !named {
		t.Fatalf("the unreadable file is not named among the skipped ones: %q", skipped)
	}
}

// Discovery accepts comments in VS Code settings.json
func TestDiscoverConfiguredServersReadsVSCodeJSONC(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	codeDir := filepath.Join(home, ".config", "Code", "User")
	if err := os.MkdirAll(codeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{
  // MCP servers for this workspace
  "mcp": {
    "servers": {
      "fs": {
        "command": "npx",
        "args": ["-y", "server-fs"],
      },
    },
  },
}`
	if err := os.WriteFile(filepath.Join(codeDir, "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}

	servers, skipped, unreadable := discoverConfiguredServers()
	if unreadable {
		t.Fatalf("a JSONC settings.json with one comment must not be unreadable, skipped = %v", skipped)
	}
	if len(servers) != 1 || servers[0].Name != "fs" {
		t.Fatalf("servers = %+v, want the one server declared past the comment", servers)
	}
}

// A config without an MCP section is not reported as skipped
func TestDiscoverConfiguredServersDoesNotReportOrdinaryEmptyConfigAsSkipped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	codeDir := filepath.Join(home, ".config", "Code", "User")
	if err := os.MkdirAll(codeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codeDir, "settings.json"),
		[]byte(`{"editor.fontSize": 14}`), 0o644); err != nil {
		t.Fatal(err)
	}

	servers, skipped, unreadable := discoverConfiguredServers()
	if len(servers) != 0 {
		t.Fatalf("servers = %+v, want none", servers)
	}
	if unreadable {
		t.Fatal("an ordinary settings.json with no MCP section is not unreadable")
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v, want none: a config file with no MCP section was never skipped, there was nothing to skip", skipped)
	}
}

// A parse failure makes the run incomplete even if another server was scanned
func TestScanDiscoveredServersExitIncompleteWhenConfigUnreadable(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{Analyzer: "a", Status: model.AnalyzerCompleted, Required: true}
	}})
	r := baseResolved(t)
	r.format = "json"
	r.output = filepath.Join(t.TempDir(), "out.json")

	code, err := scanDiscoveredServers(context.Background(), &bytes.Buffer{}, sc, r, nil, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if code != policy.ExitIncomplete {
		t.Fatalf("code = %d, want ExitIncomplete: a config file failed to parse, so this scanned nothing and cannot claim OK", code)
	}
}

func TestScanDiscoveredServersFoldsUnreadableIntoWorstAlongsideAScan(t *testing.T) {
	sc := scannerWith(fakeAnalyzer{"a", func() model.AnalyzerResult {
		return model.AnalyzerResult{
			Analyzer: "a", Status: model.AnalyzerCompleted, Required: true,
			Coverage: model.Coverage{CapabilitiesDiscovered: 1, CapabilitiesAnalyzed: 1},
		}
	}})
	servers := []discoveredServer{
		{Name: "remote-ok", Source: "cfg", Target: model.Target{Kind: model.TargetRemote, Name: "remote-ok", URL: "https://ok.example/mcp"}},
	}
	r := baseResolved(t)
	r.format = "json"
	r.output = filepath.Join(t.TempDir(), "out.json")

	code, err := scanDiscoveredServers(context.Background(), &bytes.Buffer{}, sc, r, servers, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if code != policy.ExitIncomplete {
		t.Fatalf("code = %d, want ExitIncomplete: a clean scanned server must not hide a config file that failed to parse", code)
	}
}

// The JSONC stripper must preserve all string bytes in untrusted client configs
func TestStripJSONCommentsLeavesStrictJSONMeaningAlone(t *testing.T) {
	cases := []string{
		`{"mcpServers":{"fs":{"command":"node","args":["a","b"],"env":{"K":"V"}}}}`,
		// Escaped quote followed by a backslash and the closing quote
		`{"a":"he said \"hi\"","b":"ends with a backslash\\","c":1}`,
		// Comment markers inside strings
		`{"url":"https://example.com//mcp","note":"/* not a comment */ // nor this"}`,
		// Structural characters inside strings
		`{"cmd":"sh -c 'x, y}' ","servers":{"a":1,"b":2}}`,
		`{"list":[1,2,3],"obj":{"k":"v"}}`,
	}
	for _, in := range cases {
		var want, got any
		if err := json.Unmarshal([]byte(in), &want); err != nil {
			t.Fatalf("the case itself is not valid JSON: %s", in)
		}
		stripped := stripJSONComments([]byte(in))
		if err := json.Unmarshal(stripped, &got); err != nil {
			t.Errorf("strict JSON stopped parsing after stripping:\n in: %s\nout: %s\nerr: %v", in, stripped, err)
			continue
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("stripping changed what the file declares:\n in: %s\nout: %s", in, stripped)
		}
	}
}

// An unterminated string must remain invalid without stripping its contents
func TestStripJSONCommentsRefusesToGuessAtAnUnterminatedString(t *testing.T) {
	stripped := stripJSONComments([]byte(`{"mcpServers":{"fs":{"command":"node}`))
	var v any
	if err := json.Unmarshal(stripped, &v); err == nil {
		t.Fatalf("a truncated config parsed clean after stripping: %s", stripped)
	}
}
