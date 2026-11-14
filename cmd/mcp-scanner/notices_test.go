package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// noticeTargets covers the release matrix in .github/workflows/dist.yml and the
// YARA build, whose dependencies THIRD_PARTY_NOTICES also lists
var noticeTargets = []struct{ goos, goarch, tags string }{
	{"linux", "amd64", "netgo,osusergo"},
	{"linux", "arm64", "netgo,osusergo"},
	{"windows", "amd64", ""},
	{"darwin", "arm64", ""},
	{"darwin", "amd64", ""},
	{"linux", "amd64", "yara"},
}

const stdlibHeader = "Go standard library and runtime "

// Check the manually maintained notices against the linked modules and Go release
// so dependency changes cannot leave missing, stale or incorrectly versioned entries
func TestThirdPartyNoticesMatchLinkedModules(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go list once per release target")
	}
	root := filepath.Join("..", "..")

	var mod struct{ Go, Toolchain string }
	if err := json.Unmarshal(goCmd(t, root, nil, "mod", "edit", "-json"), &mod); err != nil {
		t.Fatalf("go mod edit -json: %v", err)
	}
	wantStdlib := mod.Toolchain
	if wantStdlib == "" {
		wantStdlib = "go" + mod.Go
	}

	linked := map[string]bool{}
	for _, tg := range noticeTargets {
		env := []string{"GOOS=" + tg.goos, "GOARCH=" + tg.goarch, "CGO_ENABLED=1"}
		out := goCmd(t, root, env, "list", "-deps", "-tags", tg.tags,
			"-f", "{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}", "./cmd/...")
		for line := range strings.Lines(string(out)) {
			if line = strings.TrimSpace(line); line != "" {
				linked[line] = true
			}
		}
	}

	data, err := os.ReadFile(filepath.Join(root, "THIRD_PARTY_NOTICES"))
	if err != nil {
		t.Fatal(err)
	}
	listed, stdlib := noticeEntries(string(data))

	if stdlib != wantStdlib {
		t.Errorf("standard library entry names %q, go.mod builds with %q", stdlib, wantStdlib)
	}
	for m := range linked {
		if !listed[m] {
			t.Errorf("linked but missing from THIRD_PARTY_NOTICES: %s", m)
		}
	}
	for m := range listed {
		if !linked[m] {
			t.Errorf("listed in THIRD_PARTY_NOTICES but not linked into any release target: %s", m)
		}
	}
}

// noticeEntries returns Go module paths and versions, plus the standard library
// version. Headers sit between a rule and a License: line. Entries without a Go
// module version, such as C runtimes, are skipped.
func noticeEntries(text string) (modules map[string]bool, stdlib string) {
	modules = map[string]bool{}
	lines := strings.Split(text, "\n")
	for i := 1; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i-1], "=====") || !strings.HasPrefix(lines[i+1], "License:") {
			continue
		}
		header := lines[i]
		if v, ok := strings.CutPrefix(header, stdlibHeader); ok {
			stdlib = v
			continue
		}
		if f := strings.Fields(header); len(f) == 2 && strings.HasPrefix(f[1], "v") {
			modules[f[0]+" "+f[1]] = true
		}
	}
	return modules, stdlib
}

func goCmd(t *testing.T, dir string, env []string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, stderr)
	}
	return out
}
