package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The release job publishes whatever .github/release-notes.sh prints. Group
// commits since the previous tag by conventional-commit type, leave out merges
// and earlier releases, and put the tag's own introduction first.
func TestReleaseNotesGroupCommitsSinceThePreviousTag(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", ".github", "release-notes.sh"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	clock := 0
	git := func(args ...string) string {
		t.Helper()
		clock++
		date := fmt.Sprintf("2026-01-01T00:00:%02dZ", clock)
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(subject string) string {
		t.Helper()
		git("commit", "-q", "--allow-empty", "-m", subject)
		return git("log", "-1", "--format=%h")
	}

	git("init", "-q", "-b", "main")
	first := commit("feat: first release")
	git("tag", "v0.1.0")
	fix := commit("fix: handle empty input")
	feat := commit("feat(cli)!: add a flag")
	ci := commit("ci: pin actions")
	docs := commit("docs: explain limits")
	git("checkout", "-q", "-b", "topic")
	chore := commit("chore: tidy imports")
	git("checkout", "-q", "main")
	git("merge", "-q", "--no-ff", "-m", "Merge branch 'topic'", "topic")
	build := commit("build: link musl")
	plain := commit("Update README")
	git("tag", "v0.2.0")
	if err := os.MkdirAll(filepath.Join(dir, "docs", "release-notes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docs", "release-notes", "v0.2.0.md"), []byte("Upgrade before Friday.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	notes := func(tag string) string {
		t.Helper()
		cmd := exec.Command("sh", script, tag)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GITHUB_REPOSITORY=o/r")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("release-notes.sh %s: %v", tag, err)
		}
		return string(out)
	}

	got := notes("v0.2.0")
	want := "Upgrade before Friday.\n\n## Changes\n" +
		"\n### Features\n- Add a flag (" + feat + ")\n" +
		"\n### Fixes\n- Handle empty input (" + fix + ")\n" +
		"\n### Build and release\n- Pin actions (" + ci + ")\n- Link musl (" + build + ")\n" +
		"\n### Documentation\n- Explain limits (" + docs + ")\n" +
		"\n### Other changes\n- Tidy imports (" + chore + ")\n- Update README (" + plain + ")\n" +
		"\nFull changelog: https://github.com/o/r/compare/v0.1.0...v0.2.0\n"
	if !strings.HasPrefix(got, want) {
		t.Errorf("notes for v0.2.0 start\n%s\nwant\n%s", got[:min(len(got), len(want))], want)
	}
	if !strings.Contains(got, "--source-ref refs/tags/v0.2.0\n") || strings.Contains(got, "@") {
		t.Errorf("verification section does not name the tag and repository:\n%s", got)
	}

	// The first release has no earlier tag to compare with, and no introduction file
	got = notes("v0.1.0")
	want = "## Changes\n\n### Features\n- First release (" + first + ")\n\n## Verifying a download\n"
	if !strings.HasPrefix(got, want) {
		t.Errorf("notes for v0.1.0 start\n%s\nwant\n%s", got[:min(len(got), len(want))], want)
	}

	// A tag not created yet previews the commits since the latest tag, which
	// are none while HEAD is that tag
	got = notes("v0.3.0")
	want = "## Changes\n\nFull changelog: https://github.com/o/r/compare/v0.2.0...v0.3.0\n"
	if !strings.HasPrefix(got, want) {
		t.Errorf("preview of v0.3.0 on the v0.2.0 commit starts\n%s\nwant\n%s", got[:min(len(got), len(want))], want)
	}
	next := commit("fix: close a gap")
	got = notes("v0.3.0")
	want = "## Changes\n\n### Fixes\n- Close a gap (" + next + ")\n\nFull changelog: https://github.com/o/r/compare/v0.2.0...v0.3.0\n"
	if !strings.HasPrefix(got, want) {
		t.Errorf("preview of v0.3.0 starts\n%s\nwant\n%s", got[:min(len(got), len(want))], want)
	}
}
