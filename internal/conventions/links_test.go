package conventions

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// markdownLink matches an inline link to a document, with the fragment
// captured separately so the heading can be checked too
var markdownLink = regexp.MustCompile(`\]\(([^)\s#]+\.md)(#[^)\s]*)?\)`)

var docPath = regexp.MustCompile(`\bdocs/[A-Za-z0-9._/-]+\.md\b`)

func TestDocumentationLinksResolve(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range trackedFiles(t, root) {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // a submodule entry or a file removed since ls-files ran
		}
		text := prose(string(body), strings.HasSuffix(rel, ".md"))

		for _, m := range docPath.FindAllString(text, -1) {
			if !exists(root, m) {
				t.Errorf("%s names %s, which is not in this repository", rel, m)
			}
		}
		if !strings.HasSuffix(rel, ".md") {
			continue
		}
		for _, m := range markdownLink.FindAllStringSubmatch(text, -1) {
			target, fragment := m[1], m[2]
			if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
				continue
			}
			resolved := path.Join(path.Dir(rel), target)
			if !exists(root, resolved) {
				t.Errorf("%s links to %s, which resolves to %s and is not there", rel, target, resolved)
				continue
			}
			if fragment == "" {
				continue
			}
			dest, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(resolved)))
			if err != nil {
				continue
			}
			if !headingAnchors(string(dest))[strings.TrimPrefix(fragment, "#")] {
				t.Errorf("%s links to %s%s, but %s has no heading with that anchor", rel, target, fragment, resolved)
			}
		}
	}
}

func TestEveryDocumentIsReachable(t *testing.T) {
	root := repoRoot(t)
	files := trackedFiles(t, root)

	linked := map[string]bool{}
	for _, rel := range files {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}

		for _, m := range markdownLink.FindAllStringSubmatch(prose(string(body), true), -1) {
			linked[path.Join(path.Dir(rel), m[1])] = true
		}
	}

	for _, rel := range files {
		if !strings.HasPrefix(rel, "docs/") || !strings.HasSuffix(rel, ".md") {
			continue
		}
		if !linked[rel] {
			t.Errorf("%s is linked from nowhere: add it to an index or delete it", rel)
		}
	}
}

func trackedFiles(t *testing.T, root string) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Skipf("not a git checkout, nothing to walk: %v", err)
	}
	var files []string
	for rel := range strings.SplitSeq(strings.TrimRight(string(out), "\x00"), "\x00") {
		if rel != "" {
			files = append(files, rel)
		}
	}
	return files
}

func exists(root, rel string) bool {
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}

func prose(body string, markdown bool) string {
	if !markdown {
		return body
	}
	var keep []string
	fenced := false
	for line := range strings.SplitSeq(body, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			fenced = !fenced
			continue
		}
		if !fenced {
			keep = append(keep, line)
		}
	}
	return strings.Join(keep, "\n")
}

// headingAnchors returns the fragment each ATX heading in body is reachable
// by, following the rule forges use: lowercase, punctuation dropped, spaces
// turned into hyphens
func headingAnchors(body string) map[string]bool {
	anchors := map[string]bool{}
	for line := range strings.SplitSeq(prose(body, true), "\n") {
		if !strings.HasPrefix(line, "#") {
			continue
		}
		heading := strings.TrimSpace(strings.TrimLeft(line, "#"))
		var b strings.Builder
		for _, r := range strings.ToLower(heading) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
				b.WriteRune(r)
			case r == ' ':
				b.WriteRune('-')
			}
		}
		if b.Len() > 0 {
			anchors[b.String()] = true
		}
	}
	return anchors
}
