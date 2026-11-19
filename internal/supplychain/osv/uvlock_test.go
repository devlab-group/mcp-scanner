package osv

import "testing"

const uvLockSample = `version = 1

[[package]]
name = "my-server"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "httpx" },
]

[package.optional-dependencies]
pdf = [
    { name = "pypdf" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
    { name = "httpx" },
]

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "anyio" }]

[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pypdf"
version = "4.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.2.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "pluggy" },
    { name = "anyio" },
]

[[package]]
name = "pluggy"
version = "1.5.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "forked"
version = "1.0.0"
source = { git = "https://github.com/x/forked?rev=abc#abc" }
`

// uv.lock: registry packages are coordinates, the project's own package is not, a git source is a
// note; a package only the dev group reaches is dev-only, and one the dev group and production
// both reach (httpx, anyio) or an extra (pypdf) is not
func TestParseUvLock(t *testing.T) {
	coords, notes, err := ParseUvLock([]byte(uvLockSample))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, c := range coords {
		got[c.Name+"@"+c.Version] = true
	}
	for _, want := range []string{"httpx@0.27.0", "anyio@4.4.0", "pypdf@4.0.0", "pytest@8.2.0", "pluggy@1.5.0"} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, coords)
		}
	}
	if got["my-server@0.1.0"] || got["forked@1.0.0"] || len(notes) != 1 {
		t.Errorf("own package or git source counted: %v, notes %v", coords, notes)
	}
	dev := UvLockDevOnly([]byte(uvLockSample))
	isDev := func(n, v string) bool { return dev[Coordinate{Ecosystem: "PyPI", Name: n, Version: v}] }
	if !isDev("pytest", "8.2.0") || !isDev("pluggy", "1.5.0") {
		t.Errorf("pytest and pluggy are dev-only: %v", dev)
	}
	if isDev("httpx", "0.27.0") || isDev("anyio", "4.4.0") || isDev("pypdf", "4.0.0") {
		t.Errorf("a production or extra dependency marked dev-only: %v", dev)
	}
}

// poetry.lock: category = "dev" (Poetry < 1.2) and a groups list without "main" (Poetry 2) mark
// dev-only packages; a lock that records neither marks nothing
func TestPoetryLockDevOnly(t *testing.T) {
	lock := `[[package]]
name = "requests"
version = "2.32.0"
category = "main"

[[package]]
name = "pytest"
version = "8.2.0"
category = "dev"

[[package]]
name = "ruff"
version = "0.5.0"
groups = ["dev", "lint"]

[[package]]
name = "anyio"
version = "4.4.0"
groups = ["main", "dev"]

[[package]]
name = "plain"
version = "1.0.0"
`
	dev := PoetryLockDevOnly([]byte(lock))
	want := map[string]bool{"pytest": true, "ruff": true}
	for c := range dev {
		if !want[c.Name] {
			t.Errorf("%s marked dev-only", c.Name)
		}
		delete(want, c.Name)
	}
	if len(want) != 0 {
		t.Errorf("not marked dev-only: %v", want)
	}
}
