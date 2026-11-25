package taint

import (
	"path"
	"regexp"
	"strings"

	"github.com/devlab-group/mcp-scanner/internal/source/registration"
)

// A tree in which no MCP handler was resolved is either not an MCP server at all - a command-line
// tool, a library - or one whose registration form this build does not read. Only the first lets
// a finding drop to context: then no MCP caller reaches the path, and the missing registrations
// are already reported once, as a coverage limit. The sign of an MCP server is read broadly: an
// import or a manifest that names MCP in any spelling (an SDK this build does not know included),
// and a manifest that cannot be read counts as one.

// mcpWord is MCP as a word of an import path, a package name or a dependency: mcp, fastmcp,
// rmcp, @modelcontextprotocol/sdk, github.com/mark3labs/mcp-go, @mastra/mcp, foo-mcp-server
var mcpWord = regexp.MustCompile(`(?i)modelcontextprotocol|fastmcp|\brmcp\b|(?:^|[^a-z0-9])mcp(?:[^a-z0-9]|$)`)

// packageManifests are the files that declare a package's dependencies
var packageManifests = map[string]bool{
	"package.json": true, "pyproject.toml": true, "setup.py": true, "setup.cfg": true, "go.mod": true,
	"Cargo.toml": true, "pom.xml": true, "build.gradle": true, "build.gradle.kts": true, "Gemfile": true,
	"composer.json": true, "deno.json": true, "Pipfile": true,
}

// mcpSurface reports whether the tree shows any sign of being an MCP server for the code in file
func (gi *guardIndex) mcpSurface(file string) bool {
	if gi.surfaceImports == nil {
		v := false
		if gi.g != nil {
			v = registration.TreeImportsMCPSDK(gi.g)
			for _, f := range gi.g.Files {
				if v {
					break
				}
				for _, imp := range f.Imports {
					if mcpWord.MatchString(imp.Path) {
						v = true
						break
					}
				}
			}
		}
		gi.surfaceImports = &v
	}
	if *gi.surfaceImports {
		return true
	}
	for dir := path.Dir(file); ; dir = path.Dir(dir) {
		names, refused := gi.dirNames(dir)
		if refused {
			return true
		}
		for _, name := range names {
			if !packageManifests[name] && !(strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")) && !strings.HasSuffix(name, ".csproj") {
				continue
			}
			p := name
			if dir != "." {
				p = dir + "/" + name
			}
			text, refused := gi.manifestText(p)
			if refused || mcpWord.MatchString(text) {
				return true
			}
		}
		if dir == "." || dir == "/" || dir == "" {
			return false
		}
	}
}
