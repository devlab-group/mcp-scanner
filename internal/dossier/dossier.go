// Package dossier collects everything the static pipeline knows about an MCP server's source tree
// into one document, for a later reviewer - a person or a model - to read without the tree at
// hand: languages and manifests, the MCP SDK and its version, declared server identity, and for
// each tool, prompt and resource its declaration, handler code and reachable behavior. It reports
// facts only; findings stay in the scan report.
package dossier

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/analyzers/behavioral"
	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/internal/source/graph"
	"github.com/devlab-group/mcp-scanner/internal/source/parser"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// SchemaVersion identifies the dossier layout
const SchemaVersion = "1"

// maxHandlerSource bounds the handler source text kept per capability
const maxHandlerSource = 8000

// Dossier is the whole document
type Dossier struct {
	SchemaVersion  string       `json:"schema_version"`
	ScannerVersion string       `json:"scanner_version,omitempty"`
	GeneratedAt    time.Time    `json:"generated_at"`
	Root           string       `json:"root"`
	Repository     Repository   `json:"repository"`
	Servers        []Server     `json:"servers,omitempty"`
	MCPImports     []string     `json:"mcp_imports,omitempty"`
	Capabilities   []Capability `json:"capabilities"`
	// ReviewHints are places static analysis could not settle, for a later reviewer to revisit;
	// see docs/review-hints.md
	ReviewHints []Hint         `json:"review_hints"`
	Coverage    model.Coverage `json:"coverage"`
}

// Repository is what the tree is made of
type Repository struct {
	FilesByLanguage map[string]int `json:"files_by_language"`
	FilesParsed     int            `json:"files_parsed"`
	Functions       int            `json:"functions"`
	Manifests       []Manifest     `json:"manifests,omitempty"`
	// Readme is the start of the top-level README, as the project describes itself
	Readme string `json:"readme,omitempty"`
}

// Manifest is one package manifest and what it declares
type Manifest struct {
	Path         string            `json:"path"`
	Ecosystem    string            `json:"ecosystem"`
	Name         string            `json:"name,omitempty"`
	Version      string            `json:"version,omitempty"`
	MCPSDK       map[string]string `json:"mcp_sdk,omitempty"`
	Dependencies map[string]string `json:"dependencies,omitempty"`
}

// Server is a declared server identity: new McpServer({ name, version }), FastMCP("name")
type Server struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Call    string `json:"call"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// Capability is one tool, prompt or resource with its handler and reachable behavior
type Capability struct {
	Kind                string                      `json:"kind"`
	Name                string                      `json:"name"`
	NameResolved        bool                        `json:"name_resolved"`
	URI                 string                      `json:"uri,omitempty"`
	Description         string                      `json:"description,omitempty"`
	DescriptionResolved bool                        `json:"description_resolved"`
	Form                string                      `json:"form,omitempty"`
	File                string                      `json:"file"`
	Line                int                         `json:"line"`
	Handler             *Handler                    `json:"handler,omitempty"`
	HandlerText         string                      `json:"handler_text,omitempty"`
	Behavior            *behavioral.HandlerBehavior `json:"behavior,omitempty"`
	Declares            map[string]bool             `json:"declares,omitempty"`
}

// Handler is the function that serves a capability
type Handler struct {
	Symbol    string   `json:"symbol"`
	File      string   `json:"file"`
	StartLine int      `json:"start_line"`
	EndLine   int      `json:"end_line"`
	Params    []string `json:"params,omitempty"`
	Source    string   `json:"source,omitempty"`
	Truncated bool     `json:"source_truncated,omitempty"`
}

// Build walks root once and assembles the dossier
func Build(ctx context.Context, root, scannerVersion string) (*Dossier, error) {
	g, cov, err := source.Build(ctx, root)
	if err != nil {
		return nil, err
	}
	d := &Dossier{
		SchemaVersion: SchemaVersion, ScannerVersion: scannerVersion, GeneratedAt: time.Now().UTC(),
		Root: root, Coverage: cov,
		Repository: Repository{FilesByLanguage: map[string]int{}, FilesParsed: cov.FilesParsed, Functions: len(g.Symbols)},
	}
	for _, f := range g.Files {
		d.Repository.FilesByLanguage[f.Language]++
	}
	d.Repository.Manifests = manifests(root)
	d.Repository.Readme = readme(root)
	d.Servers = append(servers(g), jsServers(root, g)...)
	d.MCPImports = mcpImports(g)
	for _, c := range g.Capabilities {
		d.Capabilities = append(d.Capabilities, capability(root, g, c))
	}
	sort.SliceStable(d.Capabilities, func(i, j int) bool {
		a, b := d.Capabilities[i], d.Capabilities[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	d.ReviewHints = hints(d, g, cov)
	if d.ReviewHints == nil {
		d.ReviewHints = []Hint{}
	}
	return d, nil
}

func capability(root string, g *graph.Graph, c graph.Capability) Capability {
	out := Capability{
		Kind: string(c.Kind), Name: source.DisplayName(c), NameResolved: c.NameResolved,
		Description: c.Description, DescriptionResolved: c.DescriptionResolved,
		Form: c.Form, File: c.File, Line: c.Line, URI: c.URI,
		HandlerText: c.HandlerText,
	}
	text := strings.ReplaceAll(c.Name, "_", " ") + ". " + c.Description
	fs, net, proc := behavioral.Declared(text)
	out.Declares = map[string]bool{"filesystem": fs, "network": net, "process": proc}
	if c.Handler == "" {
		return out
	}
	if s := g.Symbols[c.Handler]; s != nil {
		h := &Handler{Symbol: string(s.ID), File: s.File, StartLine: s.Line, EndLine: s.EndLine, Params: s.Params}
		h.Source, h.Truncated = sourceLines(root, s.File, s.Line, s.EndLine)
		out.Handler = h
	}
	b := behavioral.Behavior(g, c.Handler)
	out.Behavior = &b
	return out
}

func sourceLines(root, file string, start, end int) (string, bool) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil || start <= 0 {
		return "", false
	}
	lines := strings.Split(string(data), "\n")
	if end < start || end > len(lines) {
		end = min(len(lines), start+200)
	}
	if start > len(lines) {
		return "", false
	}
	text := strings.Join(lines[start-1:end], "\n")
	if len(text) > maxHandlerSource {
		return text[:maxHandlerSource], true
	}
	return text, false
}

var (
	serverCtors = map[string]bool{"McpServer": true, "FastMCP": true, "MCPServer": true, "Server": true, "NewServer": true, "NewMCPServer": true, "McpServerBuilder": true}
	objName     = regexp.MustCompile(`\bname\s*[:=]\s*["'` + "`" + `]([^"'` + "`" + `]+)`)
	objVersion  = regexp.MustCompile(`\bversion\s*[:=]\s*["'` + "`" + `]([^"'` + "`" + `]+)`)
)

func servers(g *graph.Graph) []Server {
	var out []Server
	for _, c := range g.Calls {
		seg := parser.LastSegment(strings.TrimPrefix(c.CalleeText, "new "))
		if !serverCtors[seg] || len(c.Args) == 0 {
			continue
		}
		s := Server{File: c.File, Line: c.Line, Call: c.CalleeText}
		if c.Args[0].Literal {
			s.Name = c.Args[0].Value
		}
		for _, a := range c.Args {
			if s.Name == "" {
				if m := objName.FindStringSubmatch(a.Text); m != nil {
					s.Name = m[1]
				}
			}
			if a.Keyword == "name" && a.Literal {
				s.Name = a.Value
			}
			if m := objVersion.FindStringSubmatch(a.Text); m != nil && s.Version == "" {
				s.Version = m[1]
			}
			if a.Keyword == "version" && a.Literal {
				s.Version = a.Value
			}
		}
		if len(c.Args) > 1 && c.Args[1].Literal && s.Version == "" && seg == "NewMCPServer" {
			s.Version = c.Args[1].Value
		}
		if s.Name != "" || s.Version != "" {
			out = append(out, s)
		}
		if len(out) >= 20 {
			break
		}
	}
	return out
}

var mcpImport = regexp.MustCompile(`(?i)(modelcontextprotocol|fastmcp|mcp\.server|mcp-go|mcp_sdk|rmcp|\bmcp\b)`)

func mcpImports(g *graph.Graph) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range g.Files {
		for _, im := range f.Imports {
			if mcpImport.MatchString(im.Path) && !seen[im.Path] {
				seen[im.Path] = true
				out = append(out, im.Path)
			}
		}
	}
	sort.Strings(out)
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

// skipDirs are never searched for manifests: installed dependencies and build output
var skipDirs = map[string]bool{"node_modules": true, "vendor": true, ".git": true, ".venv": true, "venv": true, "__pycache__": true, "dist": true, "build": true, "target": true}

var mcpPackage = regexp.MustCompile(`(?i)^(@modelcontextprotocol/sdk|mcp|fastmcp|github\.com/modelcontextprotocol/go-sdk|github\.com/mark3labs/mcp-go|rmcp|io\.modelcontextprotocol\.sdk:.*|@modelcontextprotocol/.*|mcp-server-.*)$`)

func manifests(root string) []Manifest {
	var out []Manifest
	_ = filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if e.IsDir() {
			if skipDirs[e.Name()] || strings.Count(rel, string(os.PathSeparator)) >= 5 {
				return filepath.SkipDir
			}
			return nil
		}
		var m *Manifest
		switch e.Name() {
		case "package.json":
			m = npmManifest(p)
		case "pyproject.toml":
			m = pyprojectManifest(p)
		case "requirements.txt":
			m = requirementsManifest(p)
		case "go.mod":
			m = goModManifest(p)
		case "Cargo.toml":
			m = cargoManifest(p)
		case "pom.xml":
			m = pomManifest(p)
		}
		if m != nil {
			m.Path = filepath.ToSlash(rel)
			for dep, ver := range m.Dependencies {
				if mcpPackage.MatchString(dep) {
					if m.MCPSDK == nil {
						m.MCPSDK = map[string]string{}
					}
					m.MCPSDK[dep] = ver
				}
			}
			out = append(out, *m)
		}
		if len(out) >= 60 {
			return filepath.SkipAll
		}
		return nil
	})
	return out
}

func readSmall(p string) string {
	info, err := os.Stat(p)
	if err != nil || info.Size() > 1<<20 {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(data)
}

func npmManifest(p string) *Manifest {
	var pkg struct {
		Name            string            `json:"name"`
		Version         string            `json:"version"`
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal([]byte(readSmall(p)), &pkg) != nil {
		return nil
	}
	m := &Manifest{Ecosystem: "npm", Name: pkg.Name, Version: pkg.Version, Dependencies: map[string]string{}}
	for k, v := range pkg.Dependencies {
		m.Dependencies[k] = v
	}
	for k, v := range pkg.DevDependencies {
		if _, ok := m.Dependencies[k]; !ok {
			m.Dependencies[k] = v + " (dev)"
		}
	}
	return m
}

var (
	tomlKey     = regexp.MustCompile(`(?m)^\s*(name|version)\s*=\s*"([^"]*)"`)
	pyDepItem   = regexp.MustCompile(`"([A-Za-z0-9_.\-\[\]]+)\s*([<>=!~^][^";]*)?[^"]*"`)
	reqLine     = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_.\-\[\]]+)\s*([<>=!~][^#\s;]*)?`)
	goRequire   = regexp.MustCompile(`(?m)^\s*(?:require\s+)?([a-zA-Z0-9.\-_/]+\.[a-z]{2,}[a-zA-Z0-9.\-_/]*)\s+(v[0-9][^\s]*)`)
	goModule    = regexp.MustCompile(`(?m)^module\s+(\S+)`)
	cargoDep    = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_\-]+)\s*=\s*(?:"([^"]*)"|\{[^}]*version\s*=\s*"([^"]*)")`)
	pomArtifact = regexp.MustCompile(`<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?`)
	pomGroup    = regexp.MustCompile(`<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?`)
)

func pyprojectManifest(p string) *Manifest {
	text := readSmall(p)
	if text == "" {
		return nil
	}
	m := &Manifest{Ecosystem: "pypi", Dependencies: map[string]string{}}
	head := text
	if i := strings.Index(text, "[project]"); i >= 0 {
		head = text[i:]
	} else if i := strings.Index(text, "[tool.poetry]"); i >= 0 {
		head = text[i:]
	}
	for _, kv := range tomlKey.FindAllStringSubmatch(head, 2) {
		if kv[1] == "name" && m.Name == "" {
			m.Name = kv[2]
		}
		if kv[1] == "version" && m.Version == "" {
			m.Version = kv[2]
		}
	}
	if i := strings.Index(text, "dependencies"); i >= 0 {
		block := text[i:]
		if j := strings.Index(block, "]"); j > 0 {
			block = block[:j]
		}
		for _, d := range pyDepItem.FindAllStringSubmatch(block, -1) {
			m.Dependencies[strings.ToLower(strings.SplitN(d[1], "[", 2)[0])] = strings.TrimSpace(d[2])
		}
	}
	return m
}

func requirementsManifest(p string) *Manifest {
	text := readSmall(p)
	if text == "" {
		return nil
	}
	m := &Manifest{Ecosystem: "pypi", Dependencies: map[string]string{}}
	for _, d := range reqLine.FindAllStringSubmatch(text, -1) {
		if d[1] != "" && !strings.HasPrefix(d[1], "-") {
			m.Dependencies[strings.ToLower(strings.SplitN(d[1], "[", 2)[0])] = d[2]
		}
	}
	return m
}

func goModManifest(p string) *Manifest {
	text := readSmall(p)
	if text == "" {
		return nil
	}
	m := &Manifest{Ecosystem: "go", Dependencies: map[string]string{}}
	if mm := goModule.FindStringSubmatch(text); mm != nil {
		m.Name = mm[1]
	}
	for _, d := range goRequire.FindAllStringSubmatch(text, -1) {
		if d[1] != m.Name {
			m.Dependencies[d[1]] = d[2]
		}
	}
	return m
}

func cargoManifest(p string) *Manifest {
	text := readSmall(p)
	if text == "" {
		return nil
	}
	m := &Manifest{Ecosystem: "cargo", Dependencies: map[string]string{}}
	pkg := text
	if i := strings.Index(text, "[package]"); i >= 0 {
		pkg = text[i:]
		if j := strings.Index(pkg[1:], "\n["); j > 0 {
			pkg = pkg[:j+1]
		}
	}
	for _, kv := range tomlKey.FindAllStringSubmatch(pkg, 2) {
		if kv[1] == "name" {
			m.Name = kv[2]
		}
		if kv[1] == "version" {
			m.Version = kv[2]
		}
	}
	if i := strings.Index(text, "[dependencies]"); i >= 0 {
		deps := text[i+len("[dependencies]"):]
		if j := strings.Index(deps, "\n["); j > 0 {
			deps = deps[:j]
		}
		for _, d := range cargoDep.FindAllStringSubmatch(deps, -1) {
			v := d[2]
			if v == "" {
				v = d[3]
			}
			m.Dependencies[d[1]] = v
		}
	}
	return m
}

func pomManifest(p string) *Manifest {
	text := readSmall(p)
	if text == "" {
		return nil
	}
	m := &Manifest{Ecosystem: "maven", Dependencies: map[string]string{}}
	if a := pomArtifact.FindStringSubmatch(text); a != nil {
		m.Name, m.Version = a[1], a[2]
	}
	if i := strings.Index(text, "<dependencies>"); i >= 0 {
		for _, d := range pomGroup.FindAllStringSubmatch(text[i:], -1) {
			m.Dependencies[d[1]+":"+d[2]] = d[3]
		}
	}
	return m
}

// maxReadme bounds the README text kept
const maxReadme = 4000

func readme(root string) string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(strings.ToLower(e.Name()), "readme") {
			text := readSmall(filepath.Join(root, e.Name()))
			if len(text) > maxReadme {
				text = text[:maxReadme]
			}
			return text
		}
	}
	return ""
}

// jsNewServer finds `new McpServer({ name: "x", version: "1.0.0" })` and `new Server({...})` in
// JavaScript and TypeScript, whose constructor calls are not in the call list
var jsNewServer = regexp.MustCompile(`new\s+(McpServer|Server)\s*\(\s*\{([^}]*)\}`)

func jsServers(root string, g *graph.Graph) []Server {
	var out []Server
	for path, f := range g.Files {
		if f.Language != "javascript" && f.Language != "typescript" {
			continue
		}
		text := readSmall(filepath.Join(root, filepath.FromSlash(path)))
		for _, m := range jsNewServer.FindAllStringSubmatchIndex(text, 3) {
			body := text[m[4]:m[5]]
			s := Server{File: path, Line: strings.Count(text[:m[0]], "\n") + 1, Call: "new " + text[m[2]:m[3]]}
			if n := objName.FindStringSubmatch(body); n != nil {
				s.Name = n[1]
			}
			if v := objVersion.FindStringSubmatch(body); v != nil {
				s.Version = v[1]
			}
			if s.Name != "" || s.Version != "" {
				out = append(out, s)
			}
		}
		if len(out) >= 20 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].File < out[j].File || out[i].File == out[j].File && out[i].Line < out[j].Line
	})
	return out
}
