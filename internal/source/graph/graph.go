// Package graph is the exported source-code model shared between the discovery pass and
// every analyzer that reasons about dataflow: symbols, imports, the call graph and the MCP
// capabilities found in it
package graph

import "strconv"

// SymbolKind is what kind of definition a Symbol records
type SymbolKind string

const (
	KindFunction SymbolKind = "function"
	KindMethod   SymbolKind = "method"
	KindClass    SymbolKind = "class"
)

// SymbolID identifies a symbol uniquely within one Graph. It is built from
// the file and name so it stays stable across a rebuild of the same tree.
type SymbolID string

// Symbol is a function, method or class definition
type Symbol struct {
	ID         SymbolID   `json:"id"`
	Kind       SymbolKind `json:"kind"`
	Name       string     `json:"name"`
	Receiver   string     `json:"receiver,omitempty"` // method receiver type, or enclosing class
	File       string     `json:"file"`
	Line       int        `json:"line"`
	EndLine    int        `json:"end_line"`
	Params     []string   `json:"params,omitempty"`
	Doc        string     `json:"doc,omitempty"`        // docstring or leading comment, best-effort
	Decorators []string   `json:"decorators,omitempty"` // raw decorator/annotation source text
	// ReturnLiteral holds the keyed fields of a composite/object/dict literal
	// returned by this function, when its body is simply `return <literal>`.
	// It is how a factory function's static shape (`return &mcp.Tool{Name:
	// "x"}`) is readable without a type checker.
	ReturnLiteral []Arg `json:"return_literal,omitempty"`

	// ReturnText is the raw source text of the same `return <value>` statement ReturnLiteral
	// reads, kept regardless of whether that value is itself a literal ReturnLiteral could
	// flatten
	ReturnText string `json:"return_text,omitempty"`
}

// Import is one import/use/require statement, normalized across languages
type Import struct {
	Path  string `json:"path"` // module/package path as written
	Alias string `json:"alias,omitempty"`
	File  string `json:"file"`
	Line  int    `json:"line"`
}

// Arg is one static argument to a call
type Arg struct {
	Text    string `json:"text"`              // source text of the argument expression
	Literal bool   `json:"literal"`           // true when Text is a plain string literal
	Value   string `json:"value,omitempty"`   // the literal's decoded value, if Literal
	Keyword string `json:"keyword,omitempty"` // keyword/named-argument name, if any

	// HandlerID is set when this argument is itself an inline function literal -
	// `server.tool("x", "y", async ({ path }) => {...})`, the form the MCP SDKs' own examples
	// register a handler with - rather than a reference to a named one
	HandlerID SymbolID `json:"handler_id,omitempty"`
}

// Call is one call expression, resolved within the repo where possible
type Call struct {
	Caller     SymbolID `json:"caller,omitempty"` // "" for module/top-level code
	Callee     SymbolID `json:"callee,omitempty"` // "" when unresolved
	CalleeText string   `json:"callee_text"`      // raw callee expression, always set
	Resolved   bool     `json:"resolved"`
	InLoop     bool     `json:"in_loop,omitempty"`
	// IsDecorator is true when this call is itself a decorator expression (Python's
	// `@mcp.tool()`, a call syntactically), not an invocation at the point it appears
	IsDecorator bool   `json:"is_decorator,omitempty"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Args        []Arg  `json:"args,omitempty"`
}

// CapabilityKind is what an MCP registration declares
type CapabilityKind string

const (
	CapabilityTool     CapabilityKind = "tool"
	CapabilityPrompt   CapabilityKind = "prompt"
	CapabilityResource CapabilityKind = "resource"
)

// Capability is one discovered MCP tool/prompt/resource registration
type Capability struct {
	Kind CapabilityKind `json:"kind"`

	Name         string `json:"name,omitempty"`
	NameResolved bool   `json:"name_resolved"`

	Description         string `json:"description,omitempty"`
	DescriptionResolved bool   `json:"description_resolved"`

	Handler     SymbolID `json:"handler,omitempty"`
	HandlerText string   `json:"handler_text,omitempty"`

	// Form is how the registration was found: direct | decorator | wrapper |
	// table | loop | factory | request_handler. request_handler is the
	// low-level SDK's split form - a ListXRequestSchema/@app.list_x()
	// handler declares the capabilities, a separate Call*/Get*RequestSchema
	// handler dispatches every call by name - see the registration package
	Form string `json:"form"`

	File string `json:"file"`
	Line int    `json:"line"`
}

// File is one parsed source file
type File struct {
	Path     string   `json:"path"`
	Language string   `json:"language"`
	Imports  []Import `json:"imports,omitempty"`
	// MaxBytes is nonzero when the walk that produced this file found it over the per-file size
	// limit: only the first MaxBytes bytes were read and parsed
	MaxBytes int64 `json:"max_bytes,omitempty"`
}

// Graph is the whole-tree symbol table, call graph and MCP capability list
type Graph struct {
	Root         string               `json:"root"`
	Files        map[string]*File     `json:"files"`
	Symbols      map[SymbolID]*Symbol `json:"symbols"`
	Calls        []Call               `json:"calls"`
	Capabilities []Capability         `json:"capabilities"`
}

func New(root string) *Graph {
	return &Graph{Root: root, Files: map[string]*File{}, Symbols: map[SymbolID]*Symbol{}}
}

// CallsFrom returns every call made directly by id ("" for top-level calls)
func (g *Graph) CallsFrom(id SymbolID) []Call {
	var out []Call
	for _, c := range g.Calls {
		if c.Caller == id {
			out = append(out, c)
		}
	}
	return out
}

// Reachable does a breadth-first walk of the call graph starting at id and returns every
// resolved symbol it can reach, plus whether the walk ever had to cross an unresolved call
// to keep going
func (g *Graph) Reachable(id SymbolID) (symbols map[SymbolID]bool, sawUnknown bool) {
	symbols = map[SymbolID]bool{}
	queue := []SymbolID{id}
	visited := map[SymbolID]bool{id: true}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range g.CallsFrom(cur) {
			if !c.Resolved {
				sawUnknown = true
				continue
			}
			symbols[c.Callee] = true
			if !visited[c.Callee] {
				visited[c.Callee] = true
				queue = append(queue, c.Callee)
			}
		}
	}
	return symbols, sawUnknown
}

// MakeSymbolID builds a stable identifier for a definition at file:line,
// unique
// enough for name-based resolution and readable enough for debugging and
// finding paths
func MakeSymbolID(file, name string, line int) SymbolID {
	return SymbolID(file + ":" + name + ":" + strconv.Itoa(line))
}
