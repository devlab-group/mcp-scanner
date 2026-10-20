// Package language adapts each supported source language to a common shape: its file
// extensions, its tree-sitter grammar, and the small set of node kinds the parser and taint
// walker need to recognize (a function, a call, an assignment, a string literal)
package language

import (
	"fmt"
	"sync"
	"unsafe"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/devlab-group/mcp-scanner/internal/source/queries"
)

// ID names one of the supported languages. It is also the query directory
// name under internal/source/queries.
type ID string

const (
	Go         ID = "go"
	Python     ID = "python"
	JavaScript ID = "javascript"
	TypeScript ID = "typescript"
	Java       ID = "java"
	Rust       ID = "rust"
)

// Grammar is the node-kind vocabulary the parser and the taint walker use to
// recognize a construct without caring which grammar produced it
type Grammar struct {
	FunctionKinds []string // function/method definitions
	ClassKinds    []string // class definitions; empty for languages with none
	CallKinds     []string // call-shaped expressions (includes constructors)
	AssignKinds   []string // assignment and declaration-with-initializer nodes
	StringKinds   []string // string literal node kinds
	MemberKinds   []string // member/attribute/field access expressions
	ReturnKinds   []string
	ForKinds      []string // loop constructs, used for "registration in a loop"
}

// Adapter is everything the source pipeline needs for one language
type Adapter struct {
	ID         ID
	Extensions []string // includes the leading dot
	Grammar    Grammar

	load func() unsafe.Pointer

	once    sync.Once
	lang    *sitter.Language
	loadErr error

	queryMu    sync.Mutex
	queryCache map[string]*sitter.Query
}

// Language returns the compiled tree-sitter language, loading it on first
// use. A grammar that fails to load (or panics, which the C bindings can do
// on a malformed pointer) reports err instead of taking the process down.
func (a *Adapter) Language() (lang *sitter.Language, err error) {
	a.once.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				a.loadErr = fmt.Errorf("grammar %s panicked while loading: %v", a.ID, r)
			}
		}()
		ptr := a.load()
		if ptr == nil {
			a.loadErr = fmt.Errorf("grammar %s returned a nil language pointer", a.ID)
			return
		}
		a.lang = sitter.NewLanguage(ptr)
		if a.lang == nil {
			a.loadErr = fmt.Errorf("grammar %s: NewLanguage returned nil", a.ID)
		}
	})
	return a.lang, a.loadErr
}

// Query compiles (and caches) the named query file for this language. name
// is the file's basename without extension, for example "symbols"
func (a *Adapter) Query(name string) (*sitter.Query, error) {
	lang, err := a.Language()
	if err != nil {
		return nil, err
	}
	a.queryMu.Lock()
	defer a.queryMu.Unlock()
	if q, ok := a.queryCache[name]; ok {
		return q, nil
	}
	src := queries.Read(string(a.ID), name)
	q, qerr := sitter.NewQuery(lang, src)
	if qerr != nil {
		return nil, fmt.Errorf("compiling %s/%s.scm: %s", a.ID, name, qerr.Message)
	}
	if a.queryCache == nil {
		a.queryCache = map[string]*sitter.Query{}
	}
	a.queryCache[name] = q
	return q, nil
}

// HasQuery reports whether a query file exists for this language, for
// optional queries such as decorators
func (a *Adapter) HasQuery(name string) bool { return queries.Has(string(a.ID), name) }
