package language

import (
	"slices"

	tsgo "github.com/tree-sitter/tree-sitter-go/bindings/go"
	tsjava "github.com/tree-sitter/tree-sitter-java/bindings/go"
	tsjs "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tspy "github.com/tree-sitter/tree-sitter-python/bindings/go"
	tsrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"
	tsts "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

var all = []*Adapter{
	{
		ID:         Go,
		Extensions: []string{".go"},
		load:       tsgo.Language,
		Grammar: Grammar{
			FunctionKinds: []string{"function_declaration", "method_declaration", "func_literal"},
			CallKinds:     []string{"call_expression"},
			AssignKinds:   []string{"short_var_declaration", "assignment_statement", "var_spec"},
			StringKinds:   []string{"interpreted_string_literal", "raw_string_literal"},
			MemberKinds:   []string{"selector_expression"},
			ReturnKinds:   []string{"return_statement"},
			ForKinds:      []string{"for_statement"},
		},
	},
	{
		ID: Python,
		// .pyw is a Python source file run without a console window on
		// Windows (setup.py's own GUI-script convention); the language
		// underneath it is identical to .py
		Extensions: []string{".py", ".pyi", ".pyw"},
		load:       tspy.Language,
		Grammar: Grammar{
			FunctionKinds: []string{"function_definition"},
			ClassKinds:    []string{"class_definition"},
			CallKinds:     []string{"call"},
			AssignKinds:   []string{"assignment", "augmented_assignment"},
			StringKinds:   []string{"string"},
			MemberKinds:   []string{"attribute"},
			ReturnKinds:   []string{"return_statement"},
			ForKinds:      []string{"for_statement"},
		},
	},
	{
		ID:         JavaScript,
		Extensions: []string{".js", ".mjs", ".cjs", ".jsx"},
		load:       tsjs.Language,
		Grammar: Grammar{
			FunctionKinds: []string{"function_declaration", "function_expression", "arrow_function", "method_definition"},
			ClassKinds:    []string{"class_declaration"},
			CallKinds:     []string{"call_expression", "new_expression"},
			AssignKinds:   []string{"variable_declarator", "assignment_expression", "augmented_assignment_expression"},
			StringKinds:   []string{"string"},
			MemberKinds:   []string{"member_expression"},
			ReturnKinds:   []string{"return_statement"},
			ForKinds:      []string{"for_statement", "for_in_statement"},
		},
	},
	{
		ID: TypeScript,
		// .mts and .cts are TypeScript's ESM and CommonJS module
		// extensions (the same distinction .mjs/.cjs make for JavaScript);
		// the language is the same TypeScript grammar as .ts
		Extensions: []string{".ts", ".tsx", ".mts", ".cts"},
		load:       tsts.LanguageTypescript,
		Grammar: Grammar{
			FunctionKinds: []string{"function_declaration", "function_expression", "arrow_function", "method_definition"},
			ClassKinds:    []string{"class_declaration"},
			CallKinds:     []string{"call_expression", "new_expression"},
			AssignKinds:   []string{"variable_declarator", "assignment_expression", "augmented_assignment_expression"},
			StringKinds:   []string{"string"},
			MemberKinds:   []string{"member_expression"},
			ReturnKinds:   []string{"return_statement"},
			ForKinds:      []string{"for_statement", "for_in_statement"},
		},
	},
	{
		ID:         Java,
		Extensions: []string{".java"},
		load:       tsjava.Language,
		Grammar: Grammar{
			FunctionKinds: []string{"method_declaration"},
			ClassKinds:    []string{"class_declaration"},
			CallKinds:     []string{"method_invocation", "object_creation_expression"},
			AssignKinds:   []string{"variable_declarator", "assignment_expression"},
			StringKinds:   []string{"string_literal"},
			MemberKinds:   []string{"field_access"},
			ReturnKinds:   []string{"return_statement"},
			ForKinds:      []string{"for_statement", "enhanced_for_statement"},
		},
	},
	{
		ID:         Rust,
		Extensions: []string{".rs"},
		load:       tsrust.Language,
		Grammar: Grammar{
			FunctionKinds: []string{"function_item", "closure_expression"},
			CallKinds:     []string{"call_expression", "macro_invocation"},
			AssignKinds:   []string{"let_declaration", "assignment_expression"},
			StringKinds:   []string{"string_literal"},
			MemberKinds:   []string{"field_expression"},
			ReturnKinds:   []string{"return_expression"},
			ForKinds:      []string{"for_expression"},
		},
	},
}

// All returns every supported language's adapter, sorted by ID. Every
// adapter is always returned, even one whose grammar fails to load: callers
// must report that as a coverage skip, never drop the language silently.
func All() []*Adapter { return all }

// ForExt returns the adapter that owns extension ext (including the dot), or
// nil if no language claims it
func ForExt(ext string) *Adapter {
	for _, a := range all {
		if slices.Contains(a.Extensions, ext) {
			return a
		}
	}
	return nil
}

// ByID returns the adapter for id, or nil
func ByID(id ID) *Adapter {
	for _, a := range all {
		if a.ID == id {
			return a
		}
	}
	return nil
}
