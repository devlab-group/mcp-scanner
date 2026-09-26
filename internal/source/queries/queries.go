// Package queries embeds the tree-sitter query files for every supported
// language, so parsing never depends on a query file being present on disk
// at runtime
package queries

import "embed"

//go:embed */*.scm
var fs embed.FS

// Read returns the source of one query file, for example Read("go", "symbols").
// It panics on a missing file: the embedded set is fixed at build time, so a
// missing query is a programming error, not a runtime condition.
func Read(lang, name string) string {
	b, err := fs.ReadFile(lang + "/" + name + ".scm")
	if err != nil {
		panic("queries: no " + name + ".scm for " + lang + ": " + err.Error())
	}
	return string(b)
}

// Has reports whether a query file exists for the language, for queries that
// are optional (not every language has decorators)
func Has(lang, name string) bool {
	_, err := fs.ReadFile(lang + "/" + name + ".scm")
	return err == nil
}
