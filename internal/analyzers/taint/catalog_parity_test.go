package taint

import (
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/source/language"
)

var operationParity = map[string]map[language.ID]string{
	"list_directory": {
		language.Go:         "os.ReadDir",
		language.Python:     "os.listdir",
		language.JavaScript: "readdir",
		language.TypeScript: "readdir",
		language.Java:       "Files.list",
		language.Rust:       "std::fs::read_dir",
	},
	"rename": {
		language.Go:         "os.Rename",
		language.Python:     "os.rename",
		language.JavaScript: "rename",
		language.TypeScript: "rename",
		language.Java:       "Files.move",
		language.Rust:       "std::fs::rename",
	},
	"create_directory": {
		language.Go:         "os.Mkdir",
		language.Python:     "os.makedirs",
		language.JavaScript: "mkdir",
		language.TypeScript: "mkdir",
		language.Java:       "Files.createDirectory",
		language.Rust:       "std::fs::create_dir",
	},
	"change_mode": {
		language.Go:         "os.Chmod",
		language.Python:     "os.chmod",
		language.JavaScript: "chmod",
		language.TypeScript: "chmod",
		language.Java:       "Files.setPosixFilePermissions",
		language.Rust:       "std::fs::set_permissions",
	},
	"symlink": {
		language.Go:         "os.Symlink",
		language.Python:     "os.symlink",
		language.JavaScript: "symlink",
		language.TypeScript: "symlink",
		language.Java:       "Files.createSymbolicLink",
		language.Rust:       "std::os::unix::fs::symlink",
	},
}

func allCatalogueTexts() map[string]bool {
	texts := make(map[string]bool, len(sinkPatterns)+len(methodSinkPatterns)+len(argvSinks))
	for _, p := range sinkPatterns {
		texts[p.text] = true
	}
	for _, p := range methodSinkPatterns {
		texts[p.text] = true
	}
	for _, s := range argvSinks {
		texts[s.text] = true
	}
	return texts
}

func TestCatalog_LanguageParity(t *testing.T) {
	have := allCatalogueTexts()
	langs := language.All()
	for category, byLang := range operationParity {
		for _, adapter := range langs {
			text, ok := byLang[adapter.ID]
			if !ok {
				t.Errorf("%s: no entry declared for language %s", category, adapter.ID)
				continue
			}
			if !have[text] {
				t.Errorf("%s/%s: declared entry %q is not in the catalogue", category, adapter.ID, text)
			}
		}
		if len(byLang) != len(langs) {
			t.Errorf("%s: declares %d language(s), want exactly the %d in language.All()", category, len(byLang), len(langs))
		}
	}
}

var nodeFsPromiseMethods = []string{
	"readFile", "writeFile", "appendFile", "unlink", "rm", "rmdir",
	"rename", "copyFile", "cp", "mkdir", "open", "opendir", "readdir",
	"chmod", "symlink",
}

func TestCatalog_SyncTwins(t *testing.T) {
	promise := make(map[string]bool, len(methodSinkPatterns))
	for _, p := range methodSinkPatterns {
		promise[p.text] = true
	}
	sync := make(map[string]bool, len(sinkPatterns))
	for _, p := range sinkPatterns {
		sync[p.text] = true
	}
	for _, name := range nodeFsPromiseMethods {
		if !promise[name] {
			t.Errorf("%q is declared a node:fs/promises method but is not in methodSinkPatterns", name)
		}
		if !sync[name+"Sync"] {
			t.Errorf("%q has no %qSync entry in sinkPatterns, so the synchronous call is not a sink", name, name)
		}
	}
}
