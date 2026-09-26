package taint

import (
	"strings"
	"testing"
	"unicode"
)

var dottedModuleAPI = map[string][]string{
	"python:os": {
		"os.system", "os.popen",
		"os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
		"os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
		"os.remove", "os.removedirs", "os.rename", "os.renames",
		"os.listdir", "os.walk", "os.scandir",
		"os.mkdir", "os.makedirs", "os.chmod", "os.symlink",
	},
	"python:shutil": {
		"shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree",
		"shutil.copyfileobj", "shutil.move", "shutil.rmtree",
		"shutil.unpack_archive",
	},
	"go:os": {
		"os.ReadFile", "os.WriteFile", "os.Open", "os.OpenFile",
		"os.Remove", "os.RemoveAll", "os.Create", "os.CreateTemp", "os.MkdirAll",
		"os.ReadDir", "os.Rename", "os.Symlink", "os.Mkdir", "os.Chmod", "os.Truncate",
	},
	"go:filepath": {
		"filepath.Walk", "filepath.WalkDir",
	},
	"java:nio.file.Files": {
		"Files.readAllBytes", "Files.write", "Files.writeString",
		"Files.list", "Files.move", "Files.createDirectory", "Files.createDirectories",
		"Files.setPosixFilePermissions", "Files.createSymbolicLink",
	},
	"rust:std::fs": {
		"std::fs::read", "std::fs::read_to_string", "std::fs::write",
		"std::fs::read_dir", "std::fs::rename", "std::fs::create_dir", "std::fs::create_dir_all",
		"std::fs::set_permissions", "std::os::unix::fs::symlink",
	},
}

var methodAPI = map[string][]string{
	"python:pathlib": {
		"read_text", "read_bytes", "write_text", "write_bytes", "open",
		"unlink", "rmdir", "iterdir", "glob", "rglob", "touch", "mkdir",
	},
	"python:archive": {"extractall"},
	"node:fs": {
		"readFile", "writeFile", "appendFile", "unlink", "rm", "rename",
		"copyFile", "createReadStream", "readdir", "cp", "opendir",
		"createWriteStream", "chmod", "symlink",
	},
}

func sinkPatternTextSet() map[string]bool {
	set := make(map[string]bool, len(sinkPatterns))
	for _, p := range sinkPatterns {
		set[p.text] = true
	}
	return set
}

func methodSinkPatternTextSet() map[string]bool {
	set := make(map[string]bool, len(methodSinkPatterns))
	for _, p := range methodSinkPatterns {
		set[p.text] = true
	}
	return set
}

// TestCatalog_DottedModuleAPIIsCatalogued is dottedModuleAPI's forward
// check: every function this list claims belongs in the catalogue must
// actually be there
func TestCatalog_DottedModuleAPIIsCatalogued(t *testing.T) {
	have := sinkPatternTextSet()
	for module, names := range dottedModuleAPI {
		for _, name := range names {
			if !have[name] {
				t.Errorf("%s: %q is listed in dottedModuleAPI but has no sinkPatterns entry", module, name)
			}
		}
	}
}

func TestCatalog_DottedModuleEntriesAreDeclared(t *testing.T) {
	declared := map[string]map[string]bool{}
	for module, names := range dottedModuleAPI {
		set := make(map[string]bool, len(names))
		for _, n := range names {
			set[n] = true
		}
		declared[module] = set
	}
	for _, p := range sinkPatterns {
		module, ok := classifyDottedModule(p.text)
		if !ok {
			continue
		}
		if !declared[module][p.text] {
			t.Errorf("%s: sinkPatterns has %q but dottedModuleAPI does not declare it", module, p.text)
		}
	}
}

// TestCatalog_MethodAPIIsCatalogued is methodAPI's forward check, the same
// shape as TestCatalog_DottedModuleAPIIsCatalogued for methodSinkPatterns
func TestCatalog_MethodAPIIsCatalogued(t *testing.T) {
	have := methodSinkPatternTextSet()
	for module, names := range methodAPI {
		for _, name := range names {
			if !have[name] {
				t.Errorf("%s: %q is listed in methodAPI but has no methodSinkPatterns entry", module, name)
			}
		}
	}
}

func classifyDottedModule(text string) (module string, ok bool) {
	switch {
	case strings.HasPrefix(text, "os."):
		rest := text[len("os."):]
		if rest != "" && unicode.IsUpper(rune(rest[0])) {
			return "go:os", true
		}
		return "python:os", true
	case strings.HasPrefix(text, "shutil."):
		return "python:shutil", true
	case strings.HasPrefix(text, "filepath."):
		return "go:filepath", true
	case strings.HasPrefix(text, "Files."):
		return "java:nio.file.Files", true
	case strings.HasPrefix(text, "std::fs::"), strings.HasPrefix(text, "std::os::unix::fs::"):
		return "rust:std::fs", true
	default:
		return "", false
	}
}
