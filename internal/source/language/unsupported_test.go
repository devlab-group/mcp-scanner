package language

import "testing"

func TestIsUnsupportedSource_NoOverlapWithSupportedExtensions(t *testing.T) {
	for _, a := range All() {
		for _, ext := range a.Extensions {
			if IsUnsupportedSource(ext) {
				t.Errorf("%q is claimed by adapter %s but also listed in unsupportedExtensions", ext, a.ID)
			}
		}
	}
}

func TestIsUnsupportedSource_KnownLanguages(t *testing.T) {
	exts := []string{
		".cs", ".csx", ".kt", ".kts", ".rb", ".php", ".swift",
		".scala", ".sc", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",
		".fs", ".fsx", ".ex", ".exs", ".dart", ".m", ".mm", ".c",
	}
	for _, ext := range exts {
		if !IsUnsupportedSource(ext) {
			t.Errorf("%s: want IsUnsupportedSource true", ext)
		}
		if a := ForExt(ext); a != nil {
			t.Errorf("%s: want no adapter, got %s", ext, a.ID)
		}
	}
}

func TestIsUnsupportedSource_ShellAndScriptWrappers(t *testing.T) {
	exts := []string{
		".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".lua", ".pl",
	}
	for _, ext := range exts {
		if !IsUnsupportedSource(ext) {
			t.Errorf("%s: want IsUnsupportedSource true", ext)
		}
		if a := ForExt(ext); a != nil {
			t.Errorf("%s: want no adapter, got %s", ext, a.ID)
		}
	}
}

func TestIsUnsupportedSource_OrdinaryNonSourceStaysFalse(t *testing.T) {
	for _, ext := range []string{".md", ".png", ".json", ".yaml", ".txt", ".lock"} {
		if IsUnsupportedSource(ext) {
			t.Errorf("%s: want IsUnsupportedSource false", ext)
		}
	}
}
