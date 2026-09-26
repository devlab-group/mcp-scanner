package language

// unsupportedExtensions is a fixed list of plausible MCP source languages without adapters.
// Listed extensions count as gaps; unrelated formats such as .md and .png do not.
var unsupportedExtensions = map[string]bool{
	".cs": true, ".csx": true,
	".fs": true, ".fsx": true,
	".kt": true, ".kts": true,
	".scala": true, ".sc": true,
	".rb":    true,
	".php":   true,
	".swift": true,
	".m":     true, ".mm": true,
	".dart": true,
	".ex":   true, ".exs": true,
	".c": true, ".cc": true, ".cpp": true, ".cxx": true,
	".h": true, ".hpp": true, ".hxx": true,
	".sh": true, ".bash": true, ".zsh": true,
	".ps1": true, ".psm1": true,
	".bat": true, ".cmd": true,
	".lua": true, ".pl": true,
}

// IsUnsupportedSource reports whether lowercased ext is a known source-language extension whose
// missing adapter creates a coverage gap. Unrelated extensions also lack adapters but return false.
func IsUnsupportedSource(ext string) bool { return unsupportedExtensions[ext] }
