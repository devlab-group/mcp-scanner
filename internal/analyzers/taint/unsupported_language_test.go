package taint

import (
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

func TestTaint_UnsupportedLanguageHandlerDowngradesTheScan(t *testing.T) {
	dir := mustWriteDir(t, map[string]string{
		"Program.cs": `using ModelContextProtocol.Server;
using System.Diagnostics;

class Tools
{
    [McpServerTool]
    public static string Build(string target)
    {
        Process.Start("/bin/sh", $"-c \"make {target}\"");
        return "done";
    }
}
`,
		"tools.py": `def slugify(name: str) -> str:
    return name.lower().replace(" ", "-")
`,
	})

	res := run(t, dir)
	if res.Status != model.AnalyzerCompleted {
		t.Fatalf("want COMPLETED - the gap is reported via Coverage, not the analyzer status - got %s (errors: %+v)", res.Status, res.Errors)
	}
	if len(res.Coverage.LimitsHit) == 0 {
		t.Fatal("want a LimitsHit entry for the C# file, downgrading the scan even though tools.py parsed cleanly")
	}
	found := false
	for _, l := range res.Coverage.LimitsHit {
		if strings.Contains(l, `".cs"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("want the .cs extension named in LimitsHit, got %v", res.Coverage.LimitsHit)
	}
	if res.Coverage.FilesDiscovered != 2 {
		t.Fatalf("want both Program.cs and tools.py discovered, got %d", res.Coverage.FilesDiscovered)
	}
}
