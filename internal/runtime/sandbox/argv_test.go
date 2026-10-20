package sandbox

import (
	"strings"
	"testing"

	"github.com/devlab-group/mcp-scanner/internal/runtime/canary"
)

func TestSawToolCallResponse(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   bool
	}{
		// Initialization alone does not prove the tool ran
		{"initialize result only", `{"jsonrpc":"2.0","id":1,"result":{}}` + "\npanic: assignment to entry in nil map\n", false},
		{"initialize then tool call", `{"jsonrpc":"2.0","id":1,"result":{}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{}}`, true},
		{"tool call id as a string", `{"jsonrpc":"2.0","id":"2","result":{}}`, false},
		{"tool call result", "noise\n" + `{"jsonrpc":"2.0","id":2,"result":{"content":[]}}` + "\nmore", true},
		{"error response still answered", `{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"no"}}`, true},
		{"usage text only", "usage: server --config FILE\n", false},
		{"notification carries no id", `{"jsonrpc":"2.0","method":"notifications/message"}`, false},
		{"self-report line only", "MCP-OBS:file_read:/etc/passwd\n", false},
		{"nothing at all", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sawToolCallResponse(tc.stdout); got != tc.want {
				t.Errorf("sawToolCallResponse(%q) = %v, want %v", tc.stdout, got, tc.want)
			}
		})
	}
}

func TestBuildArgsSetsHome(t *testing.T) {
	got := buildArgs(spec{
		ContainerName: "mcpscan-home",
		Image:         "img",
		MountDir:      "/tmp/run",
		WorkDir:       "/work",
		Entrypoint:    "/sandbox/entrypoint",
		Env:           map[string]string{"HOME": canary.ContainerHome},
		Memory:        "256m",
		CPUs:          "1.0",
		PIDsLimit:     64,
		TmpfsSize:     "64m",
	})
	want := "HOME=" + canary.ContainerHome
	found := false
	for _, a := range got {
		if a == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("argv does not set %s: %s", want, strings.Join(got, " "))
	}
}

// Treat Docker's reserved exit codes and daemon exec errors as sandbox failures
func TestDockerRunFailed(t *testing.T) {
	cases := []struct {
		code   int
		stderr string
		want   bool
	}{
		{125, "", true},
		{126, "", true},
		{127, "", true},
		{255, "exec " + sandboxEntrypoint + ": no such file or directory", true},
		// docker start reports runc entrypoint failures as exit 1 with a daemon error
		{1, "Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: exec: \"/sandbox/entrypoint\": permission denied: unknown", true},
		{1, "Error response from daemon: failed to create task for container: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: exec: \"/sandbox/entrypoint\": stat /sandbox/entrypoint: no such file or directory: unknown", true},
		{0, "", false},
		{1, "usage: server", false},
		{2, "panic: nil map", false},
		{137, "", false},
	}
	for _, c := range cases {
		if _, got := dockerRunFailed(c.code, c.stderr); got != c.want {
			t.Errorf("dockerRunFailed(%d, %q) = %v, want %v", c.code, c.stderr, got, c.want)
		}
	}
}
