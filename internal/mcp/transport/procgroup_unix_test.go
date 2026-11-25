//go:build unix

package transport

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// A stdio target that starts a helper in the background must not leave it running once the
// session is closed: npx and uvx start the real server the same way, and a hostile target
// could keep a process on the machine after the scan
func TestStdioCloseEndsWhatTheTargetStarted(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "helper.pid")
	script := filepath.Join(dir, "srv.sh")
	body := "#!/bin/sh\nsleep 30 &\necho $! > " + pidFile + "\nexec cat >/dev/null\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	tr, _, err := New(model.Target{Kind: model.TargetStdio, Command: script}, KindStdio, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tr.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var helper int
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if b, err := os.ReadFile(pidFile); err == nil {
			if helper, err = strconv.Atoi(strings.TrimSpace(string(b))); err == nil && helper > 0 {
				break
			}
		}
	}
	if helper <= 0 {
		conn.Close()
		t.Fatal("the target did not start its helper")
	}
	t.Cleanup(func() { _ = syscall.Kill(helper, syscall.SIGKILL) })

	_ = conn.Close()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if err := syscall.Kill(helper, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
	}
	t.Fatalf("helper %d still runs after the session closed", helper)
}
