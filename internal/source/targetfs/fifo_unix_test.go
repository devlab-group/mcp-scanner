//go:build unix

package targetfs

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO in the tree would block an open for reading until something writes to it; the check
// before the open refuses it at once
func TestFIFOIsRefusedWithoutBlocking(t *testing.T) {
	root, _ := tree(t)
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.md"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, err := Read(root, "pipe.md", 100)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("err = %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read blocked on a FIFO")
	}
}
