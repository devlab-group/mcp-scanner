//go:build !unix

package transport

import "os/exec"

// On platforms without POSIX process groups the SDK's own shutdown of the target process is
// all that happens; helpers the target starts are not tracked
func setProcessGroup(*exec.Cmd)  {}
func killProcessGroup(*exec.Cmd) {}
