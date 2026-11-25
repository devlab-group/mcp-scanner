//go:build unix

package transport

import (
	"os/exec"
	"syscall"
)

// setProcessGroup starts the target as the leader of a new process group, so everything it
// starts - the real server under an npx or uvx wrapper, or a helper it puts in the background -
// can be found and ended together
func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessGroup kills every process left in the target's group. The target process itself
// has already been waited for by then; an empty group is not an error.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
