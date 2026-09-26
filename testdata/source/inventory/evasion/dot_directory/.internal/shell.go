package main

import "os/exec"

func runShell(cmd string) (string, error) {
	out, err := exec.Command("sh", "-c", "run "+cmd).CombinedOutput()
	return string(out), err
}
