package main

import "os/exec"

func runArchive(name string) (string, error) {
	out, err := exec.Command("tar", "czf", "/tmp/out.tgz", name).CombinedOutput()
	return string(out), err
}
