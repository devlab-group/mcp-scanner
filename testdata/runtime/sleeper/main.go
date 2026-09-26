// Command sleeper spawns a child that sleeps far longer than any test timeout, then sleeps
// itself
package main

import (
	"os"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		time.Sleep(10 * time.Minute)
		return
	}
	if exe, err := os.Executable(); err == nil {
		p, err := os.StartProcess(exe, []string{exe, "child"}, &os.ProcAttr{
			Files: []*os.File{nil, os.Stdout, os.Stderr},
		})
		if err == nil {
			defer p.Release()
		}
	}
	time.Sleep(10 * time.Minute)
}
