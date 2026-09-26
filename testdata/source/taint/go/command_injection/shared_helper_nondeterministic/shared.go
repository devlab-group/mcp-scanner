// Two tools taint different parameters of this shared helper. Each seed combination must be
// analyzed independently so map iteration order cannot decide which flow is found.
package taintfixture

import "os/exec"

func runShared(a string, b string) {
	exec.Command("sh", "-c", "first "+a).Output()
	exec.Command("sh", "-c", "second "+b).Output()
}
