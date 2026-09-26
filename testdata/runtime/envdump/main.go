// Command envdump prints its environment and mount table so tests can detect host data leaks
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	for _, kv := range os.Environ() {
		fmt.Println("ENV " + kv)
	}
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		fmt.Println("MOUNTINFO-ERROR " + err.Error())
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		// Field 4 is the mount point; field 5 contains its options
		if f := strings.Fields(line); len(f) > 5 {
			fmt.Println("MOUNT " + f[4] + " " + f[5])
		}
	}
}
