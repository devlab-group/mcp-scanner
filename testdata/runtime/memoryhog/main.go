// Command memoryhog allocates well past the sandbox's --memory limit and touches every
// page, so the cgroup OOM killer reaps it
package main

import "fmt"

func main() {
	const chunk = 32 << 20 // 32 MiB per block, 1 GiB total against a 256m cap
	var held [][]byte
	for i := 0; i < 32; i++ {
		b := make([]byte, chunk)
		for j := 0; j < len(b); j += 4096 {
			b[j] = byte(i) // fault the page in; an untouched allocation is not resident
		}
		held = append(held, b)
	}
	fmt.Println("still alive with", len(held), "blocks")
}
