package graph

import (
	"fmt"
	"reflect"
	"testing"
)

// An indexed graph answers as one that reads every call, in the same order, and a graph that grew
// after it was indexed is read in full again
func TestCallsFromIndexed(t *testing.T) {
	g := New("")
	for i := range 60 {
		g.Calls = append(g.Calls, Call{Caller: SymbolID(fmt.Sprintf("f%d", i%7)), CalleeText: fmt.Sprintf("c%d", i), Line: i})
	}
	linear := map[SymbolID][]Call{}
	for i := range 8 {
		id := SymbolID(fmt.Sprintf("f%d", i))
		linear[id] = g.CallsFrom(id)
	}
	g.IndexCalls()
	for id, want := range linear {
		if got := g.CallsFrom(id); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: indexed %v, linear %v", id, got, want)
		}
	}
	g.Calls = append(g.Calls, Call{Caller: "f1", CalleeText: "late"})
	if got := g.CallsFrom("f1"); len(got) != len(linear["f1"])+1 || got[len(got)-1].CalleeText != "late" {
		t.Fatalf("a call added after indexing is missing: %v", got)
	}
}
