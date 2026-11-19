package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// A 503 or a dropped connection from OSV is retried; a 400 is an answer and is not
func TestQueryRetriesTransientFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []int
		wantErr  bool
		wantHits int32
	}{
		{"503 then 200", []int{503, 200}, false, 2},
		{"429 twice then 200", []int{429, 429, 200}, false, 3},
		{"500 every time", []int{500, 500, 500, 500}, true, 3},
		{"400 is final", []int{400, 200}, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				i := hits.Add(1) - 1
				w.WriteHeader(tc.statuses[min(int(i), len(tc.statuses)-1)])
				if tc.statuses[min(int(i), len(tc.statuses)-1)] == 200 {
					w.Write([]byte(`{"vulns":[]}`))
				}
			}))
			defer srv.Close()
			c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
			_, err := c.Query(context.Background(), Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"})
			if (err != nil) != tc.wantErr || hits.Load() != tc.wantHits {
				t.Fatalf("err=%v hits=%d, want err=%v hits=%d", err, hits.Load(), tc.wantErr, tc.wantHits)
			}
		})
	}
}

// Advisories are fetched several at a time; every one arrives, and one that cannot be fetched
// fails the lookup rather than leaving a partial answer that reads as clean
func TestAdvisoriesFetchedConcurrently(t *testing.T) {
	for _, failID := range []string{"", "GHSA-7"} {
		var inFlight, peak atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/querybatch" {
				w.Write([]byte(`{"results":[{"vulns":[` + vulnIDs(12) + `]}]}`))
				return
			}
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(20 * time.Millisecond)
			id := r.URL.Path[len("/vulns/"):]
			if id == failID {
				w.WriteHeader(404)
				return
			}
			w.Write([]byte(`{"id":"` + id + `"}`))
		}))
		c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
		got, err := c.QueryBatch(context.Background(), []Coordinate{{Ecosystem: "npm", Name: "x", Version: "1"}})
		srv.Close()
		if failID != "" {
			if err == nil {
				t.Fatalf("a failed advisory fetch must fail the lookup, got %v", got)
			}
			continue
		}
		if err != nil || len(got[Coordinate{Ecosystem: "npm", Name: "x", Version: "1"}]) != 12 {
			t.Fatalf("want 12 advisories, got %v, %v", got, err)
		}
		if peak.Load() < 2 {
			t.Fatalf("advisories were fetched one at a time (peak %d)", peak.Load())
		}
	}
}

func vulnIDs(n int) string {
	var b []byte
	for i := 1; i <= n; i++ {
		if i > 1 {
			b = append(b, ',')
		}
		b = append(b, []byte(`{"id":"GHSA-`+strconv.Itoa(i)+`"}`)...)
	}
	return string(b)
}
