package osv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPClientQuerySendsCoordinateAndParsesVulns(t *testing.T) {
	var captured queryRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&captured)
		json.NewEncoder(w).Encode(queryResponse{Vulns: []Vuln{{
			ID:      "GHSA-xxxx-yyyy-zzzz",
			Aliases: []string{"CVE-2023-9999"},
			Summary: "a bad thing",
			Affected: []Affected{{
				Package: struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
					Purl      string `json:"purl,omitempty"`
				}{Ecosystem: "npm", Name: "lodash"},
				Ranges:           []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "4.17.21"}}}},
				DatabaseSpecific: map[string]any{"severity": "HIGH"},
			}},
		}}})
	}))
	defer srv.Close()

	c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
	vulns, err := c.Query(context.Background(), Coordinate{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"})
	if err != nil {
		t.Fatal(err)
	}
	if captured.Package.Name != "lodash" || captured.Package.Ecosystem != "npm" || captured.Version != "4.17.15" {
		t.Fatalf("query request did not carry the coordinate: %+v", captured)
	}
	if len(vulns) != 1 || vulns[0].ID != "GHSA-xxxx-yyyy-zzzz" {
		t.Fatalf("got %+v", vulns)
	}
	if vulns[0].Severity() != "HIGH" {
		t.Fatalf("Severity() = %q, want HIGH", vulns[0].Severity())
	}
	if got := vulns[0].FixedVersions("lodash"); len(got) != 1 || got[0] != "4.17.21" {
		t.Fatalf("FixedVersions() = %v, want [4.17.21]", got)
	}
}

func TestHTTPClientNonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
	if _, err := c.Query(context.Background(), Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); err == nil {
		t.Fatal("expected an error on a non-200 response")
	}
}

func TestHTTPClientQueryFailsClosedWithNoClient(t *testing.T) {
	c := &HTTPClient{BaseURL: "https://example.invalid"}
	if _, err := c.Query(context.Background(), Coordinate{Ecosystem: "npm", Name: "x", Version: "1.0.0"}); err == nil {
		t.Fatal("expected an error with no Client configured, not a silent fall back to http.DefaultClient")
	}
}

type fakeQuerier struct {
	byCoord map[Coordinate][]Vuln
	err     error
}

func (f fakeQuerier) Query(ctx context.Context, c Coordinate) ([]Vuln, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byCoord[c], nil
}

func TestQueryAllCollectsOnlyAffectedCoordinates(t *testing.T) {
	clean := Coordinate{Ecosystem: "npm", Name: "clean", Version: "1.0.0"}
	bad := Coordinate{Ecosystem: "npm", Name: "bad", Version: "0.1.0"}
	q := fakeQuerier{byCoord: map[Coordinate][]Vuln{bad: {{ID: "GHSA-1"}}}}
	got, err := QueryAll(context.Background(), q, []Coordinate{clean, bad})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (only the affected coordinate)", len(got))
	}
	if _, ok := got[bad]; !ok {
		t.Fatal("missing the affected coordinate's result")
	}
}

func TestQueryAllPropagatesFailure(t *testing.T) {
	q := fakeQuerier{err: errors.New("network down")}
	_, err := QueryAll(context.Background(), q, []Coordinate{{Ecosystem: "npm", Name: "x", Version: "1.0.0"}})
	if err == nil {
		t.Fatal("expected the querier's failure to propagate")
	}
}

func TestQueryAllUsesBatchWhenTheQuerierSupportsIt(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequestBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		results := make([]batchResult, len(req.Queries))
		for i, q := range req.Queries {
			if q.Package.Name == "left-pad" {
				results[i] = batchResult{Vulns: []minimalVuln{{ID: "GHSA-1"}}}
			}
		}
		json.NewEncoder(w).Encode(batchResponseBody{Results: results})
	})
	mux.HandleFunc("/vulns/GHSA-1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Vuln{ID: "GHSA-1", Summary: "bad thing"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
	bad := Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}
	got, err := QueryAll(context.Background(), c, []Coordinate{bad})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[bad]) != 1 || got[bad][0].ID != "GHSA-1" {
		t.Fatalf("got %v, want one GHSA-1 result for left-pad", got)
	}
}

func TestHTTPClientQueryBatchHydratesAdvisoriesPerCoordinate(t *testing.T) {
	lodash := Coordinate{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"}
	leftpad := Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}
	clean := Coordinate{Ecosystem: "npm", Name: "clean", Version: "1.0.0"}

	summaries := map[string]string{
		"GHSA-lodash":    "lodash prototype pollution",
		"GHSA-leftpad-1": "left-pad advisory one",
		"GHSA-leftpad-2": "left-pad advisory two",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req batchRequestBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if len(req.Queries) != 3 {
			t.Fatalf("batch request carried %d queries, want 3", len(req.Queries))
		}
		results := make([]batchResult, len(req.Queries))
		for i, q := range req.Queries {
			switch q.Package.Name {
			case "lodash":
				results[i] = batchResult{Vulns: []minimalVuln{{ID: "GHSA-lodash"}}}
			case "left-pad":
				results[i] = batchResult{Vulns: []minimalVuln{{ID: "GHSA-leftpad-1"}, {ID: "GHSA-leftpad-2"}}}
			}
		}
		json.NewEncoder(w).Encode(batchResponseBody{Results: results})
	})
	mux.HandleFunc("/vulns/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/vulns/")
		s, ok := summaries[id]
		if !ok {
			t.Fatalf("unexpected advisory fetch for %s", id)
		}
		json.NewEncoder(w).Encode(Vuln{ID: id, Summary: s})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
	got, err := QueryAll(context.Background(), c, []Coordinate{lodash, leftpad, clean})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d affected coordinates, want 2 (clean must be absent): %v", len(got), got)
	}
	if len(got[lodash]) != 1 || got[lodash][0].Summary != "lodash prototype pollution" {
		t.Fatalf("lodash result = %+v", got[lodash])
	}
	if len(got[leftpad]) != 2 {
		t.Fatalf("left-pad result = %+v, want 2 advisories", got[leftpad])
	}
	if _, ok := got[clean]; ok {
		t.Fatal("clean coordinate must not appear in results")
	}
}

func TestHTTPClientQueryBatchShortResponseIsGapNotClean(t *testing.T) {
	coords := []Coordinate{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "b", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "c", Version: "1.0.0"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		// Two results for three queries
		json.NewEncoder(w).Encode(batchResponseBody{Results: []batchResult{{}, {}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
	got, err := c.QueryBatch(context.Background(), coords)
	if err == nil {
		t.Fatal("expected an error when the batch response is shorter than the request")
	}
	if len(got) != 0 {
		t.Fatalf("a short response must not be read as any coordinate being clean, got %v", got)
	}
}

func TestHTTPClientQueryBatchNonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
	if _, err := c.QueryBatch(context.Background(), []Coordinate{{Ecosystem: "npm", Name: "x", Version: "1.0.0"}}); err == nil {
		t.Fatal("expected an error on a non-200 response")
	}
}

func TestHTTPClientQueryBatchPagesLargeCoordinateLists(t *testing.T) {
	n := batchChunkSize + 10
	coords := make([]Coordinate, n)
	for i := range coords {
		coords[i] = Coordinate{Ecosystem: "npm", Name: fmt.Sprintf("pkg%d", i), Version: "1.0.0"}
	}

	var requests, seen int
	mux := http.NewServeMux()
	mux.HandleFunc("/querybatch", func(w http.ResponseWriter, r *http.Request) {
		requests++
		var req batchRequestBody
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if len(req.Queries) > batchChunkSize {
			t.Fatalf("one request carried %d queries, want at most %d", len(req.Queries), batchChunkSize)
		}
		seen += len(req.Queries)
		json.NewEncoder(w).Encode(batchResponseBody{Results: make([]batchResult, len(req.Queries))})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &HTTPClient{BaseURL: srv.URL, Client: srv.Client()}
	if _, err := c.QueryBatch(context.Background(), coords); err != nil {
		t.Fatal(err)
	}
	if requests < 2 {
		t.Fatalf("got %d request(s), want more than 1 to page through %d coordinates", requests, n)
	}
	if seen != n {
		t.Fatalf("server saw %d coordinate(s) total, want %d", seen, n)
	}
}
