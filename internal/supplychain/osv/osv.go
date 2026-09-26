// Package osv queries the OSV (Open Source Vulnerabilities) database for a set of
// ecosystem/name/version coordinates, and parses the lockfile formats that produce those
// coordinates in the first place
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/revinand/mcp-scanner/internal/httpx"
)

// Coordinate identifies one package version to check. Ecosystem follows
// OSV's own vocabulary: "npm", "PyPI", "Go", "crates.io".
type Coordinate struct {
	Ecosystem string
	Name      string
	Version   string
}

func (c Coordinate) String() string { return fmt.Sprintf("%s:%s@%s", c.Ecosystem, c.Name, c.Version) }

// Event is one point in an affected-version range
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Range is one affected-version range, e.g. a SEMVER range with an
// "introduced" and a "fixed" event
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Affected is one package's affected-version data within a Vuln
type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Purl      string `json:"purl,omitempty"`
	} `json:"package"`
	Ranges           []Range        `json:"ranges,omitempty"`
	Versions         []string       `json:"versions,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

// Vuln is one OSV record
type Vuln struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases,omitempty"` // typically CVE and/or GHSA ids
	Summary          string         `json:"summary,omitempty"`
	Details          string         `json:"details,omitempty"`
	Affected         []Affected     `json:"affected,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

// Severity returns OSV's own severity label when the record carries one,
// preferring the top-level field and falling back to the first affected
// entry that has one. It returns "" when OSV did not classify it, which
// callers should treat as "confirmed affected, severity unknown" rather
// than as a reason to drop the finding.
func (v Vuln) Severity() string {
	if s, ok := stringField(v.DatabaseSpecific, "severity"); ok {
		return s
	}
	for _, a := range v.Affected {
		if s, ok := stringField(a.DatabaseSpecific, "severity"); ok {
			return s
		}
	}
	return ""
}

// FixedVersions collects every "fixed" event across every range for the
// named package, so a report can tell a reader what to upgrade to
func (v Vuln) FixedVersions(name string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range v.Affected {
		if a.Package.Name != "" && a.Package.Name != name {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && !seen[e.Fixed] {
					seen[e.Fixed] = true
					out = append(out, e.Fixed)
				}
			}
		}
	}
	return out
}

func stringField(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok && s != ""
}

// Querier looks up vulnerabilities for one coordinate. The HTTP client
// below implements it against the live API; tests implement it against a
// fixed set of recorded responses.
type Querier interface {
	Query(ctx context.Context, coord Coordinate) ([]Vuln, error)
}

const defaultBaseURL = "https://api.osv.dev/v1"

// HTTPClient is a Querier backed by the public OSV API. Its client is
// guarded by httpx: no private-network destination, dial-time enforcement,
// no cross-origin redirect followed - the same policy a registry fetch
// gets, since this is the same class of fixed, third-party network call.
type HTTPClient struct {
	BaseURL string
	Client  *http.Client
}

// NewHTTPClient builds a Querier against the public OSV API
func NewHTTPClient() *HTTPClient {
	return &HTTPClient{BaseURL: defaultBaseURL, Client: httpx.DefaultPolicy().Client(30 * time.Second)}
}

type queryRequest struct {
	Version string `json:"version,omitempty"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

type queryResponse struct {
	Vulns []Vuln `json:"vulns"`
}

func (c *HTTPClient) Query(ctx context.Context, coord Coordinate) ([]Vuln, error) {
	body := queryRequest{Version: coord.Version}
	body.Package.Name = coord.Name
	body.Package.Ecosystem = coord.Ecosystem

	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("osv: encode query for %s: %w", coord, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.BaseURL, "/")+"/query", bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("osv: build request for %s: %w", coord, err)
	}
	req.Header.Set("Content-Type", "application/json")

	// NewHTTPClient always sets a guarded client, so this path is unreachable
	// through it - but the struct is exported and constructible directly,
	// and a nil Client falling back to http.DefaultClient is the one place
	// an unguarded client could enter an outbound path. Failing closed here
	// costs nothing and removes that footgun.
	if c.Client == nil {
		return nil, fmt.Errorf("osv: no HTTP client configured (use NewHTTPClient, which sets a guarded one)")
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: query %s: %w", coord, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: query %s returned status %d", coord, resp.StatusCode)
	}

	var parsed queryResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("osv: could not parse response for %s: %w", coord, err)
	}
	return parsed.Vulns, nil
}

// BatchQuerier is a Querier that can also look up many coordinates in one
// round trip. QueryAll uses it when the Querier passed in implements it -
// HTTPClient does - and falls back to Query per coordinate otherwise, which
// is what a test double implementing only Querier gets.
type BatchQuerier interface {
	Querier
	QueryBatch(ctx context.Context, coords []Coordinate) (map[Coordinate][]Vuln, error)
}

// QueryAll looks up every coordinate, stopping early on context
// cancellation. It returns partial results alongside any error so a caller
// can still report what it managed to check.
func QueryAll(ctx context.Context, q Querier, coords []Coordinate) (map[Coordinate][]Vuln, error) {
	if bq, ok := q.(BatchQuerier); ok {
		return bq.QueryBatch(ctx, coords)
	}
	out := make(map[Coordinate][]Vuln, len(coords))
	for _, c := range coords {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		vulns, err := q.Query(ctx, c)
		if err != nil {
			return out, fmt.Errorf("osv: %w", err)
		}
		if len(vulns) > 0 {
			out[c] = vulns
		}
	}
	return out, nil
}

// batchChunkSize stays below OSV's 1000-query request cap and bounds request/response memory
const batchChunkSize = 500

type batchQuery struct {
	Version string `json:"version,omitempty"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

type batchRequestBody struct {
	Queries []batchQuery `json:"queries"`
}

// minimalVuln is what querybatch returns per hit: an id and a modified timestamp, not the
// summary/affected/aliases a finding needs. QueryBatch therefore hydrates each distinct ID
// once before attaching full records to their coordinates.
type minimalVuln struct {
	ID string `json:"id"`
}

type batchResult struct {
	Vulns []minimalVuln `json:"vulns"`
	// NextPageToken means this coordinate has more matching advisories than fit on one page. The
	// batch client does not follow it, so later advisories are omitted.
	NextPageToken string `json:"next_page_token,omitempty"`
}

type batchResponseBody struct {
	Results []batchResult `json:"results"`
}

// QueryBatch sends bounded chunks and maps each positional response back to its coordinate.
// A short response is an error because treating the missing positions as empty would report
// unchecked packages as clean.
func (c *HTTPClient) QueryBatch(ctx context.Context, coords []Coordinate) (map[Coordinate][]Vuln, error) {
	out := make(map[Coordinate][]Vuln, len(coords))
	idsByCoord := make(map[Coordinate][]string)
	wantIDs := make(map[string]bool)

	for start := 0; start < len(coords); start += batchChunkSize {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		end := min(start+batchChunkSize, len(coords))
		chunk := coords[start:end]

		results, err := c.postQueryBatch(ctx, chunk)
		if err != nil {
			return out, err
		}
		if len(results) != len(chunk) {
			return out, fmt.Errorf("osv: querybatch returned %d result(s) for %d coordinate(s), cannot tell which is which", len(results), len(chunk))
		}
		for i, r := range results {
			if len(r.Vulns) == 0 {
				continue
			}
			coord := chunk[i]
			ids := make([]string, len(r.Vulns))
			for j, v := range r.Vulns {
				ids[j] = v.ID
				wantIDs[v.ID] = true
			}
			idsByCoord[coord] = ids
		}
	}

	full := make(map[string]Vuln, len(wantIDs))
	for id := range wantIDs {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		v, err := c.getVuln(ctx, id)
		if err != nil {
			return out, fmt.Errorf("osv: fetch advisory %s: %w", id, err)
		}
		full[id] = v
	}

	for coord, ids := range idsByCoord {
		vulns := make([]Vuln, 0, len(ids))
		for _, id := range ids {
			vulns = append(vulns, full[id])
		}
		out[coord] = vulns
	}
	return out, nil
}

func (c *HTTPClient) postQueryBatch(ctx context.Context, coords []Coordinate) ([]batchResult, error) {
	body := batchRequestBody{Queries: make([]batchQuery, len(coords))}
	for i, coord := range coords {
		body.Queries[i].Version = coord.Version
		body.Queries[i].Package.Name = coord.Name
		body.Queries[i].Package.Ecosystem = coord.Ecosystem
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("osv: encode batch query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.BaseURL, "/")+"/querybatch", bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("osv: build batch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Same footgun guard as Query: NewHTTPClient always sets one, but the
	// struct is exported and constructible directly
	if c.Client == nil {
		return nil, fmt.Errorf("osv: no HTTP client configured (use NewHTTPClient, which sets a guarded one)")
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: batch query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: batch query returned status %d", resp.StatusCode)
	}

	// A batch response is still just ids and timestamps, but a chunk this
	// size can legitimately carry more of them than a single query's
	// response ever would - double the single-query cap for the same
	// "bounded but generous" reason that cap exists
	var parsed batchResponseBody
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("osv: could not parse batch response: %w", err)
	}
	return parsed.Results, nil
}

// getVuln fetches one advisory's full record - the fields querybatch does not return - by
// id. The ID comes from a provider response and is path-escaped before it becomes part of a URL.
func (c *HTTPClient) getVuln(ctx context.Context, id string) (Vuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.BaseURL, "/")+"/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		return Vuln{}, fmt.Errorf("osv: build request for advisory %s: %w", id, err)
	}
	if c.Client == nil {
		return Vuln{}, fmt.Errorf("osv: no HTTP client configured (use NewHTTPClient, which sets a guarded one)")
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return Vuln{}, fmt.Errorf("osv: fetch advisory %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Vuln{}, fmt.Errorf("osv: advisory %s returned status %d", id, resp.StatusCode)
	}

	var v Vuln
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&v); err != nil {
		return Vuln{}, fmt.Errorf("osv: could not parse advisory %s: %w", id, err)
	}
	return v, nil
}
