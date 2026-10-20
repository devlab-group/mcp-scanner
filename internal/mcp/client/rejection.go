package client

import (
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

// httpStatusError adds the HTTP status code a request failed with to the
// underlying error, without losing it. It satisfies analyzer.StatusCoder,
// which is what a caller checks with errors.As to tell a clean 401/403
// rejection from a connection that never got a response.
type httpStatusError struct {
	status int
	err    error
}

func (e *httpStatusError) Error() string { return e.err.Error() }
func (e *httpStatusError) Unwrap() error { return e.err }
func (e *httpStatusError) Status() int   { return e.status }

var _ analyzer.StatusCoder = (*httpStatusError)(nil)

// authChallengeCap bounds how much of a WWW-Authenticate value the sniffer
// keeps. The header comes from a server the scan does not trust; an
// unbounded server-controlled string has no business landing in a snapshot,
// a report, or an API response.
const authChallengeCap = 256

// responseSniff records the latest HTTP status and WWW-Authenticate value without changing the
// exchange. Rejection classification uses the status code and the SDK's ErrSessionMissing
// sentinel, never unstable error prose.
type responseSniff struct {
	status atomic.Int32
	auth   atomic.Value // string; empty until a response carries the header
	// responses lets callers distinguish this request's status from an earlier response
	responses atomic.Int64
}

func (s *responseSniff) authHeader() string {
	v, _ := s.auth.Load().(string)
	return v
}

type statusSniffer struct {
	base  http.RoundTripper
	sniff *responseSniff
}

func (s statusSniffer) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := s.base.RoundTrip(req)
	if resp != nil {
		s.sniff.status.Store(int32(resp.StatusCode))
		s.sniff.responses.Add(1)
		if v := resp.Header.Get("WWW-Authenticate"); v != "" {
			if len(v) > authChallengeCap {
				v = v[:authChallengeCap] + "...(truncated)"
			}
			s.sniff.auth.Store(v)
		}
	}
	return resp, err
}

// snoopStatus attaches a statusSniffer to tr's HTTP client, if it has one -
// stdio has none, and gets a recorder that always reads zero/empty. Call it
// fresh for each connection attempt, right after transport.New: the
// recorder only describes the requests that one attempt goes on to make.
func snoopStatus(tr mcp.Transport) *responseSniff {
	sniff := &responseSniff{}
	var hc *http.Client
	switch t := tr.(type) {
	// Asked for first, and the only case that matters in production: a transport this scanner
	// built carries its own client, so no wrapper around it can hide the client and quietly
	// turn every observed status into nothing
	case interface{ HTTPClient() *http.Client }:
		hc = t.HTTPClient()
	case *mcp.StreamableClientTransport:
		hc = t.HTTPClient
	case *mcp.SSEClientTransport:
		hc = t.HTTPClient
	}
	if hc == nil {
		return sniff
	}
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	hc.Transport = statusSniffer{base: base, sniff: sniff}
	return sniff
}

// classifyDialErr adds typed status and session-rejection classifications without replacing the
// original error. New classifications must wrap with %w so errors.Is and errors.As still work.
func classifyDialErr(err error, lastStatus int32) error {
	if err == nil {
		return nil
	}
	// The sentinel is wrapped whether or not a status was observed. Over HTTP there is always a
	// status, so checking it first made the session branch unreachable - and the spec has a
	// server answer an unrecognized session id with 404, which is not a status any caller reads
	// as a credential decision.
	if errors.Is(err, mcp.ErrSessionMissing) {
		err = fmt.Errorf("%w: %w", analyzer.ErrSessionRejected, err)
	}
	if lastStatus != 0 {
		return &httpStatusError{status: int(lastStatus), err: err}
	}
	return err
}
