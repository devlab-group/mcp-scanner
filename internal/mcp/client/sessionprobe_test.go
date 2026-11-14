package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/testdata/protocol/fixtures"
)

// The protocol uses 404 to reject an unknown session ID. Classify it as a session
// rejection only when the request supplied an ID; preserve other refusals.
func TestCall_404RejectsOnlyAResumedSessionID(t *testing.T) {
	server := func(*http.Request) *mcp.Server { return fixtures.WellBehaved() }
	stateful := mcp.NewStreamableHTTPHandler(server, nil)
	stateless := mcp.NewStreamableHTTPHandler(server, &mcp.StreamableHTTPOptions{Stateless: true})
	refuse := func(status int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, http.StatusText(status), status)
		})
	}
	notFoundFor := func(method string, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if bytes.Contains(body, []byte(method)) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}

	tests := []struct {
		name         string
		handler      http.Handler
		resumeID     string
		method       string
		wantStatus   int
		wantRejected bool
	}{
		{
			name:         "unknown resumed id answered 404 by the SDK server",
			handler:      stateful,
			resumeID:     "no-such-session",
			method:       "tools/list",
			wantStatus:   http.StatusNotFound,
			wantRejected: true,
		},
		{
			name:       "resumed id refused with 400",
			handler:    refuse(http.StatusBadRequest),
			resumeID:   "some-session",
			method:     "tools/list",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "no session id presented, answered 404",
			handler:    notFoundFor("missing/method", stateless),
			method:     "missing/method",
			wantStatus: http.StatusNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			d := NewDialer(Options{Timeout: 5 * time.Second, AllowPrivateNetworks: true}).(analyzer.SessionDialer)
			target := model.Target{Kind: model.TargetRemote, URL: srv.URL, Transport: "streamable"}
			sess, err := d.DialWithOptions(ctx, target, analyzer.DialOptions{ResumeSessionID: tt.resumeID})
			if err != nil {
				t.Fatalf("DialWithOptions(resume %q) error = %v", tt.resumeID, err)
			}
			defer sess.Close()

			_, err = sess.Call(ctx, tt.method, nil)
			if err == nil {
				t.Fatalf("Call(%q) succeeded, want a refusal", tt.method)
			}
			if got := errors.Is(err, analyzer.ErrSessionRejected); got != tt.wantRejected {
				t.Errorf("Call(%q) ErrSessionRejected = %v, want %v (err: %v)", tt.method, got, tt.wantRejected, err)
			}
			sc, ok := errors.AsType[analyzer.StatusCoder](err)
			if !ok || sc.Status() != tt.wantStatus {
				t.Errorf("Call(%q) status = %v, want %d (err: %v)", tt.method, sc, tt.wantStatus, err)
			}
			if errors.Is(err, analyzer.ErrConnectionClosed) {
				t.Errorf("Call(%q) answered with a status is marked as closed: %v", tt.method, err)
			}
		})
	}
}
