// Package api implements the scanner's HTTP API: POST /v1/scans submits a
// target, GET /v1/scans/{id} polls its result, and /healthz, /readyz serve
// standard liveness/readiness checks. It is net/http only - no router
// dependency, using the method+wildcard patterns net/http.ServeMux has
// supported since Go 1.22.
package api

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/config"
	"github.com/devlab-group/mcp-scanner/internal/policy"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/pkg/scanner"
)

const (
	// defaultMaxBodyBytes bounds a POST /v1/scans body: a submission is a
	// target description, not a place to upload arbitrary data
	defaultMaxBodyBytes = 1 << 20
	// defaultMaxConcurrentScans bounds scans actually running at once
	defaultMaxConcurrentScans = 4
	// defaultMaxInFlight bounds submissions accepted but not yet finished
	// (pending + running), so a burst of submissions cannot grow the
	// in-memory store without limit
	defaultMaxInFlight = 64
	// defaultRecordRetention bounds how long a finished record is kept
	// before it is evicted on the next put, regardless of maxStoredRecords.
	// Changing it changes how long a caller has to poll GET /v1/scans/{id}
	// before the result disappears.
	defaultRecordRetention = time.Hour
	// defaultMaxStoredRecords is the hard cap on records kept regardless of
	// age: once retention alone is not enough (a burst within the window),
	// the oldest records are evicted down to this count
	defaultMaxStoredRecords = 1000
	// defaultMaxStoredBytes bounds the store by the size of what it is actually holding, not
	// just how many records: a scanned target controls how large its own snapshot and findings
	// are (up to the generous per-list caps in internal/mcp/discovery), so maxRecords alone
	// does not bound total memory
	defaultMaxStoredBytes = 256 << 20
)

// defaultAllowedTargetKinds is what a deployment gets with no explicit
// opt-in: a kind that only ever reaches out over the network the operator
// already exposed this server to, never one that starts a local process or
// reads a local path the operator did not choose
var defaultAllowedTargetKinds = []model.TargetKind{model.TargetRemote}

// sensitiveTargetKinds start a process or read a path on the host the API
// process can see. Enabling any of them requires a configured auth token -
// NewServer refuses to start otherwise - and TargetSource/TargetStatic
// additionally require Options.BaseDir: both take a caller-supplied path
// and read whatever it names.
var sensitiveTargetKinds = map[model.TargetKind]bool{
	model.TargetStdio:   true,
	model.TargetSource:  true,
	model.TargetStatic:  true,
	model.TargetPackage: true,
}

// localPathTargetKinds is the subset of sensitiveTargetKinds that reads a
// path the caller named, resolved against Options.BaseDir. It decides two
// things: which kinds need Options.BaseDir configured, and which submitted
// paths are resolved against it.
var localPathTargetKinds = map[model.TargetKind]bool{
	model.TargetSource: true,
	model.TargetStatic: true,
}

// redactedPathTargetKinds is every kind whose discovery errors can carry raw filesystem
// detail (permission denied, a parse error quoting the first bytes of the file, the
// server's own extraction directory) that the caller doesn't otherwise get to observe about
// the host - see redactLocalPathErrors
var redactedPathTargetKinds = map[model.TargetKind]bool{
	model.TargetSource:  true,
	model.TargetStatic:  true,
	model.TargetPackage: true,
}

// Options configures a Server. Zero values fall back to the defaults
// above.
type Options struct {
	Policy             policy.Policy
	MaxBodyBytes       int64
	MaxConcurrentScans int
	MaxInFlight        int
	ScanTimeout        time.Duration

	// ScanOptions is the base scanner.Options built from the server's configuration file
	// (app.ScanOptions(cfg)) - analyzers, timeouts, and per-analyzer settings. handleSubmit copies it,
	// applies request analyzers and blocking severity, then sets the policy baseline and resolved
	// source root.
	ScanOptions scanner.Options

	// AllowedTargetKinds restricts what POST /v1/scans will accept.
	// Defaults to remote only - anything that starts a process or reads a
	// local path is opt-in per deployment.
	AllowedTargetKinds []model.TargetKind

	// TokenEnv names the environment variable holding the bearer token required on every request
	// except /healthz and /readyz. Empty means no token; NewServer accepts that only when no
	// sensitive target kind is enabled. The secret is read once during construction.
	TokenEnv string

	// BaseDir bounds a submitted source/static-target path: it is resolved
	// against BaseDir with filepath.EvalSymlinks and a containment check.
	// For TargetSource, Options.Root for the scan is set from the result;
	// for TargetStatic, Target.Path is. Required whenever TargetSource or
	// TargetStatic is in AllowedTargetKinds.
	BaseDir string

	// RecordRetention bounds how long a stored record survives before the
	// next put evicts it. Defaults to defaultRecordRetention.
	RecordRetention time.Duration
	// MaxStoredRecords caps the store regardless of age. Defaults to
	// defaultMaxStoredRecords.
	MaxStoredRecords int
	// MaxStoredBytes caps the store by the summed size of every stored
	// result, oldest evicted first, regardless of MaxStoredRecords: a
	// remote target the caller controls decides how large its own
	// discovery snapshot is, so a count cap alone does not bound memory.
	// Defaults to defaultMaxStoredBytes.
	MaxStoredBytes int64

	// Logger receives detail that must not go back to an API caller - for
	// example the underlying filesystem error behind a redacted "target
	// could not be read" response. Defaults to a discard logger.
	Logger *slog.Logger
}

// Server is the HTTP API. Build one with NewServer and mount Handler()
type Server struct {
	scanner     *scanner.Scanner
	pol         policy.Policy
	store       *store
	baseOptions scanner.Options

	maxBodyBytes int64
	maxInFlight  int
	scanTimeout  time.Duration

	allowedTargetKinds map[model.TargetKind]bool
	token              string
	baseDir            string
	logger             *slog.Logger

	sem      chan struct{}
	inFlight atomic.Int64
	shutdown atomic.Bool
}

// NewServer builds a Server around an already-configured *scanner.Scanner; its Preparer and
// registry decide what scans can do. Startup fails when sensitive target kinds lack authentication
// or the filesystem boundary needed to prevent unauthenticated process execution or arbitrary
// file reads.
func NewServer(sc *scanner.Scanner, opts Options) (*Server, error) {
	maxBody := opts.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBodyBytes
	}
	maxConcurrent := opts.MaxConcurrentScans
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentScans
	}
	maxInFlight := opts.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = defaultMaxInFlight
	}
	scanTimeout := opts.ScanTimeout
	if scanTimeout <= 0 {
		scanTimeout = 10 * time.Minute
	}
	retention := opts.RecordRetention
	if retention <= 0 {
		retention = defaultRecordRetention
	}
	maxRecords := opts.MaxStoredRecords
	if maxRecords <= 0 {
		maxRecords = defaultMaxStoredRecords
	}
	maxBytes := opts.MaxStoredBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxStoredBytes
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	allowed := opts.AllowedTargetKinds
	if len(allowed) == 0 {
		allowed = defaultAllowedTargetKinds
	}
	allowedSet := make(map[model.TargetKind]bool, len(allowed))
	var sensitive []model.TargetKind
	needsBaseDir := false
	for _, k := range allowed {
		allowedSet[k] = true
		if sensitiveTargetKinds[k] {
			sensitive = append(sensitive, k)
		}
		if localPathTargetKinds[k] {
			needsBaseDir = true
		}
	}

	token := config.Secret(opts.TokenEnv)
	if len(sensitive) > 0 && token == "" {
		return nil, fmt.Errorf("api: target kind(s) %v are enabled but no auth token is configured (set TokenEnv to an environment variable holding one)", sensitive)
	}
	if needsBaseDir && opts.BaseDir == "" {
		return nil, fmt.Errorf("api: a local-path target kind is enabled but Options.BaseDir is not set")
	}

	return &Server{
		scanner:            sc,
		pol:                opts.Policy,
		store:              newStore(retention, maxRecords, maxBytes),
		baseOptions:        opts.ScanOptions,
		maxBodyBytes:       maxBody,
		maxInFlight:        maxInFlight,
		scanTimeout:        scanTimeout,
		allowedTargetKinds: allowedSet,
		token:              token,
		baseDir:            opts.BaseDir,
		logger:             logger,
		sem:                make(chan struct{}, maxConcurrent),
	}, nil
}

// Handler returns the API's http.Handler. Every route but the two health
// checks requires the configured bearer token, when one is configured.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /v1/scans", s.requireAuth(http.HandlerFunc(s.handleSubmit)))
	mux.Handle("GET /v1/scans/{id}", s.requireAuth(http.HandlerFunc(s.handleGet)))
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	return mux
}

// requireAuth checks the Authorization header against the configured
// token with a constant-time comparison, so a wrong guess cannot be
// narrowed down byte by byte through timing. No token configured means no
// sensitive target kind is enabled (NewServer already enforced that), so
// the route is left open.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" {
			next.ServeHTTP(w, r)
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		supplied := strings.TrimPrefix(auth, prefix)
		if subtle.ConstantTimeCompare([]byte(supplied), []byte(s.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Shutdown marks the server not-ready. It does not cancel scans already
// running; callers still shut those down via the context passed to
// Handler's own server (e.g. http.Server.Shutdown at the transport level).
func (s *Server) Shutdown(context.Context) error {
	s.shutdown.Store(true)
	return nil
}
