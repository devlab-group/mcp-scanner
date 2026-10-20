package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/mcp/client"
	"github.com/devlab-group/mcp-scanner/internal/policy"
	reportjson "github.com/devlab-group/mcp-scanner/internal/report/json"
	"github.com/devlab-group/mcp-scanner/internal/supplychain"
	"github.com/devlab-group/mcp-scanner/pkg/model"
	"github.com/devlab-group/mcp-scanner/pkg/scanner"
)

// submitRequest is the POST /v1/scans body. It intentionally mirrors only
// the fields a caller needs to describe a target; scanner.Options fields
// that control how the scan behaves internally (Root, per-analyzer
// Options) are not exposed here.
type submitRequest struct {
	Target struct {
		Kind      string            `json:"kind"`
		Name      string            `json:"name,omitempty"`
		URL       string            `json:"url,omitempty"`
		Headers   map[string]string `json:"headers,omitempty"`
		Transport string            `json:"transport,omitempty"`
		Command   string            `json:"command,omitempty"`
		Args      []string          `json:"args,omitempty"`
		Path      string            `json:"path,omitempty"`
		Ecosystem string            `json:"ecosystem,omitempty"`
		Package   string            `json:"package,omitempty"`
		Version   string            `json:"version,omitempty"`
	} `json:"target"`
	Analyzers        []string `json:"analyzers,omitempty"`
	FailOn           string   `json:"fail_on,omitempty"`
	BlockingSeverity string   `json:"blocking_severity,omitempty"`

	// ActiveProbes is read only to refuse it
	ActiveProbes string `json:"active_probes,omitempty"`
}

func (r submitRequest) toTarget() (model.Target, error) {
	t := model.Target{
		Kind: model.TargetKind(r.Target.Kind), Name: r.Target.Name,
		URL: r.Target.URL, Headers: r.Target.Headers, Transport: r.Target.Transport,
		Path:      r.Target.Path,
		Ecosystem: r.Target.Ecosystem, Package: r.Target.Package, Version: r.Target.Version,
	}
	// Only stdio may carry a command. The runtime analyzer also executes
	// target.Command for source and package scans, so copying it onto those kinds
	// would bypass the API's allowed-kind gate.
	if t.Kind == model.TargetStdio {
		t.Command, t.Args = r.Target.Command, r.Target.Args
	}
	if err := t.Validate(); err != nil {
		return model.Target{}, err
	}
	// Checked here so an unknown transport is the same 400 a usage error
	// gets, rather than an accepted submission that only fails once the
	// scan tries to connect - see client.ValidateTransport. An empty value
	// (the "auto" default) always validates, so this is safe unconditionally.
	if err := client.ValidateTransport(t.Transport); err != nil {
		return model.Target{}, err
	}
	return t, nil
}

// toOptions starts from base - the scan options built once from the server's configuration
// file - and overrides only what a request is meant to control per scan
func (r submitRequest) toOptions(base scanner.Options) (scanner.Options, error) {
	opts := base
	if len(r.Analyzers) > 0 {
		opts.Analyzers = r.Analyzers
	}
	if r.BlockingSeverity != "" {
		sev, err := model.ParseSeverity(r.BlockingSeverity)
		if err != nil {
			return opts, fmt.Errorf("blocking_severity: %w", err)
		}
		opts.BlockingSeverity = sev
	}
	return opts, nil
}

// submitResponse never carries anything from the request beyond an echo of
// the target kind - specifically never the headers a caller may have
// submitted for the target's own authentication
type submitResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if s.shutdown.Load() {
		writeError(w, http.StatusServiceUnavailable, "server is shutting down")
		return
	}
	// The increment itself is the admission check: reserve a slot first, then give it back on
	// every path below that does not end in the scan goroutine taking ownership of it
	if s.inFlight.Add(1) > int64(s.maxInFlight) {
		s.inFlight.Add(-1)
		writeError(w, http.StatusTooManyRequests, "too many scans pending or running")
		return
	}
	fail := func(status int, msg string) {
		s.inFlight.Add(-1)
		writeError(w, status, msg)
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxBodyBytes)
	var req submitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(http.StatusBadRequest, "could not parse request body as JSON")
		return
	}
	if req.ActiveProbes != "" {
		fail(http.StatusBadRequest,
			"active_probes is deployment configuration, not a request field: set active_probes in the server's configuration file")
		return
	}
	target, err := req.toTarget()
	if err != nil {
		fail(http.StatusBadRequest, "invalid target: "+err.Error())
		return
	}
	if !s.allowedTargetKinds[target.Kind] {
		fail(http.StatusBadRequest, "target kind is not permitted on this server")
		return
	}
	sopts, err := req.toOptions(s.baseOptions)
	// Same reason as the command line: suppression has to happen before the
	// verdict, not after it
	if err == nil {
		sopts.Baseline = s.pol.Baseline
	}
	if err != nil {
		fail(http.StatusBadRequest, "invalid options: "+err.Error())
		return
	}
	if localPathTargetKinds[target.Kind] {
		resolved, err := resolveWithinBase(s.baseDir, target.Path)
		if err != nil {
			// The detail (which component of the path does not exist, a
			// permission error, the base dir itself being misconfigured)
			// is exactly the kind of host-filesystem fact a caller should
			// not get to probe for - see redactLocalPathErrors below for
			// the same reasoning applied to a scan that gets further
			s.logger.Warn("rejected path outside base dir", "target_kind", target.Kind, "detail", err.Error())
			fail(http.StatusBadRequest, "invalid path")
			return
		}
		target.Path = resolved
		if target.Kind == model.TargetSource {
			sopts.Root = resolved
		}
	}
	// What goes back in result.target.path. The scan needs the resolved host path; the caller
	// does not, and a precise one - including MCP_SCANNER_API_BASE_DIR, or the server's own
	// temp directory for a package - is the filesystem oracle docs/api.md says not to hand out.
	reportedPath := req.Target.Path
	failOn := req.FailOn
	pol := s.pol
	if failOn != "" {
		// ParseFailOn accepts "none", keeping API and file configuration consistent
		sev, err := policy.ParseFailOn(failOn)
		if err != nil {
			fail(http.StatusBadRequest, "invalid fail_on: "+err.Error()+` (or "none" to turn the gate off)`)
			return
		}
		pol.FailOn = sev
	}

	id, err := newID()
	if err != nil {
		s.logger.Error("could not generate a scan id", "detail", err.Error())
		fail(http.StatusInternalServerError, "could not allocate a scan id")
		return
	}

	// scratch is the package extraction directory, if any. It is owned by
	// run below, not by Preparer.Prepare: Scan can return before Prepare is
	// ever reached (an unresolvable analyzer name fails first), and nothing
	// else would then remove a directory this handler already created.
	var scratch string
	if target.Kind == model.TargetPackage {
		// A package target's extraction directory belongs to the scanner, not the submitter:
		// whatever path the request named is never looked at
		dest, err := os.MkdirTemp("", supplychain.ExtractionDirPrefix)
		if err != nil {
			s.logger.Error("could not create package extraction directory", "detail", err.Error())
			fail(http.StatusInternalServerError, "could not allocate a scan directory")
			return
		}
		target.Path = dest
		sopts.Root = dest
		scratch = dest
		// A package target's path is a scratch directory this server
		// allocated. It is not something the caller named and not
		// something they get to learn.
		reportedPath = ""
	}

	rec := &record{ID: id, Status: statusPending, CreatedAt: time.Now().UTC()}
	s.store.put(rec)

	go s.run(id, target, sopts, pol, scratch, reportedPath)

	writeJSON(w, http.StatusAccepted, submitResponse{ID: id, Status: string(statusPending)})
}

// run executes the scan and stores its result. Its scratch directory is removed on every exit,
// including failures that happen before target preparation completes.
func (s *Server) run(id string, target model.Target, sopts scanner.Options, pol policy.Policy, scratch, reportedPath string) {
	defer s.inFlight.Add(-1)
	if scratch != "" {
		defer os.RemoveAll(scratch)
	}
	// runOne recovers an analyzer panic; nothing recovers a panic in the
	// preparer, the client or the SDK on hostile input, and this runs in
	// its own goroutine, so one would take the whole process down with
	// every in-flight scan and every stored record
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("scan panicked", "id", id, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			s.store.update(id, func(rec *record) {
				rec.Status = statusError
				rec.Message = "the scan failed"
			})
		}
	}()

	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	s.store.update(id, func(r *record) { r.Status = statusRunning })

	ctx, cancel := context.WithTimeout(context.Background(), s.scanTimeout)
	defer cancel()

	res, err := s.scanner.Scan(ctx, target, sopts)
	if err != nil {
		s.store.update(id, func(r *record) {
			r.Status = statusError
			r.Message = err.Error()
		})
		return
	}
	if redactedPathTargetKinds[target.Kind] {
		redactLocalPathErrors(res, s.logger, id, s.baseDir)
	}
	// Every kind that rewrote target.Path above (both this handler's own BaseDir resolution and
	// the package extraction directory) cleared or left reportedPath to match, so applying it
	// unconditionally reports back exactly what the caller is owed regardless of kind
	if res != nil {
		res.Target.Path = reportedPath
	}
	decision := pol.Apply(res)
	// Measured outside the store's lock: json.Marshal on a large result is real work, and it
	// must not hold every other request's store access while it runs
	size := resultSize(res)
	if ceiling := s.store.byteCeiling(); ceiling > 0 && size > ceiling {
		// A result bigger than the whole store's ceiling would be evicted the instant it was
		// stored, and the caller would then poll a 404 it cannot tell from a bad id
		res.Snapshot = nil
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"the captured snapshot was dropped from this stored result: it was larger than this deployment keeps (%d bytes); findings and coverage are unaffected", ceiling))
		size = resultSize(res)
	}
	s.store.update(id, func(r *record) {
		r.Status = statusDone
		r.Result = res
		r.Decision = &decision
		r.Bytes = size
	})
}

type getResponse struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"`
	Message   string            `json:"message,omitempty"`
	Result    *model.ScanResult `json:"result,omitempty"`
	Pass      *bool             `json:"pass,omitempty"`
	ExitCode  *int              `json:"exit_code,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, ok := s.store.get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "no scan with that id")
		return
	}
	resp := getResponse{ID: rec.ID, Status: string(rec.Status), Message: rec.Message, Result: rec.Result, CreatedAt: rec.CreatedAt}
	if rec.Decision != nil {
		resp.Pass = &rec.Decision.Pass
		resp.ExitCode = &rec.Decision.ExitCode
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if s.shutdown.Load() {
		writeError(w, http.StatusServiceUnavailable, "shutting down")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// writeJSON encodes v after escaping invisible and direction-changing characters in
// target-controlled text. If sanitization fails, it emits a fixed error instead of falling
// back to the unsafe value.
func writeJSON(w http.ResponseWriter, status int, v any) {
	safe, err := reportjson.SanitizedValue(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "could not encode the response"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(safe)
}

// writeError writes a fixed-shape error body built only from msg, which
// every caller sets to a static or already-sanitized string - never from
// request headers or raw body content
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// resolveWithinBase resolves a caller-submitted path against base and
// refuses one that escapes it. Both sides go through filepath.EvalSymlinks
// before the containment check, so a symlink - inside base or in the
// submitted path itself - cannot be used to point outside base without
// that being visible in the resolved form being compared.
func resolveWithinBase(base, submitted string) (string, error) {
	if base == "" {
		return "", fmt.Errorf("local scanning is not configured on this server")
	}
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", fmt.Errorf("resolve configured base directory: %w", err)
	}
	joined := filepath.Join(resolvedBase, submitted)
	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	rel, err := filepath.Rel(resolvedBase, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the configured base directory")
	}
	return resolved, nil
}

// redactLocalPathErrors replaces a discovery-failure analyzer error message with a generic
// one, after logging the original server-side, for target kinds where that message can
// carry host filesystem detail about a path the caller chose but doesn't otherwise get to
// observe
func redactLocalPathErrors(res *model.ScanResult, logger *slog.Logger, id, baseDir string) {
	if res == nil {
		return
	}
	for i := range res.Analyzers {
		for j := range res.Analyzers[i].Errors {
			e := &res.Analyzers[i].Errors[j]
			if !strings.HasPrefix(e.Message, scanner.DiscoveryFailedPrefix) {
				continue
			}
			logger.Warn("redacted a target-read error before returning it",
				"id", id, "analyzer", res.Analyzers[i].Analyzer, "detail", e.Message)
			e.Message = "target could not be read"
		}
	}
	for i := range res.Warnings {
		if !strings.Contains(res.Warnings[i], scanner.DiscoveryFailedPrefix) {
			continue
		}
		logger.Warn("redacted a target-read warning before returning it",
			"id", id, "detail", res.Warnings[i])
		res.Warnings[i] = "target could not be read"
	}
	redactBaseDir(res, logger, id, baseDir)
}

// redactBaseDir is the backstop for a host path that reaches a result some way the
// exact-message redaction above doesn't know about - an analyzer's own error, a coverage
// skip reason or limit record that formats an absolute path directly
func redactBaseDir(res *model.ScanResult, logger *slog.Logger, id, baseDir string) {
	if res == nil || baseDir == "" {
		return
	}
	resolvedBase, err := filepath.EvalSymlinks(baseDir)
	if err != nil || resolvedBase == "" {
		resolvedBase = baseDir
	}

	redacted := false
	redact := func(s string) string {
		if !strings.Contains(s, resolvedBase) {
			return s
		}
		redacted = true
		return strings.ReplaceAll(s, resolvedBase, "<base>")
	}
	redactCoverage := func(cov *model.Coverage) {
		for i := range cov.SkipReasons {
			cov.SkipReasons[i] = redact(cov.SkipReasons[i])
		}
		for i := range cov.LimitsHit {
			cov.LimitsHit[i] = redact(cov.LimitsHit[i])
		}
	}

	for i := range res.Analyzers {
		a := &res.Analyzers[i]
		for j := range a.Errors {
			a.Errors[j].Message = redact(a.Errors[j].Message)
		}
		redactCoverage(&a.Coverage)
	}
	for i := range res.Warnings {
		res.Warnings[i] = redact(res.Warnings[i])
	}
	redactCoverage(&res.Coverage)

	if redacted {
		logger.Warn("redacted the configured base directory out of a scan result before returning it", "id", id)
	}
}

// randRead is crypto/rand.Read, indirected so a test can simulate the
// entropy source failing. crypto/rand.Read itself no longer returns an
// error for that case (it crashes the process instead, see
// https://go.dev/issue/66821).
var randRead = rand.Read

// newID returns a random scan identifier. It refuses rather than falling back to a
// predictable one: this id is the only thing keeping one authenticated caller from reading
// another's result at GET /v1/scans/{id}, so a clock-derived fallback would be a weaker
// boundary than the random id it replaced.
func newID() (string, error) {
	var b [12]byte
	if _, err := randRead(b[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return "scan_" + hex.EncodeToString(b[:]), nil
}

// countingWriter totals what is written to it and keeps none of it
type countingWriter int64

func (c *countingWriter) Write(p []byte) (int, error) {
	*c += countingWriter(len(p))
	return len(p), nil
}

// resultSize measures the buffered plain JSON encoding without retaining another copy. The
// sanitized response may be larger, so this bounds stored result data rather than the exact bytes
// later sent to a caller.
func resultSize(res *model.ScanResult) int64 {
	var n countingWriter
	if err := json.NewEncoder(&n).Encode(res); err != nil {
		return 0
	}
	return int64(n)
}
