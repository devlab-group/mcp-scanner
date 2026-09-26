// Package auth analyzes authentication, token, and session security for a live MCP target.
// Checks that need unavailable credentials remain visible as skips, but missing test tokens alone
// do not make the analyzer partial.
package auth

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/httpx"
	"github.com/revinand/mcp-scanner/internal/mcp/client"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

const name = "auth"

func init() { analyzer.Register(New()) }

// Analyzer implements analyzer.Analyzer
type Analyzer struct {
	// httpClient lets tests replace the passive metadata client. Production metadataClient calls
	// internal/httpx so metadata fetches get dial-time address checks and same-origin redirects.
	httpClient *http.Client
}

// New builds the auth analyzer
func New() *Analyzer { return &Analyzer{} }

// metadataClient is the HTTP client the passive metadata fetch uses for
// one scan: whatever a test injected, or one built from this scan's own
// private-network policy
func (a *Analyzer) metadataClient(ac *analyzer.AnalysisContext) *http.Client {
	if a.httpClient != nil {
		return a.httpClient
	}
	return httpx.Policy{AllowPrivateNetworks: ac.AllowPrivateNetworks}.Client(15 * time.Second)
}

func (a *Analyzer) Name() string { return name }

// Analyze runs the passive discovery and, where permitted and configured,
// the active credential/session matrix
func (a *Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	started := time.Now().UTC()
	res := model.AnalyzerResult{Analyzer: name, StartedAt: started}

	if target.Kind != model.TargetRemote {
		res = model.Skipped(name, fmt.Sprintf("auth analysis only applies to remote targets, got %q", target.Kind))
		res.StartedAt, res.FinishedAt = started, time.Now().UTC()
		return res
	}

	st := &state{
		analyzer: a,
		target:   target,
		ac:       ac,
		tokens:   readTokens(ac),
	}
	// Every session state.attempt opens stays live until here: several matrix cases
	// (session_user_a, session_user_b, reused_session) need an earlier attempt's session id to
	// still be valid server-side, and a Dialer's Close is free to mean "terminate this session"
	// (reused_session relies on exactly that)
	defer st.closeSessions()

	var findings []model.Finding
	var cov model.Coverage
	// matrixRan distinguishes a disabled matrix from individual cases that lack optional tokens.
	// A disabled matrix makes the result PARTIAL; missing optional cases remain documented limits.
	matrixRan := false

	// Passive discovery uses one well-known-metadata fetch and runs only at probe level safe or
	// higher
	cov.CapabilitiesDiscovered++
	if ac.Probes.AtLeast(analyzer.ProbeSafe) {
		findings = append(findings, a.passive(ctx, st)...)
		cov.CapabilitiesAnalyzed++
	} else {
		cov.CapabilitiesSkipped++
		cov.SkipReasons = append(cov.SkipReasons, "passive metadata discovery skipped: probe level below safe")
	}

	if ac.Dialer == nil {
		cov.CapabilitiesDiscovered += len(matrixCaseNames)
		cov.CapabilitiesSkipped += len(matrixCaseNames)
		cov.SkipReasons = append(cov.SkipReasons, "no dialer available: cannot open additional sessions for the credential matrix")
	} else if !ac.Probes.AtLeast(analyzer.ProbeSafe) {
		cov.CapabilitiesDiscovered += len(matrixCaseNames)
		cov.CapabilitiesSkipped += len(matrixCaseNames)
		cov.SkipReasons = append(cov.SkipReasons, "credential matrix skipped: probe level below safe")
	} else {
		matrixRan = true
		mf, mc := a.runMatrix(ctx, st)
		findings = append(findings, mf...)
		cov.Add(mc)

		for _, extra := range []struct {
			name string
			run  func(context.Context, *state) (bool, *model.Finding, string)
		}{
			{"session_fixation", a.checkSessionFixation},
			{"token_passthrough", a.checkTokenPassthrough},
		} {
			cov.CapabilitiesDiscovered++
			ran, ef, skipReason := extra.run(ctx, st)
			if ran {
				cov.CapabilitiesAnalyzed++
				if ef != nil {
					findings = append(findings, *ef)
				}
			} else {
				cov.CapabilitiesSkipped++
				cov.SkipReasons = append(cov.SkipReasons, extra.name+": "+skipReason)
			}
		}
	}

	res.Findings = findings
	res.Coverage = cov
	res.Warnings = st.warnings

	if cov.CapabilitiesAnalyzed == 0 {
		res = model.Skipped(name, firstOr(cov.SkipReasons, "no auth check could be run against this target"))
		res.StartedAt, res.FinishedAt = started, time.Now().UTC()
		return res
	}
	// Most of the credential matrix needs a test token only the operator can mint (see
	// docs/analyzers/auth.md); a case skipped for a missing token is a documented limitation,
	// not a failure, and does not by itself downgrade the result - every case is still visible
	// in Coverage either way
	switch {
	case !matrixRan:
		res.Status = model.AnalyzerPartial
	case st.inconclusiveProbe:
		res.Status = model.AnalyzerPartial
	default:
		res.Status = model.AnalyzerCompleted
	}
	res.FinishedAt = time.Now().UTC()
	res.Duration = res.FinishedAt.Sub(started)
	return res
}

func firstOr(ss []string, fallback string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return fallback
}

// state carries everything one Analyze run threads through passive
// discovery and the matrix
type state struct {
	analyzer *Analyzer
	target   model.Target
	ac       *analyzer.AnalysisContext
	tokens   map[string]string

	metadataFound bool
	resourceURL   string
	authServers   []string
	tlsUsed       bool

	// Populated by caseValidToken; caseSessionUserA, caseSessionUserB,
	// caseReusedSession and caseGuessedSessionID depend on it
	validToken     string
	validSessionID string
	validAccepted  bool

	// sessions holds every session attempt opened, retained instead of
	// closed so a later case can still reuse the session id one of these
	// belongs to; closeSessions closes them all at the end of Analyze
	sessions []analyzer.Session

	// inconclusiveProbe is set when a matrix or standalone check proves neither acceptance nor
	// rejection, including connection failures and failed identity-tool calls
	inconclusiveProbe bool

	warnings []string
}

// probeDialer is ac.Dialer with resource and prompt content fetches disabled. These probes need
// only the handshake and acceptance result, so reconnecting must not repeatedly fetch content.
func (st *state) probeDialer() analyzer.Dialer {
	return client.WithoutContentFetch(st.ac.Dialer)
}

// retain keeps a successfully opened session alive until closeSessions runs
// at the end of Analyze, instead of leaking it or closing it immediately,
// which would terminate a session id a later matrix case still needs to reuse
func (st *state) retain(sess analyzer.Session) {
	st.sessions = append(st.sessions, sess)
}

// closeSessions closes every session state.attempt opened during this
// analysis. A close failure is a warning, not a change to any probe's
// already-recorded result - the finding stands regardless of whether the
// scanner managed to tidy up after itself.
func (st *state) closeSessions() {
	for _, sess := range st.sessions {
		if err := sess.Close(); err != nil {
			st.warnings = append(st.warnings, "failed to close a probe session: "+err.Error())
		}
	}
	st.sessions = nil
}

// Describe documents this analyzer for `mcp-scanner analyzers`
func (a *Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name: name,
		Purpose: "Checks whether an MCP server actually enforces authentication and session " +
			"boundaries: token validation, audience/issuer/expiry/scope checks, and whether a " +
			"session id is bound to the user that created it.",
		Threats: []string{
			"missing or bypassable authentication",
			"token accepted without audience, issuer, expiry or scope validation",
			"session fixation (server accepts a client-chosen session id)",
			"session id not bound to the user that created it",
			"guessable or sequential session ids",
			"a closed session id still being honored",
			"token passthrough to a third party (confused deputy)",
			"protected-resource metadata naming a different resource than the target",
			"an authorization server declared on a different origin than the resource",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceProtocol, model.EvidenceConfirmed},
		Active:   true,
		Limitations: []string{
			"applies only to remote targets; every other target kind is SKIPPED",
			"cannot forge a validly-signed token for a real authorization server, so the " +
				"expiry, audience, issuer, scope and cross-user checks only run when the " +
				"operator supplies matching test tokens through the \"tokens\" option",
			"session/user-identity confirmation and token-passthrough detection only run when " +
				"an allowlisted \"identity_tool\" option is configured",
			"a session id that looks random but was generated by a broken PRNG is not detected; " +
				"the predictability check only catches structurally sequential or short ids",
			"the protected-resource metadata fetch refuses cross-origin redirects and applies " +
				"the scan's own private-network policy, so metadata published behind a redirect " +
				"to another origin, or on a private address without --allow-private-networks, " +
				"reads as \"not found\" rather than being fetched",
			"session fixation is only observable against a server that accepts a handshake " +
				"carrying a client-chosen session id; a server that refuses one - which both " +
				"reference SDKs do - leaves the check recorded as skipped, not passed",
			"an authorization server on a different origin than the resource is reported at moderate " +
				"confidence: it is also a normal, common deployment shape, not proof of a problem",
		},
		RequiresNetwork:     true,
		RequiresCredentials: false,
	}
}

// readTokens pulls operator-supplied test credentials from ac.Options["auth"]["tokens"].
// Only the operator, who controls (or was given limited test access to) the target's identity
// provider, can mint tokens in these specific bad states; the analyzer never forges a
// signature itself.
func readTokens(ac *analyzer.AnalysisContext) map[string]string {
	out := map[string]string{}

	// tokens_env first, so a literal below can override it. These are the target's own working
	// credentials: naming an environment variable keeps them out of a file that gets committed
	// and out of what the config command prints, which is how every other credential in this
	// scanner is handled.
	for caseName, env := range optionStringMap(ac, "tokens_env") {
		if v := config.Secret(env); v != "" {
			out[caseName] = v
		}
	}
	maps.Copy(out, optionStringMap(ac, "tokens"))
	return out
}

// optionStringMap reads one analyzer option as a map of strings, accepting
// both shapes a decoded configuration can produce: map[string]any from YAML,
// map[string]string from a configuration built in Go
func optionStringMap(ac *analyzer.AnalysisContext, key string) map[string]string {
	out := map[string]string{}
	v, ok := ac.Option(name, key)
	if !ok {
		return out
	}
	switch m := v.(type) {
	case map[string]string:
		maps.Copy(out, m)
	case map[string]any:
		for k, val := range m {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

// identityTool names the allowlisted tool (if any) that returns the
// caller's identity, used only by the checks that need to see actual
// response content rather than an accept/reject signal. Left unset, those
// checks are skipped rather than guessing at a tool name that might have a
// side effect on the real target.
func identityTool(ac *analyzer.AnalysisContext) (string, bool) {
	v, ok := ac.Option(name, "identity_tool")
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" || !ac.ToolCallAllowed(s) {
		return "", false
	}
	return s, true
}

// validCredential returns the best available "known good" bearer token:
// an operator-supplied one, or whatever the target was already configured
// with
func (st *state) validCredential() (string, bool) {
	if t, ok := st.tokens["valid"]; ok && t != "" {
		return t, true
	}
	if h := headerValue(st.target.Headers, "Authorization"); h != "" {
		return strings.TrimPrefix(h, "Bearer "), true
	}
	return "", false
}

func headerValue(h map[string]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// withAuth clones target with Authorization set to token (or removed, if
// token is empty), and optionally a session id header set
func withAuth(target model.Target, token, sessionID string) model.Target {
	t := target
	headers := map[string]string{}
	for k, v := range target.Headers {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Mcp-Session-Id") {
			continue
		}
		headers[k] = v
	}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	if sessionID != "" {
		headers["Mcp-Session-Id"] = sessionID
	}
	t.Headers = headers
	return t
}

func redactAuth(headerValue string) string {
	if headerValue == "" {
		return "(none)"
	}
	n := len(headerValue)
	if n <= 6 {
		return fmt.Sprintf("%s(len=%d)", headerValue, n)
	}
	return fmt.Sprintf("%s...(len=%d)", headerValue[:6], n)
}

// redactSessionID keeps the first six characters and length, matching token evidence. Values of
// six characters or fewer remain fully visible, so callers must not treat this as secret erasure.
func redactSessionID(id string) string { return redactAuth(id) }

// dialOutcome is what one attempt actually learned. Only outcomeRejected is
// proof the target enforces the boundary being probed; outcomeAccepted is
// the opposite finding; outcomeInconclusive means the probe got no usable
// answer at all - a network error, a timeout, a malformed response, or an
// unexpected status - and must never be treated as either.
type dialOutcome int

const (
	outcomeAccepted dialOutcome = iota
	outcomeRejected
	outcomeInconclusive
)

// dialResult is the outcome of one attempt to establish a session and use
// it, kept generic enough to back every matrix case's evidence
type dialResult struct {
	outcome   dialOutcome
	sessionID string
	detail    string
}

func (r dialResult) accepted() bool { return r.outcome == outcomeAccepted }

// probeDial opens one of the off-spec session shapes these checks need; the
// connection layer must say it can make that shape, or a probe silently
// becomes an ordinary handshake and the check reports on a connection that
// was never made
func (st *state) probeDial(ctx context.Context, t model.Target, opts analyzer.DialOptions) (analyzer.Session, error) {
	d := st.probeDialer()
	if d == nil {
		return nil, fmt.Errorf("%w: no dialer available", analyzer.ErrDialOptionUnsupported)
	}
	if opts == (analyzer.DialOptions{}) {
		// An ordinary credential probe is an ordinary dial. Only the two
		// off-spec session shapes need a connection layer that can make
		// them, so requiring the wider contract here would report every
		// plain case as unrunnable against a Dialer that is perfectly able
		// to run it.
		return d.Dial(ctx, t)
	}
	sd, ok := d.(analyzer.SessionDialer)
	if !ok {
		return nil, fmt.Errorf("%w: this connection layer cannot open session probes", analyzer.ErrDialOptionUnsupported)
	}
	return sd.DialWithOptions(ctx, t, opts)
}

// unsupportedProbe reports whether err means the probe was never made, as
// opposed to made and refused. It is the difference between "this check did
// not run" and "this boundary held", and counting the first as the second is
// how a check reports coverage it does not have.
func unsupportedProbe(err error) bool { return errors.Is(err, analyzer.ErrDialOptionUnsupported) }

// attempt opens a session with the given credentials/session id and, if it succeeds, makes
// one side-effect-free tools/list call to confirm the session is actually usable, not just
// that the transport connected
func (st *state) attempt(ctx context.Context, token, sessionID string) dialResult {
	t := withAuth(st.target, token, "")
	opts := analyzer.DialOptions{}
	if sessionID != "" {
		// Resumed, not handshaked. Whether a server honours an id it should
		// not is a question about a request that carries one, and running
		// initialize while carrying it asks something else the server is
		// entitled to answer differently.
		opts.ResumeSessionID = sessionID
	}
	// A probe that carried a session id, against a target whose no-session
	// control already worked, can read the spec's 404 for an unrecognized
	// id as the refusal it is. Without a session id, or without that
	// control, the same 404 could be a moved endpoint answering everything
	// identically, and stays inconclusive.
	classify := classifyErr
	if opts.ResumeSessionID != "" && st.validAccepted {
		classify = classifyResumeErr
	}

	sess, err := st.probeDial(ctx, t, opts)
	if err != nil {
		if unsupportedProbe(err) {
			return dialResult{outcome: outcomeInconclusive, detail: describeErr(err)}
		}
		return dialResult{outcome: classify(err), detail: describeErr(err)}
	}
	st.retain(sess)
	got := sess.SessionID()
	if got == "" {
		got = sessionID
	}
	if _, err := sess.Call(ctx, "tools/list", nil); err != nil {
		return dialResult{outcome: classify(err), sessionID: got, detail: describeErr(err)}
	}
	return dialResult{outcome: outcomeAccepted, sessionID: got, detail: "tools/list succeeded"}
}

// rejectionStatuses are the HTTP status codes that carry an authentication, authorization
// or session decision about the request sent - the spec's 401/403, plus the 400 real
// servers use for an unrecognized or malformed session id. A 404 or 429 does not prove that
// the server evaluated the credential or session state.
var rejectionStatuses = map[int]bool{
	http.StatusBadRequest:   true,
	http.StatusUnauthorized: true,
	http.StatusForbidden:    true,
}

// classifyResumeErr is classifyErr for a probe that carries a session id on a target whose
// no-session control already succeeded. There, a 404 for an unrecognized session id is a
// refusal - the endpoint is known to answer, and the id is the only thing that changed.
func classifyResumeErr(err error) dialOutcome {
	if errors.Is(err, analyzer.ErrSessionRejected) {
		return outcomeRejected
	}
	return classifyErr(err)
}

// classifyErr tells a typed, expected rejection from everything else. Only two things
// count: a status in rejectionStatuses that the target actually answered with, or the SDK's
// own signal that a session id is unrecognized - both reached via errors.As/errors.Is,
// never guessed from error text.
func classifyErr(err error) dialOutcome {
	if sc, ok := errors.AsType[analyzer.StatusCoder](err); ok {
		if rejectionStatuses[sc.Status()] {
			return outcomeRejected
		}
		return outcomeInconclusive
	}
	if errors.Is(err, analyzer.ErrSessionRejected) {
		return outcomeRejected
	}
	return outcomeInconclusive
}

func describeErr(err error) string {
	if err == nil {
		return ""
	}
	if pe, ok := err.(*analyzer.ProtocolError); ok {
		return fmt.Sprintf("protocol error %d: %s", pe.Code, pe.Message)
	}
	return err.Error()
}

func evidenceFor(level model.EvidenceLevel, desc, method string, token, sessionID string, result dialResult) model.Evidence {
	data := map[string]any{
		"request": map[string]any{
			"method":          method,
			"authorization":   redactAuth(bearer(token)),
			"session_id_sent": redactSessionID(sessionID),
		},
		"response": map[string]any{
			"accepted":   result.accepted(),
			"detail":     result.detail,
			"session_id": redactSessionID(result.sessionID),
		},
	}
	return model.Evidence{Level: level, Kind: "auth_probe", Description: desc, Data: data}
}

func bearer(token string) string {
	if token == "" {
		return ""
	}
	return "Bearer " + token
}

func finding(ruleID, category, title string, sev model.Severity, conf float64, level model.EvidenceLevel, desc string, ev ...model.Evidence) model.Finding {
	return model.Finding{
		RuleID:        ruleID,
		Category:      category,
		Title:         title,
		Severity:      sev,
		Confidence:    conf,
		EvidenceLevel: level,
		Description:   desc,
		Analyzer:      name,
		Evidence:      ev,
	}
}
