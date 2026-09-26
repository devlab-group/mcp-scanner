package auth

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// matrixCaseNames is the full set of credential/session probes, in the
// order runMatrix runs them. Its length is also how many are counted as
// discovered-but-skipped when the matrix cannot run at all (no dialer, or
// the probe policy forbids it).
var matrixCaseNames = []string{
	"no_token", "valid_token", "invalid_token", "expired_token",
	"wrong_audience", "wrong_issuer", "insufficient_scope", "excessive_scope",
	"session_user_a", "session_user_b", "reused_session",
	"malformed_session_id", "guessed_session_id",
}

// caseOutcome is what one matrix case reports back to runMatrix
type caseOutcome struct {
	name       string
	ran        bool
	ok         bool // case-specific "control passed", used by dependent cases
	finding    *model.Finding
	skipReason string
	// inconclusive marks a skip that happened because a probe got no usable
	// answer (a dial error, a timeout, a broken tools/list channel), as
	// opposed to an ordinary documented skip (an operator-supplied token was
	// never configured). runMatrix copies this state to state.inconclusiveProbe,
	// which forces PARTIAL because an attempted boundary check proved neither
	// enforcement nor a vulnerability.
	inconclusive bool
}

func skip(name, reason string) caseOutcome { return caseOutcome{name: name, skipReason: reason} }

// inconclusiveSkip is skip's counterpart for a probe that was attempted but
// proved nothing either way - it must count against the analyzer's overall
// completion, not just explain a gap in Coverage the way an ordinary skip does
func inconclusiveSkip(name, reason string) caseOutcome {
	return caseOutcome{name: name, skipReason: reason, inconclusive: true}
}

func (a *Analyzer) runMatrix(ctx context.Context, st *state) ([]model.Finding, model.Coverage) {
	var findings []model.Finding
	cov := model.Coverage{}

	record := func(o caseOutcome) {
		cov.CapabilitiesDiscovered++
		if !o.ran {
			cov.CapabilitiesSkipped++
			cov.SkipReasons = append(cov.SkipReasons, o.name+": "+o.skipReason)
			if o.inconclusive {
				st.inconclusiveProbe = true
			}
			return
		}
		cov.CapabilitiesAnalyzed++
		if o.finding != nil {
			findings = append(findings, *o.finding)
		}
	}

	noToken := a.caseNoToken(ctx, st)
	record(noToken)
	record(a.caseValidToken(ctx, st))
	// A target that accepts no credential is not validating bearer tokens. Do not report a garbage
	// token as a separate validation failure when the same open access explains both outcomes.
	open := noToken.ran && noToken.finding != nil
	if open {
		record(skip("invalid_token", "the target accepted a request with no credential at all, so a garbage token cannot test validation that does not run"))
	} else {
		record(a.caseInvalidToken(ctx, st))
	}
	record(a.tokenCase(ctx, st, "expired_token", "auth.expired_token_accepted",
		"MCP endpoint accepts an expired token", model.SeverityHigh))
	record(a.tokenCase(ctx, st, "wrong_audience", "auth.audience_not_validated",
		"MCP endpoint accepts a token issued for a different audience", model.SeverityHigh))
	record(a.tokenCase(ctx, st, "wrong_issuer", "auth.issuer_not_validated",
		"MCP endpoint accepts a token from an untrusted issuer", model.SeverityHigh))
	insufficient := a.tokenCase(ctx, st, "insufficient_scope", "auth.scope_not_enforced",
		"MCP endpoint accepts a token without the scope its operation requires", model.SeverityMedium)
	record(insufficient)
	record(a.caseExcessiveScope(ctx, st, insufficient))
	userA := a.caseSessionUserA(ctx, st)
	record(userA)
	// Same gate, same reason: a session cannot be bound to a user the
	// target never identified. The lifetime cases below are not gated,
	// because how long a session id stays valid is a question a server
	// answers whether or not it authenticates anyone.
	if open {
		record(skip("session_user_b", "the target accepted a request with no credential at all, so a session cannot be bound to a user it never identified"))
	} else {
		record(a.caseSessionUserB(ctx, st, userA))
	}
	record(a.caseReusedSession(ctx, st))
	record(a.caseMalformedSessionID(ctx, st))
	record(a.caseGuessedSessionID(ctx, st))

	return findings, cov
}

// rejectionCase is the shared shape of every "the target should reject this"
// probe: a clean rejection means the boundary held (no finding, the case
// still ran); an accepted request means it did not (buildFinding runs); and
// anything else means the probe proved nothing, which is reported as an
// inconclusive skip rather than silently folded into either answer
func rejectionCase(name string, res dialResult, buildFinding func() model.Finding) caseOutcome {
	switch res.outcome {
	case outcomeRejected:
		return caseOutcome{name: name, ran: true}
	case outcomeInconclusive:
		return inconclusiveSkip(name, "probe was inconclusive: "+res.detail)
	default: // outcomeAccepted
		f := buildFinding()
		return caseOutcome{name: name, ran: true, finding: &f}
	}
}

func (a *Analyzer) caseNoToken(ctx context.Context, st *state) caseOutcome {
	res := st.attempt(ctx, "", "")
	return rejectionCase("no_token", res, func() model.Finding {
		ev := evidenceFor(model.EvidenceConfirmed, "unauthenticated tools/list attempt", "tools/list", "", "", res)
		sev, conf := model.SeverityLow, 0.5
		if st.metadataFound {
			sev, conf = model.SeverityHigh, 0.9
		}
		return finding("auth.no_auth_required", "broken_authentication",
			"MCP endpoint accepts requests with no Authorization header",
			sev, conf, model.EvidenceConfirmed,
			"A tools/list call succeeded with no Authorization header at all.", ev)
	})
}

func (a *Analyzer) caseValidToken(ctx context.Context, st *state) caseOutcome {
	token, ok := st.validCredential()
	if !ok {
		return skip("valid_token", "no valid test credential configured (no \"tokens.valid\" option and no Authorization header on the target)")
	}
	res := st.attempt(ctx, token, "")
	st.validToken = token
	// A failed control invalidates every conclusion that depends on it,
	// not just a warning: st.validAccepted stays false either way, so
	// session_user_a, session_user_b and reused_session all skip rather
	// than proceed as if the baseline credential were known good
	switch res.outcome {
	case outcomeAccepted:
		st.validSessionID = res.sessionID
		st.validAccepted = true
		return caseOutcome{name: "valid_token", ran: true, ok: true}
	case outcomeRejected:
		st.warnings = append(st.warnings, "the configured valid credential was rejected; dependent session checks will be skipped")
		return caseOutcome{name: "valid_token", ran: true}
	default:
		st.warnings = append(st.warnings, "the configured valid credential could not be tested; dependent session checks will be skipped")
		return inconclusiveSkip("valid_token", "probe was inconclusive: "+res.detail)
	}
}

func (a *Analyzer) caseInvalidToken(ctx context.Context, st *state) caseOutcome {
	garbage := "invalid.invalid.invalid"
	res := st.attempt(ctx, garbage, "")
	return rejectionCase("invalid_token", res, func() model.Finding {
		ev := evidenceFor(model.EvidenceConfirmed, "garbage bearer token attempt", "tools/list", garbage, "", res)
		return finding("auth.invalid_token_accepted", "broken_authentication",
			"MCP endpoint accepts a syntactically invalid bearer token",
			model.SeverityCritical, 0.95, model.EvidenceConfirmed,
			"A malformed, unsignable bearer token was accepted.", ev)
	})
}

// tokenCase covers the four matrix entries that share the same shape:
// present an operator-supplied token known to be bad in one specific way,
// and flag it if the target accepts it anyway
func (a *Analyzer) tokenCase(ctx context.Context, st *state, key, ruleID, title string, sev model.Severity) caseOutcome {
	token, ok := st.tokens[key]
	if !ok || token == "" {
		return skip(key, fmt.Sprintf("no %q test token configured (set options.auth.tokens.%s)", key, key))
	}
	res := st.attempt(ctx, token, "")
	return rejectionCase(key, res, func() model.Finding {
		ev := evidenceFor(model.EvidenceConfirmed, key+" token attempt", "tools/list", token, "", res)
		return finding(ruleID, "broken_authentication", title, sev, 0.9, model.EvidenceConfirmed,
			fmt.Sprintf("A %s token was accepted when it should have been rejected.", strings.ReplaceAll(key, "_", " ")), ev)
	})
}

// caseExcessiveScope is the control half of the scope pair: a token with
// more than enough scope should be accepted. It only produces a finding of
// its own when the result is inconsistent with the insufficient-scope case,
// which points at broken (not merely absent) scope enforcement.
func (a *Analyzer) caseExcessiveScope(ctx context.Context, st *state, insufficient caseOutcome) caseOutcome {
	token, ok := st.tokens["excessive_scope"]
	if !ok || token == "" {
		return skip("excessive_scope", "no \"excessive_scope\" test token configured (set options.auth.tokens.excessive_scope)")
	}
	res := st.attempt(ctx, token, "")
	switch res.outcome {
	case outcomeAccepted:
		return caseOutcome{name: "excessive_scope", ran: true}
	case outcomeInconclusive:
		return inconclusiveSkip("excessive_scope", "probe was inconclusive: "+res.detail)
	}
	// outcomeRejected: a broader-scoped token being refused is only
	// interesting in contrast to the insufficient-scope case being accepted
	if insufficient.ran && insufficient.finding != nil {
		ev := evidenceFor(model.EvidenceProtocol, "excessive scope token attempt", "tools/list", token, "", res)
		f := finding("auth.scope_enforcement_inverted", "broken_authorization",
			"A broader-scoped token is rejected while a narrower-scoped one is accepted",
			model.SeverityMedium, 0.6, model.EvidenceProtocol,
			"Scope enforcement appears inconsistent between an insufficient- and an excessive-scope token.", ev)
		return caseOutcome{name: "excessive_scope", ran: true, finding: &f}
	}
	st.warnings = append(st.warnings, "the configured excessive_scope token was rejected; it may not actually carry broader scope")
	return caseOutcome{name: "excessive_scope", ran: true}
}

func (a *Analyzer) caseSessionUserA(ctx context.Context, st *state) caseOutcome {
	if !st.validAccepted || st.validSessionID == "" {
		return skip("session_user_a", "no valid session available (valid_token baseline did not succeed)")
	}
	res := st.attempt(ctx, st.validToken, st.validSessionID)
	switch res.outcome {
	case outcomeAccepted:
		// Control case: the session's own owner reusing it is expected to
		// work, so this is never itself a finding
		return caseOutcome{name: "session_user_a", ran: true, ok: true}
	case outcomeRejected:
		st.warnings = append(st.warnings, "the owning user's own session id was rejected on reuse; the cross-user check will be skipped")
		return caseOutcome{name: "session_user_a", ran: true}
	default:
		return inconclusiveSkip("session_user_a", "probe was inconclusive: "+res.detail)
	}
}

func (a *Analyzer) caseSessionUserB(ctx context.Context, st *state, userA caseOutcome) caseOutcome {
	if !userA.ran || !userA.ok {
		return skip("session_user_b", "session-reuse-by-owner control case did not succeed; cannot test cross-user reuse")
	}
	tokenB, ok := st.tokens["user_b"]
	if !ok || tokenB == "" {
		return skip("session_user_b", "no \"user_b\" test token configured (set options.auth.tokens.user_b)")
	}
	res := st.attempt(ctx, tokenB, st.validSessionID)
	return rejectionCase("session_user_b", res, func() model.Finding {
		ev := evidenceFor(model.EvidenceProtocol, "different user presenting user A's session id", "tools/list", tokenB, st.validSessionID, res)
		level, sev := model.EvidenceProtocol, model.SeverityHigh
		desc := "A second user's token, combined with the first user's session id, was accepted at the protocol level."
		if tool, ok := identityTool(st.ac); ok {
			identity, err := st.identityViaTool(ctx, tokenB, st.validSessionID, tool)
			switch {
			case err == nil && identity != "":
				ev.Data["identity_returned"] = identity
				level, sev = model.EvidenceConfirmed, model.SeverityCritical
				desc = fmt.Sprintf("A second user's token, combined with the first user's session id, was accepted and returned identity %q.", identity)
			default:
				// An operator configures identity_tool precisely to get the
				// stronger answer here. Staying at the protocol level with
				// nothing said about why reads as though the tool was never
				// configured at all.
				st.warnings = append(st.warnings, fmt.Sprintf(
					"identity_tool %q did not return an identity for the cross-user session probe, so this finding stays at the protocol level: %s",
					tool, describeErr(err)))
			}
		}
		ev.Level = level
		return finding("auth.session_not_bound_to_user", "broken_access_control",
			"A session id is honored regardless of which user's token accompanies it",
			sev, 0.85, level, desc, ev)
	})
}

func (a *Analyzer) caseReusedSession(ctx context.Context, st *state) caseOutcome {
	if !st.validAccepted || st.validToken == "" {
		return skip("reused_session", "no valid credential configured")
	}
	sess, err := st.probeDialer().Dial(ctx, withAuth(st.target, st.validToken, ""))
	if err != nil {
		reason := "could not open a session to close and reuse: " + describeErr(err)
		if classifyErr(err) == outcomeInconclusive {
			return inconclusiveSkip("reused_session", reason)
		}
		return skip("reused_session", reason)
	}
	sid := sess.SessionID()
	sess.Close() // our test dialer sends this as an HTTP DELETE, MCP's session-termination convention
	if sid == "" {
		return skip("reused_session", "target did not return a session id to test reuse of")
	}

	res := st.attempt(ctx, st.validToken, sid)
	return rejectionCase("reused_session", res, func() model.Finding {
		ev := evidenceFor(model.EvidenceConfirmed, "reuse of a closed session id", "tools/list", st.validToken, sid, res)
		return finding("auth.reused_session_accepted", "broken_session_management",
			"A closed session id is still accepted",
			model.SeverityMedium, 0.75, model.EvidenceConfirmed,
			"A session that was explicitly terminated was accepted again afterward.", ev)
	})
}

func (a *Analyzer) caseMalformedSessionID(ctx context.Context, st *state) caseOutcome {
	// Without a credential the rejection this case reads as "the malformed
	// id was refused" is the target refusing the missing token, and the
	// session id never got a verdict at all. guessed_session_id already
	// declines to run for the same reason
	token, ok := st.validCredential()
	if !ok {
		return skip("malformed_session_id", "no valid credential configured, so a rejection could not be attributed to the session id rather than the missing token")
	}
	// A target that handshook successfully and issued no session id has no
	// session ids to validate - a stateless deployment is the ordinary case.
	// Sending it a malformed one gets the same answer every other request
	// gets, and reading that as "the malformed id was accepted" reports a
	// mechanism the target does not have.
	if st.validAccepted && st.validSessionID == "" {
		return skip("malformed_session_id", "the target issued no session id on a successful handshake, so it has no session ids to validate")
	}
	malformed := "' OR '1'='1"
	res := st.attempt(ctx, token, malformed)
	return rejectionCase("malformed_session_id", res, func() model.Finding {
		ev := evidenceFor(model.EvidenceConfirmed, "malformed session id", "tools/list", token, malformed, res)
		return finding("auth.malformed_session_id_accepted", "broken_session_management",
			"An unrecognized, malformed session id is accepted instead of rejected",
			model.SeverityMedium, 0.7, model.EvidenceConfirmed,
			"A structurally invalid session id was accepted rather than rejected.", ev)
	})
}

func (a *Analyzer) caseGuessedSessionID(ctx context.Context, st *state) caseOutcome {
	token, ok := st.validCredential()
	if !ok {
		return skip("guessed_session_id", "no valid credential configured")
	}
	a1 := st.attempt(ctx, token, "")
	a2 := st.attempt(ctx, token, "")
	if a1.outcome == outcomeInconclusive || a2.outcome == outcomeInconclusive {
		return inconclusiveSkip("guessed_session_id", "could not obtain two fresh session ids to compare: probe was inconclusive")
	}
	if !a1.accepted() || !a2.accepted() || a1.sessionID == "" || a2.sessionID == "" {
		return skip("guessed_session_id", "could not obtain two fresh session ids to compare")
	}
	if a1.sessionID == a2.sessionID || !predictable(a1.sessionID, a2.sessionID) {
		return caseOutcome{name: "guessed_session_id", ran: true}
	}
	ev := evidenceFor(model.EvidenceProtocol, "two freshly issued session ids", "initialize", token, "", a2)
	ev.Data["session_id_1"] = redactSessionID(a1.sessionID)
	ev.Data["session_id_2"] = redactSessionID(a2.sessionID)
	f := finding("auth.guessable_session_id", "broken_session_management",
		"Session ids are predictable",
		model.SeverityHigh, 0.7, model.EvidenceProtocol,
		fmt.Sprintf("Two freshly issued session ids follow a predictable pattern: %s.", predictabilityReason(a1.sessionID, a2.sessionID)), ev)
	return caseOutcome{name: "guessed_session_id", ran: true, finding: &f}
}

// predictable flags the classic smells of a guessable id: too short to
// carry meaningful entropy, or two ids that share a literal prefix and
// differ only by a small integer suffix (sequential counters)
func predictable(a, b string) bool {
	if len(a) < 16 || len(b) < 16 {
		return true
	}
	pa, na := splitTrailingDigits(a)
	pb, nb := splitTrailingDigits(b)
	if pa != pb || na == "" || nb == "" {
		return false
	}
	ia, erra := strconv.Atoi(na)
	ib, errb := strconv.Atoi(nb)
	if erra != nil || errb != nil {
		return false
	}
	diff := ia - ib
	return diff > -1000 && diff < 1000
}

// predictabilityReason names which of predictable's two patterns matched, without the id
// values themselves - the finding built from it carries the shape of the problem, not the
// live session ids that demonstrate it
func predictabilityReason(a, b string) string {
	if len(a) < 16 || len(b) < 16 {
		return "too short to carry meaningful entropy"
	}
	return "share a literal prefix and differ only by a small increment (a sequential counter)"
}

func splitTrailingDigits(s string) (prefix, digits string) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	return s[:i], s[i:]
}

// identityViaTool dials with the given credentials, calls the named
// allowlisted tool, and returns whatever text it responds with
func (st *state) identityViaTool(ctx context.Context, token, sessionID, tool string) (string, error) {
	// Resumed rather than handshaked, for the same reason the case that
	// calls this one is: the question is whether the target serves this
	// session id to this token, and running initialize while carrying the
	// id would be asking something else
	opts := analyzer.DialOptions{}
	if sessionID != "" {
		opts.ResumeSessionID = sessionID
	}
	sess, err := st.probeDial(ctx, withAuth(st.target, token, ""), opts)
	if err != nil {
		return "", err
	}
	defer sess.Close()
	res, err := sess.CallTool(ctx, tool, map[string]any{})
	if err != nil {
		return "", err
	}
	if len(res.Text) > 0 {
		return res.Text[0], nil
	}
	return "", nil
}

// checkSessionFixation is not one of the 13 credential/session matrix
// cases (it needs no operator-supplied token, so it is tracked as its own
// coverage item, the same way checkTokenPassthrough is): it dials with a
// client-chosen Mcp-Session-Id and checks whether the server adopted it
// instead of minting its own unpredictable one
func (a *Analyzer) checkSessionFixation(ctx context.Context, st *state) (ran bool, f *model.Finding, skipReason string) {
	if st.probeDialer() == nil {
		return false, nil, "no dialer available"
	}
	token, ok := st.validCredential()
	if !ok {
		return false, nil, "no valid credential configured"
	}
	const chosen = "attacker-chosen-session-id-0000000000000000"
	t := withAuth(st.target, token, "")
	// The id goes on the initialize request itself and on nothing after it,
	// which is what makes this the session-fixation question: does the
	// server mint its own id, or adopt the one the client proposed. Sending
	// it on every request instead would be the resume probe, which asks
	// something else.
	sess, err := st.probeDial(ctx, t, analyzer.DialOptions{ProposeSessionID: chosen})
	if err != nil {
		if unsupportedProbe(err) {
			// Not "the boundary held". The probe was never made, and a
			// check that cannot be made must not raise the analyzed count.
			st.inconclusiveProbe = true
			return false, nil, "this connection layer cannot propose a session id at initialize, so session fixation was not tested"
		}
		// A failed dial proves nothing about session fixation
		if classifyErr(err) == outcomeInconclusive {
			st.inconclusiveProbe = true
		}
		return false, nil, "could not open a session to test: " + describeErr(err)
	}
	defer sess.Close()
	got := sess.SessionID()
	if got == "" {
		// Stateless servers and legacy SSE connections expose no session id. Without one, the
		// probe cannot tell whether the server adopted the proposed id.
		return false, nil, "the connection exposes no session id, so whether the server adopted the proposed one could not be observed"
	}
	if got != chosen {
		return true, nil, ""
	}
	ev := model.Evidence{
		Level: model.EvidenceConfirmed, Kind: "auth_probe", Description: "client-supplied session id at initialize",
		// A server that accepts a client-chosen session id has made that
		// id a working credential against itself, so it leaves the report
		// redacted like every other session id here. The finding does not
		// need the value: it is that the two matched, and the branch above
		// returned already if they had not.
		Data: map[string]any{"authorization": redactAuth(bearer(token)),
			"chosen_session_id": redactSessionID(chosen), "returned_session_id": redactSessionID(got)},
	}
	fnd := finding("auth.session_fixation", "broken_session_management",
		"Server accepts a client-chosen session id instead of minting its own",
		model.SeverityHigh, 0.85, model.EvidenceConfirmed,
		"The server echoed back a client-supplied Mcp-Session-Id instead of generating a fresh, unpredictable one.", ev)
	return true, &fnd, ""
}

// checkTokenPassthrough looks for a confused-deputy signal: a tool response
// that echoes the exact bearer token it was called with back to the caller,
// which would mean the server forwarded the token somewhere instead of
// consuming it locally
func (a *Analyzer) checkTokenPassthrough(ctx context.Context, st *state) (ran bool, f *model.Finding, skipReason string) {
	if st.probeDialer() == nil {
		return false, nil, "no dialer available"
	}
	if !st.ac.Probes.AtLeast(analyzer.ProbeToolCalls) {
		return false, nil, "probe level below tool-calls"
	}
	tool, ok := identityTool(st.ac)
	if !ok {
		return false, nil, "no identity_tool configured (or not in the allowlist)"
	}
	token, ok := st.validCredential()
	if !ok {
		return false, nil, "no valid credential configured"
	}

	sess, err := st.probeDialer().Dial(ctx, withAuth(st.target, token, ""))
	if err != nil {
		if classifyErr(err) == outcomeInconclusive {
			st.inconclusiveProbe = true
		}
		return false, nil, "could not dial: " + describeErr(err)
	}
	defer sess.Close()

	res, err := sess.CallTool(ctx, tool, map[string]any{})
	if err != nil {
		// The call never happened - refused, timed out, or the connection
		// died - which is not the same as it running and echoing nothing
		// back. Read the same way a failed dial or tools/list already is:
		// the scanner learned nothing about token passthrough here.
		st.inconclusiveProbe = true
		return false, nil, "identity tool call failed: " + describeErr(err)
	}
	for _, text := range res.Text {
		if strings.Contains(text, token) {
			ev := model.Evidence{
				Level: model.EvidenceProtocol, Kind: "auth_probe", Description: "identity tool response",
				Data: map[string]any{"authorization": redactAuth(bearer(token)), "tool": tool},
			}
			pf := finding("auth.token_passthrough", "confused_deputy",
				"The caller's bearer token is echoed back by a tool response",
				model.SeverityHigh, 0.6, model.EvidenceProtocol,
				"A tool response contained the exact bearer token used to call it, suggesting it is forwarded rather than terminated at this server.", ev)
			return true, &pf, ""
		}
	}
	return true, nil, ""
}
