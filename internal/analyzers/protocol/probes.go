package protocol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

// probeTimeout bounds every individual probe: a hung server must not hang
// the analyzer along with it. A var, not a const, so tests simulating a hang
// do not have to actually wait out the production timeout.
var probeTimeout = 10 * time.Second

// leakPatterns are substrings that show up in a stack trace or an internal
// filesystem path but essentially never in a normal protocol error message
var leakPatterns = []string{
	".go:", "goroutine ", "panic:", "runtime error:",
	"Traceback (most recent",
	"/home/", "/usr/", "/root/", `C:\`,
}

// leakRegexes catches shapes a plain substring cannot without firing on ordinary text: "0x"
// alone matches any message that quotes a byte or rune ("invalid character 0x00"), and
// "\tat " alone matches any tab-indented line
var leakRegexes = []*regexp.Regexp{
	regexp.MustCompile(`0x[0-9a-fA-F]{6,}`),
	regexp.MustCompile(`\n\tat [\w.$]+\(`),
}

func leaksInternals(s string) (bool, string) {
	for _, p := range leakPatterns {
		if strings.Contains(s, p) {
			return true, p
		}
	}
	for _, re := range leakRegexes {
		if m := re.FindString(s); m != "" {
			return true, m
		}
	}
	return false, ""
}

// credentialHeaderNames are the header names known to carry a credential.
// Anything else passes through unredacted.
const credentialHeaderNames = `authorization|proxy-authorization|x-api-key|api-key|x-auth-token|cookie|set-cookie`

// jsonCredentialHeader matches a credential header written as a JSON key,
// the shape requestEvidence and every raw-response call site actually
// produce: `"Authorization":"Bearer ..."`. The value is captured separately
// from the key so it can be dropped while the key survives.
var jsonCredentialHeader = regexp.MustCompile(`(?i)"(` + credentialHeaderNames + `)"\s*:\s*"(?:[^"\\]|\\.)*"`)

// plainCredentialHeader matches the same headers written as plain
// "name: value" text, e.g. an error message that echoes a rejected request
// back verbatim instead of as JSON
var plainCredentialHeader = regexp.MustCompile(`(?i)\b(` + credentialHeaderNames + `)(\s*:\s*)[^\n"]*`)

// redact bounds a string for use as evidence and strips the value of any
// credential-carrying header it contains, in case a probe's error text or a raw server
// response ever echoes request headers back
func redact(s string) string {
	const maxLen = 400
	s = jsonCredentialHeader.ReplaceAllString(s, `"$1":"[redacted]"`)
	s = plainCredentialHeader.ReplaceAllString(s, "$1$2[redacted]")
	if len(s) > maxLen {
		s = s[:maxLen] + "...(truncated)"
	}
	return s
}

// requestEvidence renders the request half of a probe's evidence: the exact
// method and params that were sent, so a reader can see what triggered the
// finding without re-running the probe
func requestEvidence(method string, params any) map[string]any {
	data := map[string]any{"method": method}
	if b, err := json.Marshal(params); err == nil {
		data["params"] = redact(string(b))
	}
	return data
}

// acceptedUnanswered reports whether err reflects a request the server took but never
// replied to, as opposed to a clean rejection or a dead connection. A written request timing
// out, or a 2xx response with no decodable body, proves acceptance without a JSON-RPC answer.
func acceptedUnanswered(err error) (bool, string) {
	if sc, ok := errors.AsType[analyzer.StatusCoder](err); ok {
		if status := sc.Status(); status >= 200 && status < 300 {
			return true, fmt.Sprintf("HTTP %d, no reply", status)
		}
		return false, ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true, "no reply before the probe timeout"
	}
	return false, ""
}

// evaluateRejectionProbe is shared by every probe whose only correct outcome is a clean
// rejection: the server may answer with any JSON-RPC error, or a transport-level rejection
// (some servers reject an unroutable request at the HTTP layer before JSON-RPC dispatch
// ever sees it) - both count as "handled cleanly"
func evaluateRejectionProbe(label, method string, params any, err error) []model.Finding {
	req := requestEvidence(method, params)
	if err == nil {
		req["response"] = "request accepted"
		return []model.Finding{newFinding(
			RuleProbeUnexpectedAnswer, "protocol_conformance", "Server answered a request that should have been rejected",
			model.SeverityMedium, model.EvidenceProtocol, 0.6, "",
			fmt.Sprintf("The %s probe expected a clean rejection; the server answered successfully instead.", label),
			protocolEvidence(label, "request accepted", req),
		)}
	}
	// Check this before accepted-unanswered. An HTTP request can return 202 and then lose the
	// response stream, which means the connection died rather than the server staying silent.
	if errors.Is(err, analyzer.ErrConnectionClosed) {
		req["response"] = "connection closed without an answer"
		return []model.Finding{newFinding(
			RuleProbeConnectionDied, "protocol_conformance", "Server dropped the connection instead of answering a probe",
			model.SeverityHigh, model.EvidenceProtocol, 0.6, "",
			fmt.Sprintf("The %s probe got no answer: the server closed the connection or exited instead of rejecting the request.", label),
			protocolEvidence(label, "connection closed without an answer", req),
		)}
	}
	// This is not "the server did not answer" in general - a client-side decode failure on a
	// 2xx, or a deadline that can only be reached after the request was written successfully,
	// both mean the server took the request and chose not to reply
	if accepted, detail := acceptedUnanswered(err); accepted {
		req["response"] = detail
		return []model.Finding{newFinding(
			RuleProbeAcceptedUnanswered, "protocol_conformance", "Server accepted a request without ever answering it",
			model.SeverityMedium, model.EvidenceProtocol, 0.6, "",
			fmt.Sprintf("The %s probe sent a request that should have been rejected; the server accepted it (%s) and never sent a response.", label, detail),
			protocolEvidence(label, detail, req),
		)}
	}
	if leaked, pattern := leaksInternals(err.Error()); leaked {
		req["response"] = redact(err.Error())
		return []model.Finding{newFinding(
			RuleProbeLeaksInternals, "information_disclosure", "Error message leaks internal detail",
			model.SeverityMedium, model.EvidenceProtocol, 0.7, "",
			fmt.Sprintf("The %s probe's error response looks like it leaked internal detail (matched %q).", label, pattern),
			protocolEvidence(label, redact(err.Error()), req),
		)}
	}
	return nil
}

// probeUnknownMethod sends a method name that cannot exist. -32601 is the
// textbook answer; see evaluateRejectionProbe for what else is acceptable
func probeUnknownMethod(ctx context.Context, sess analyzer.Session) []model.Finding {
	const method = "mcp-scanner/definitely-not-a-real-method"
	_, err := sess.Call(ctx, method, nil)
	return evaluateRejectionProbe("unknown method", method, nil, err)
}

// probeInvalidParams sends a known method with a param whose type violates
// its schema (name should be a string)
func probeInvalidParams(ctx context.Context, sess analyzer.Session) []model.Finding {
	params := map[string]any{"name": 12345}
	_, err := sess.Call(ctx, "tools/call", params)
	return evaluateRejectionProbe("invalid params", "tools/call", params, err)
}

// probeMalformedRequest sends a request that is not well-formed JSON-RPC: an
// empty method (go-sdk#976 treats "" as a real, if unusual, method name) with
// a bare-value params, which the spec requires to be an object or array
func probeMalformedRequest(ctx context.Context, sess analyzer.Session) []model.Finding {
	_, err := sess.Call(ctx, "", 42)
	return evaluateRejectionProbe("malformed request", "", 42, err)
}

// probeInvalidResourceURI asks to read a resource whose URI is not one
func probeInvalidResourceURI(ctx context.Context, sess analyzer.Session) []model.Finding {
	params := map[string]any{"uri": "not a uri \x00\x01"}
	_, err := sess.Call(ctx, "resources/read", params)
	return evaluateRejectionProbe("invalid resource URI", "resources/read", params, err)
}

// probeUnsupportedProtocolVersion asks a fresh, not-yet-initialized channel to negotiate a
// protocol version nobody speaks. A compliant server may reject this outright, or may
// negotiate down to a version it does support and answer normally - both are fine.
func probeUnsupportedProtocolVersion(ctx context.Context, sess analyzer.Session) []model.Finding {
	const bogusVersion = "1999-01-01"
	params := map[string]any{
		"protocolVersion": bogusVersion,
		"clientInfo":      map[string]any{"name": "mcp-scanner-probe", "version": "0"},
		"capabilities":    map[string]any{},
	}
	raw, err := sess.Call(ctx, "initialize", params)
	if err != nil {
		return evaluateRejectionProbe("unsupported protocol version", "initialize", params, err)
	}
	req := requestEvidence("initialize", params)
	req["response"] = redact(string(raw))
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if jerr := json.Unmarshal(raw, &result); jerr != nil || result.ProtocolVersion == "" {
		return []model.Finding{newFinding(
			RuleProbeUnexpectedAnswer, "protocol_conformance", "Server accepted an unsupported protocol version without negotiating",
			model.SeverityMedium, model.EvidenceProtocol, 0.6, "",
			"initialize succeeded for an unsupported protocol version but returned no usable protocolVersion in the result.",
			protocolEvidence("unsupported protocol version", redact(string(raw)), req),
		)}
	}
	if result.ProtocolVersion == bogusVersion {
		return []model.Finding{newFinding(
			RuleProbeUnexpectedAnswer, "protocol_conformance", "Server echoed back an unsupported protocol version instead of negotiating",
			model.SeverityMedium, model.EvidenceProtocol, 0.7, "",
			fmt.Sprintf("initialize with protocolVersion %q succeeded and echoed that exact version back, rather than rejecting it or negotiating a version the server actually supports.", bogusVersion),
			protocolEvidence("unsupported protocol version", redact(string(raw)), req),
		)}
	}
	return nil // negotiated down to a real version: correct behavior
}

// probeInvalidToolName calls a tool that does not exist. The expected shape
// is a normal, successful response with IsError true (an "error result"),
// not a JSON-RPC-level failure - though a clean JSON-RPC rejection is also
// acceptable. Only pretending the call succeeded, or leaking internals in
// the error text, is a problem.
func probeInvalidToolName(ctx context.Context, sess analyzer.Session) []model.Finding {
	params := map[string]any{
		"name": "mcp-scanner-definitely-not-a-real-tool", "arguments": map[string]any{},
	}
	raw, err := sess.Call(ctx, "tools/call", params)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return evaluateRejectionProbe("invalid tool name", "tools/call", params, err)
		}
		if leaked, pattern := leaksInternals(err.Error()); leaked {
			req := requestEvidence("tools/call", params)
			req["response"] = redact(err.Error())
			return []model.Finding{newFinding(
				RuleProbeLeaksInternals, "information_disclosure", "Error message leaks internal detail",
				model.SeverityMedium, model.EvidenceProtocol, 0.7, "",
				fmt.Sprintf("The invalid tool name probe's error response looks like it leaked internal detail (matched %q).", pattern),
				protocolEvidence("invalid tool name", redact(err.Error()), req),
			)}
		}
		return nil // a clean JSON-RPC-level rejection is fine too
	}

	var result struct {
		IsError bool             `json:"isError"`
		Content []map[string]any `json:"content"`
	}
	_ = json.Unmarshal(raw, &result)
	text := fmt.Sprint(result.Content)
	req := requestEvidence("tools/call", params)
	req["response"] = redact(text)
	if leaked, pattern := leaksInternals(text); leaked {
		return []model.Finding{newFinding(
			RuleProbeLeaksInternals, "information_disclosure", "Tool error result leaks internal detail",
			model.SeverityMedium, model.EvidenceProtocol, 0.7, "",
			fmt.Sprintf("Calling a nonexistent tool returned content that looks like it leaked internal detail (matched %q).", pattern),
			protocolEvidence("invalid tool name", redact(text), req),
		)}
	}
	if !result.IsError {
		return []model.Finding{newFinding(
			RuleProbeUnexpectedAnswer, "protocol_conformance", "Server did not report an error for a nonexistent tool",
			model.SeverityMedium, model.EvidenceProtocol, 0.6, "",
			"tools/call for a tool name that was never declared returned a successful result instead of isError=true or a JSON-RPC error.",
			protocolEvidence("invalid tool name", redact(string(raw)), req),
		)}
	}
	return nil
}

// probeCapabilityMismatchActive checks the direction of the capability
// mismatch that discovery deliberately does not attempt: a method the
// server never advertised support for, answered anyway. This is a small,
// bounded number of read-only list calls, safe at the same level as the
// other probes here.
func probeCapabilityMismatchActive(ctx context.Context, snap *model.Snapshot, sess analyzer.Session) []model.Finding {
	if snap == nil || sess == nil {
		return nil
	}
	checks := []struct {
		advertised bool
		method     string
		label      string
	}{
		{snap.Capabilities["tools"] != nil, "tools/list", "tools"},
		{snap.Capabilities["prompts"] != nil, "prompts/list", "prompts"},
		{snap.Capabilities["resources"] != nil, "resources/list", "resources"},
	}
	var findings []model.Finding
	for _, c := range checks {
		if c.advertised {
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		_, err := sess.Call(pctx, c.method, map[string]any{})
		cancel()
		if err == nil {
			findings = append(findings, newFinding(
				RuleCapabilityMismatch, "protocol_conformance", "Server answers a method for a capability it does not advertise",
				model.SeverityMedium, model.EvidenceProtocol, 0.7, "",
				fmt.Sprintf("%s answered even though the %s capability was never advertised in initialize.", c.method, c.label),
				protocolEvidence(c.method, "request accepted", map[string]any{"method": c.method}),
			))
		}
	}
	return findings
}

// withoutRule drops every finding carrying one of ruleIDs. It exists for the
// one case where a finding was already built before the caller learned it
// was about the scanner rather than the target.
func withoutRule(fs []model.Finding, ruleIDs ...string) []model.Finding {
	out := fs[:0:0]
	for _, f := range fs {
		drop := slices.Contains(ruleIDs, f.RuleID)
		if !drop {
			out = append(out, f)
		}
	}
	return out
}

// probeSpec names one probe function for the orchestrator below
type probeSpec struct {
	name string
	run  func(ctx context.Context, sess analyzer.Session) []model.Finding
}

func activeProbeSpecs() []probeSpec {
	return []probeSpec{
		{"unknown method", probeUnknownMethod},
		{"invalid params", probeInvalidParams},
		{"malformed request", probeMalformedRequest},
		{"unsupported protocol version", probeUnsupportedProtocolVersion},
		{"invalid resource URI", probeInvalidResourceURI},
		{"invalid tool name", probeInvalidToolName},
	}
}

// runActiveProbes runs every safe probe against ac.Session, checking after each one that the
// connection survived. If a probe kills the session, it reconnects through ac.Dialer so later
// probes and the capability-mismatch check do not use a dead session. complete is false when a
// probe or reconnect cannot finish, which makes the analyzer PARTIAL.
func runActiveProbes(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) (findings []model.Finding, warnings []string, complete bool) {
	sess := ac.Session
	complete = true
	var extraSessions []analyzer.Session
	defer func() {
		for _, s := range extraSessions {
			_ = s.Close()
		}
	}()

	for _, p := range activeProbeSpecs() {
		if ctx.Err() != nil {
			warnings = append(warnings, fmt.Sprintf(
				"probe %q did not run: the analyzer or scan deadline elapsed first", p.name))
			complete = false
			break
		}
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		fs := p.run(pctx, sess)
		cancel()
		if ctx.Err() != nil {
			// pctx is a child of the analyzer and scan contexts, so a probe sees
			// context.DeadlineExceeded whichever of the three clocks ran out. A deadline the scanner
			// imposed on itself is not a fact about the target, so any "the server did not answer"
			// finding the probe drew from it does not stand; the gap is recorded instead.
			findings = append(findings, withoutRule(fs, RuleProbeConnectionDied, RuleProbeAcceptedUnanswered)...)
			warnings = append(warnings, fmt.Sprintf(
				"probe %q was cut short by the analyzer or scan deadline, not by its own %s bound", p.name, probeTimeout))
			complete = false
			break
		}
		findings = append(findings, fs...)
		// The ping still runs so the analyzer can reconnect, but it must not report a connection
		// death already reported by the probe
		diedOnProbe := false
		for _, f := range fs {
			if f.RuleID == RuleProbeConnectionDied {
				diedOnProbe = true
			}
		}

		lctx, lcancel := context.WithTimeout(ctx, probeTimeout)
		_, perr := sess.Call(lctx, "ping", nil)
		lcancel()
		if perr == nil {
			continue
		}
		if _, ok := errors.AsType[*analyzer.ProtocolError](perr); ok {
			// A JSON-RPC error reply is the connection answering: the
			// server is there, the framing survived the probe, and it chose
			// to reject this call. A server that answers ping with -32601
			// is alive by definition. session.go draws the same line for
			// the same call and keeps the channel rather than dropping it.
			continue
		}
		if ctx.Err() != nil {
			warnings = append(warnings, fmt.Sprintf(
				"the liveness ping after probe %q was cut short by the analyzer or scan deadline, not by its own %s bound", p.name, probeTimeout))
			complete = false
			break
		}
		if !diedOnProbe {
			findings = append(findings, newFinding(
				RuleProbeConnectionDied, "protocol_conformance", "Connection did not survive a probe",
				model.SeverityHigh, model.EvidenceProtocol, 0.6, "",
				fmt.Sprintf("After the %q probe, a ping to the server got no clean answer: %v", p.name, perr),
				protocolEvidence("ping", redact(perr.Error()), map[string]any{"after_probe": p.name}),
			))
		}
		if ac.Dialer == nil {
			complete = false
			continue
		}
		newSess, derr := ac.Dialer.Dial(ctx, target)
		if derr != nil {
			// The remaining probes cannot run, and attributing each connection failure to its
			// probe would create duplicate findings
			warnings = append(warnings, fmt.Sprintf("could not reconnect after the %q probe, so the remaining probes did not run: %v", p.name, derr))
			complete = false
			break
		}
		extraSessions = append(extraSessions, newSess)
		sess = newSess
	}

	findings = append(findings, probeCapabilityMismatchActive(ctx, ac.Snapshot, sess)...)
	return findings, warnings, complete
}
