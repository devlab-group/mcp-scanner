// Package observer turns a raw sandbox run into []analyzer.Observation. With no in-container
// instrumentation, it relies on canaries, synthetic-network hits, captured output, and explicit
// fixture markers; findings claim only what those signals demonstrate.
package observer

import (
	"strconv"
	"strings"

	"github.com/revinand/mcp-scanner/pkg/analyzer"
)

// MaxCapture bounds how much of stdout/stderr is retained for evidence.
// Anything sandboxed output can be arbitrarily large or adversarial; nothing
// downstream should have to allocate proportionally to it.
const MaxCapture = 8192

// obsPrefix is the self-report convention fixtures may use. It is never
// trusted on its own for canary_hit accounting; it only produces file_read,
// file_write, process_exec, net_connect and dns_query observations.
const obsPrefix = "MCP-OBS:"

// Input is everything the observer needs to reconstruct what happened
type Input struct {
	Started  bool
	ExitCode int
	TimedOut bool
	Reaped   bool
	Stdout   string
	Stderr   string
	Canaries []analyzer.Canary
}

// Observe builds the observation list for a completed (or aborted) run
func Observe(in Input) []analyzer.Observation {
	var out []analyzer.Observation

	if in.Started {
		out = append(out, analyzer.Observation{
			Kind:   "process_exec",
			Detail: "sandbox entrypoint executed, exit_code=" + strconv.Itoa(in.ExitCode),
			Data: map[string]any{
				"timed_out": in.TimedOut,
				"reaped":    in.Reaped,
			},
		})
	}

	// Search the raw, untruncated capture: a tool whose ordinary reply
	// exceeds MaxCapture would otherwise hide every canary it echoes past
	// that point, and at --network none this search is the only observation
	// channel there is. Sanitize is applied afterward, only to what gets
	// kept for the report.
	raw := in.Stdout + "\n" + in.Stderr

	for _, c := range in.Canaries {
		if c.Value == "" {
			continue
		}
		if strings.Contains(raw, c.Value) {
			out = append(out, analyzer.Observation{
				Kind:     "canary_hit",
				CanaryID: c.ID,
				Detail:   "canary value (" + c.Kind + ") appeared in sandbox output",
				Data: map[string]any{
					"kind": c.Kind,
					"path": c.Path,
					"env":  c.Env,
				},
			})
		}
	}

	combined := Sanitize(in.Stdout, MaxCapture) + "\n" + Sanitize(in.Stderr, MaxCapture)
	out = append(out, selfReported(combined)...)

	return out
}

// selfReported parses "MCP-OBS:<kind>:<detail>" lines emitted by
// scanner-authored fixtures. kind must be one of the Observation kinds this
// package already knows about; anything else is ignored rather than trusted
// blindly
func selfReported(text string) []analyzer.Observation {
	valid := map[string]bool{
		"file_read": true, "file_write": true, "process_exec": true,
		"net_connect": true, "dns_query": true,
	}
	var out []analyzer.Observation
	for line := range strings.SplitSeq(text, "\n") {
		if !strings.HasPrefix(line, obsPrefix) {
			continue
		}
		rest := strings.TrimPrefix(line, obsPrefix)
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) != 2 || !valid[parts[0]] {
			continue
		}
		out = append(out, analyzer.Observation{
			Kind:   parts[0],
			Detail: Sanitize(parts[1], 512),
		})
	}
	return out
}

// Sanitize bounds s to max bytes and escapes control characters, so captured
// sandbox output is always safe to put in a report or a log line
func Sanitize(s string, max int) string {
	if len(s) > max {
		s = s[:max] + "...(truncated)"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteString(strconv.QuoteRune(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
