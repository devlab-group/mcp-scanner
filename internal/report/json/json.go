// Package json writes sanitized ScanResult values using the versioned schema. Model JSON tags
// define the wire format; this layer adds formatting and the same escaping as other reporters.
package json

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/devlab-group/mcp-scanner/internal/report"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

// Write serializes and sanitizes one result. Target headers and environment
// variables are excluded by model.Target's JSON tags.
func Write(w io.Writer, result *model.ScanResult) error {
	return encodeSanitized(w, result)
}

// WriteMany serializes results as a single top-level JSON array, for a
// command that scans more than one target (known-configs --run) into one
// report instead of one file per target
func WriteMany(w io.Writer, results []*model.ScanResult) error {
	if results == nil {
		results = []*model.ScanResult{}
	}
	return encodeSanitized(w, results)
}

// SanitizedValue applies Write's string escaping for callers with their own
// envelope, such as the HTTP API
func SanitizedValue(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return sanitizeJSON(data)
}

// encodeSanitized marshals v the normal way, then re-decodes and
// re-encodes it through sanitizeJSON before writing it out
func encodeSanitized(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sanitized, err := sanitizeJSON(data)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sanitized)
}

// sanitizeJSON walks decoded values so new schema fields are covered. It sanitizes Go
// strings before re-encoding, preserving escape markers after a JSON round trip.
func sanitizeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return sanitizeValue(v), nil
}

// sanitizeValue recurses through the map[string]any/[]any tree
// encoding/json produces from a UseNumber decode, running every string -
// map key or leaf value - through report.SanitizeBlock. Numbers
// (json.Number, which marshals back out using its original text), bools
// and nil pass through untouched.
func sanitizeValue(v any) any {
	switch t := v.(type) {
	case string:
		return report.SanitizeBlock(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[report.SanitizeBlock(k)] = sanitizeValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = sanitizeValue(val)
		}
		return out
	default:
		return v
	}
}
