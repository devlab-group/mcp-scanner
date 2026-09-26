package model

// EvidenceLevel says how the scanner learned something. A regex match on a
// tool description and a payload that actually executed in a sandbox are both
// findings, but they are not the same claim, so they never share a level.
type EvidenceLevel string

const (
	// EvidenceHeuristic is a guess: keyword match, naming convention, shape
	EvidenceHeuristic EvidenceLevel = "HEURISTIC"
	// EvidenceStatic came from parsing the source, not from grepping it
	EvidenceStatic EvidenceLevel = "STATIC"
	// EvidenceDataflow is a traced source-to-sink path
	EvidenceDataflow EvidenceLevel = "DATAFLOW"
	// EvidenceProtocol came from observed MCP protocol behaviour
	EvidenceProtocol EvidenceLevel = "PROTOCOL"
	// EvidenceDynamic came from running the target
	EvidenceDynamic EvidenceLevel = "DYNAMIC"
	// EvidenceConfirmed means a controlled payload produced the predicted effect
	EvidenceConfirmed EvidenceLevel = "CONFIRMED"
)

var evidenceRank = map[EvidenceLevel]int{
	EvidenceHeuristic: 0,
	EvidenceStatic:    1,
	EvidenceDataflow:  2,
	EvidenceProtocol:  2,
	EvidenceDynamic:   3,
	EvidenceConfirmed: 4,
}

func (e EvidenceLevel) Rank() int {
	if r, ok := evidenceRank[e]; ok {
		return r
	}
	return -1
}

func (e EvidenceLevel) Valid() bool { _, ok := evidenceRank[e]; return ok }

// Evidence is one observation backing a finding. Snippets may contain target-controlled or
// sensitive text, so analyzers redact secrets and human-facing writers escape unsafe characters.
type Evidence struct {
	Level       EvidenceLevel `json:"level"`
	Kind        string        `json:"kind,omitempty"` // e.g. "yara_match", "taint_path", "http_response"
	Description string        `json:"description,omitempty"`
	File        string        `json:"file,omitempty"`
	Line        int           `json:"line,omitempty"`
	Snippet     string        `json:"snippet,omitempty"`
	// Path is the ordered source-to-sink trace for dataflow evidence
	Path []FlowStep `json:"path,omitempty"`
	// Data holds analyzer-specific structured detail (request/response
	// traces, sandbox observations, OSV records)
	Data map[string]any `json:"data,omitempty"`
}

// FlowStep is one hop in a taint path
type FlowStep struct {
	Kind     string `json:"kind"` // source | transform | sanitizer | unknown | sink
	Symbol   string `json:"symbol,omitempty"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Resolved bool   `json:"resolved"`
}
