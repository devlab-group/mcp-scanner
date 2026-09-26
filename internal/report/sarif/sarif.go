// Package sarif writes a model.ScanResult as SARIF 2.1.0
// (https://docs.oasis-open.org/sarif/sarif/v2.1.0/), the format GitHub code
// scanning and most CI security dashboards consume
package sarif

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/revinand/mcp-scanner/internal/report"
	"github.com/revinand/mcp-scanner/pkg/model"
)

const schemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
const version = "2.1.0"
const toolName = "mcp-scanner"

type document struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool        tool         `json:"tool"`
	Results     []result     `json:"results"`
	Invocations []invocation `json:"invocations,omitempty"`
	Properties  *runProps    `json:"properties,omitempty"`
}

// runProps carries the scan status and verdict verbatim in the run's property
// bag. executionSuccessful is one bit and cannot say whether a run ended
// ERROR, PARTIAL or SKIPPED, nor whether a successful run came back SAFE or
// UNSAFE; a consumer that gates on those reads them here instead of parsing
// notification text
type runProps struct {
	Status  model.ScanStatus `json:"mcpScannerStatus,omitempty"`
	Verdict model.Verdict    `json:"mcpScannerVerdict,omitempty"`
}

// invocation says whether the scan itself ran, and carries the scan-level notes that are
// not about any one finding - the verdict reasons and the warnings - so they have somewhere
// to go without a result to attach to
type invocation struct {
	ExecutionSuccessful        bool           `json:"executionSuccessful"`
	ToolExecutionNotifications []notification `json:"toolExecutionNotifications,omitempty"`
}

type notification struct {
	Message textBlock `json:"message"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
	Version        string `json:"version,omitempty"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name,omitempty"`
	ShortDescription textBlock `json:"shortDescription"`
	FullDescription  textBlock `json:"fullDescription"`
	Help             textBlock `json:"help"`
	Properties       ruleProps `json:"properties"`
}

type textBlock struct {
	Text string `json:"text"`
}

type ruleProps struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             textBlock         `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          ruleProps         `json:"properties"`
	Suppressions        []suppression     `json:"suppressions,omitempty"`
}

// suppression carries a baselined finding's state into SARIF instead of
// dropping the result, which would hide the evidence a baseline is
// supposed to keep. kind is "external": the suppression came from a
// baseline file outside the analysis, not from an annotation in the
// scanned source, which is what SARIF's "inSource" kind means
type suppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification,omitempty"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           *region          `json:"region,omitempty"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
}

// Write serializes result as SARIF 2.1.0 with a single run. Every rule referenced by a
// result is declared once in driver.rules; each result carries a level derived from the
// finding's severity plus a security-severity score, and a location when the finding names
// a file.
func Write(w io.Writer, res *model.ScanResult) error {
	doc := document{Schema: schemaURI, Version: version, Runs: []run{buildRun(res)}}
	return encode(w, doc)
}

// WriteMany serializes results as one SARIF document with one run per
// result - that is what SARIF's runs array is for, and what a command that
// scans more than one target (known-configs --run) needs so every target
// ends up in the one report file instead of one truncating the last
func WriteMany(w io.Writer, results []*model.ScanResult) error {
	doc := document{Schema: schemaURI, Version: version, Runs: make([]run, 0, len(results))}
	for _, res := range results {
		doc.Runs = append(doc.Runs, buildRun(res))
	}
	return encode(w, doc)
}

func encode(w io.Writer, doc document) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// ruleIDFor is the id one finding contributes to the SARIF rules table. A finding that
// failed Finding.Validate() is kept and suppressed rather than dropped, and such a finding
// can carry an empty RuleID; SARIF's reportingDescriptor requires an id, and `"id": ""` is
// not one, so those findings share a fixed id instead.
func ruleIDFor(f model.Finding) string {
	if f.RuleID == "" {
		return "mcp-scanner.invalid-finding"
	}
	return report.Sanitize(f.RuleID)
}

// buildRun turns one scan result into one SARIF run
func buildRun(res *model.ScanResult) run {
	// Both arrays are initialized rather than left nil: SARIF declares
	// run.results and driver.rules as arrays, and a scan with nothing to
	// report was serializing them as null, which is not an array
	rn := run{
		Tool: tool{Driver: driver{
			Name:           toolName,
			InformationURI: "https://github.com/revinand/mcp-scanner",
			Version:        res.ScannerVersion,
			Rules:          []rule{},
		}},
		Results: []result{},
	}

	ruleIndex := map[string]int{}
	for _, f := range res.Findings {
		id := ruleIDFor(f)
		if _, ok := ruleIndex[id]; ok {
			continue
		}
		ruleIndex[id] = len(rn.Tool.Driver.Rules)
		rn.Tool.Driver.Rules = append(rn.Tool.Driver.Rules, rule{
			ID:               id,
			Name:             report.Sanitize(f.Title),
			ShortDescription: textBlock{Text: report.Sanitize(f.Title)},
			FullDescription:  textBlock{Text: report.SanitizeBlock(f.Description)},
			Properties:       ruleProps{SecuritySeverity: securityScore(f.Severity), Tags: []string{report.Sanitize(f.Category)}},
		})
	}

	for _, f := range res.Findings {
		id := ruleIDFor(f)
		sr := result{
			RuleID:     id,
			RuleIndex:  ruleIndex[id],
			Level:      levelFor(f.Severity),
			Message:    textBlock{Text: report.SanitizeBlock(f.Description)},
			Properties: ruleProps{SecuritySeverity: securityScore(f.Severity)},
		}
		if f.ID != "" {
			// f.ID is the scanner's hash of the target scope and finding identity, not text echoed
			// from the target, so it is safe to preserve verbatim
			sr.PartialFingerprints = map[string]string{"mcpScannerFindingId": f.ID}
		}
		if f.File != "" {
			loc := physicalLocation{ArtifactLocation: artifactLocation{URI: report.Sanitize(f.File)}}
			if f.Line > 0 {
				loc.Region = &region{StartLine: f.Line}
			}
			sr.Locations = []location{{PhysicalLocation: loc}}
		}
		if f.Suppressed {
			// Without this a baselined finding reappears in SARIF as a full-
			// severity live alert: GitHub code scanning has no other way to
			// know a finding it already saw was accepted, which is the one
			// consumer whose whole purpose is holding a queue of open alerts
			sr.Suppressions = []suppression{{
				Kind:          "external",
				Status:        "accepted",
				Justification: report.SanitizeBlock(f.SuppressionReason),
			}}
		}
		rn.Results = append(rn.Results, sr)
	}

	// The invocation is not optional: a scan that reached nothing produces
	// no results, and without it that document is indistinguishable from a
	// clean run. executionSuccessful tracks the one field that decides
	// whether the analysis ran, and the reasons a required analyzer failed
	// live in res.VerdictReasons, not in res.Warnings
	notes := make([]notification, 0, len(res.VerdictReasons)+len(res.Warnings))
	for _, reason := range res.VerdictReasons {
		notes = append(notes, notification{Message: textBlock{Text: report.SanitizeBlock(reason)}})
	}
	for _, warning := range res.Warnings {
		notes = append(notes, notification{Message: textBlock{Text: report.SanitizeBlock(warning)}})
	}
	rn.Invocations = []invocation{{
		ExecutionSuccessful:        res.Status == model.StatusCompleted,
		ToolExecutionNotifications: notes,
	}}
	if res.Status != "" || res.Verdict != "" {
		rn.Properties = &runProps{Status: res.Status, Verdict: res.Verdict}
	}
	return rn
}

// levelFor maps our severity to SARIF's level vocabulary (error, warning,
// note, none)
func levelFor(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	case model.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// securityScore maps our severity to the 0-10 security-severity property
// GitHub code scanning and similar dashboards use to rank alerts
func securityScore(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical:
		return "9.5"
	case model.SeverityHigh:
		return "7.5"
	case model.SeverityMedium:
		return "5.0"
	case model.SeverityLow:
		return "3.0"
	default:
		return fmt.Sprintf("%.1f", 0.0)
	}
}
