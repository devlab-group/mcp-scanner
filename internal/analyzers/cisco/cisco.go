// Package cisco sends a target's declared MCP surface to Cisco AI Defense for inspection
// (prompt injection, data exfiltration setups, unsafe content). Missing credentials produce a
// visible skip, while provider failures remain errors rather than clean results. The request
// shape was written from public documentation without a live credential; verify it against the
// current API before depending on this integration.
package cisco

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/httpx"
	"github.com/revinand/mcp-scanner/internal/llm"
	"github.com/revinand/mcp-scanner/internal/mcp/snapshot"
	"github.com/revinand/mcp-scanner/internal/mcp/surface"
	"github.com/revinand/mcp-scanner/internal/source"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func init() { analyzer.Register(&Analyzer{}) }

const (
	name             = "cisco"
	defaultEndpoint  = "https://api.us.security.cisco.com/ai-defense/v1"
	defaultAPIKeyEnv = "CISCO_AI_DEFENSE_API_KEY"
	defaultTimeout   = 30 * time.Second
	surfaceBudget    = 40000
)

// Analyzer is the "cisco" analyzer
type Analyzer struct{}

func (a *Analyzer) Name() string { return name }

func (a *Analyzer) AppliesTo(kind model.TargetKind) bool {
	switch kind {
	case model.TargetRemote, model.TargetStdio, model.TargetStatic, model.TargetSource, model.TargetPackage:
		return true
	}
	return false
}

func (a *Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name:                name,
		Purpose:             "Submits declared tool/prompt/resource text to Cisco AI Defense for GenAI-focused inspection (prompt injection, unsafe content, data exfiltration setups).",
		Threats:             []string{"prompt_injection", "unsafe_content", "data_exfiltration"},
		Evidence:            []model.EvidenceLevel{model.EvidenceHeuristic},
		Active:              false,
		Limitations:         []string{"third-party classifier: quality and coverage depend on Cisco's model, not this scanner", "skipped entirely when no API key is configured"},
		RequiresNetwork:     true,
		RequiresCredentials: true,
	}
}

type settings struct {
	endpoint              string
	apiKeyEnv             string
	timeout               time.Duration
	allowInsecureEndpoint bool
}

func settingsFrom(ac *analyzer.AnalysisContext) settings {
	s := settings{endpoint: defaultEndpoint, apiKeyEnv: defaultAPIKeyEnv, timeout: defaultTimeout}
	if v, ok := ac.Option(name, "endpoint"); ok {
		if str, ok := v.(string); ok && str != "" {
			s.endpoint = str
		}
	}
	if v, ok := ac.Option(name, "api_key_env"); ok {
		if str, ok := v.(string); ok && str != "" {
			s.apiKeyEnv = str
		}
	}
	if v, ok := ac.Option(name, "timeout"); ok {
		if d, ok := v.(time.Duration); ok && d > 0 {
			s.timeout = d
		}
	}
	if v, ok := ac.Option(name, "allow_insecure_endpoint"); ok {
		if b, ok := v.(bool); ok {
			s.allowInsecureEndpoint = b
		}
	}
	return s
}

type classification struct {
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

type inspectResponse struct {
	Verdict         string           `json:"verdict"` // "safe" | "unsafe"
	Classifications []classification `json:"classifications"`
}

// Analyze submits the declared surface for inspection. It never sends the
// scanned server anything back and never gives it a way to act: this is a
// one-shot text classification call.
func (a *Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	if ac.Snapshot == nil || ac.Snapshot.CapabilityCount() == 0 {
		return model.Skipped(name, "no declared MCP surface to submit")
	}
	s := settingsFrom(ac)
	key := config.Secret(s.apiKeyEnv)
	if key == "" {
		return model.Skipped(name, fmt.Sprintf("no Cisco AI Defense API key configured (set %s)", s.apiKeyEnv))
	}

	surface, included, skipped := buildSurface(ac.Snapshot, surfaceBudget)
	if included == 0 {
		return model.Skipped(name, "declared surface exceeded the inspection budget before anything could be included")
	}

	resp, err := inspect(ctx, s, key, surface, target.Describe())
	if err != nil {
		return model.Errorf(name, llm.AnalyzerErrorKind(err), "Cisco AI Defense request failed: %v", err)
	}

	res := model.AnalyzerResult{
		Analyzer: name,
		Status:   model.AnalyzerCompleted,
		Required: true,
		Coverage: model.Coverage{
			CapabilitiesDiscovered: ac.Snapshot.CapabilityCount(),
			CapabilitiesAnalyzed:   included,
			CapabilitiesSkipped:    skipped,
		},
	}
	if skipped > 0 {
		// The inspection budget is the scanner protecting its own request
		// size, not an explanation of why the excluded items are safe - it
		// belongs in LimitsHit, which Coverage.Gaps always reports, not
		// SkipReasons, which a balanced discovered/analyzed/skipped count
		// can satisfy and so hide the very truncation it should flag
		res.Coverage.LimitsHit = []string{fmt.Sprintf("%d declared item(s) did not fit the %d-character inspection budget and were excluded", skipped, surfaceBudget)}
	}

	// ac.Snapshot.CapabilityCount only counts what reached the snapshot;
	// this folds in what discovery itself stopped short of (a paged tool
	// list, a repeated cursor), which the inspection-budget accounting above
	// cannot see
	res.Coverage = snapshot.FoldCapabilityCoverage(ac.Snapshot, res.Coverage)

	if target.Kind == model.TargetSource || target.Kind == model.TargetPackage {
		// This analyzer only ever reports capability counts; on a source or
		// package target, the file-level walk that read the tree in the
		// first place recorded its own limits and failures separately, and
		// they belong in this result too - otherwise a scan that excludes
		// the source analyzer reports a clean pass over a directory whose
		// file-level gaps nobody in the run surfaced
		res.Coverage = source.FoldWalkCoverage(ac.Artifacts, res.Coverage)
	}

	for _, c := range resp.Classifications {
		res.Findings = append(res.Findings, toFinding(c))
	}
	return res
}

func toFinding(c classification) model.Finding {
	category := c.Category
	if category == "" {
		category = "unsafe_content"
	}
	sev, err := model.ParseSeverity(c.Severity)
	if err != nil {
		sev = model.SeverityMedium
	}
	conf := c.Confidence
	if conf <= 0 || conf > 1 {
		conf = 0.5
	}
	return model.Finding{
		RuleID:        "cisco." + category,
		Category:      category,
		Title:         "Cisco AI Defense: " + category,
		Severity:      sev,
		Confidence:    conf,
		EvidenceLevel: model.EvidenceHeuristic,
		Description:   c.Description,
		Analyzer:      name,
		Evidence: []model.Evidence{{
			Level:       model.EvidenceHeuristic,
			Kind:        "cisco_ai_defense_classification",
			Description: c.Description,
			Data:        map[string]any{"provider": "cisco_ai_defense"},
		}},
	}
}

func inspect(ctx context.Context, s settings, key, surface, targetName string) (*inspectResponse, error) {
	body, err := json.Marshal(map[string]any{
		"content":  surface,
		"metadata": map[string]string{"source": "mcp-scanner", "target": targetName},
	})
	if err != nil {
		return nil, &llm.Error{Provider: "cisco", Kind: llm.ErrProvider, Message: "encode request: " + err.Error()}
	}

	target := strings.TrimSuffix(s.endpoint, "/") + "/inspect"

	// The endpoint is a value the operator configured deliberately - unlike a registry or OSV
	// fetch, it may legitimately point at a private network (a self-hosted or internal Cisco AI
	// Defense deployment), so private networks are allowed here explicitly and only for this
	// client, not by default across the package
	policy := httpx.Policy{AllowPrivateNetworks: true, AllowedSchemes: httpx.EndpointSchemes(s.allowInsecureEndpoint)}
	if err := policy.CheckURL(target); err != nil {
		return nil, &llm.Error{Provider: "cisco", Kind: llm.ErrProvider, Message: "configured endpoint rejected: " + err.Error()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, &llm.Error{Provider: "cisco", Kind: llm.ErrProvider, Message: "build request: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cisco-AI-Defense-API-Key", key)

	client := policy.Client(s.timeout)
	raw, err := llm.Do(ctx, client, req, "cisco")
	if err != nil {
		return nil, err
	}

	var parsed inspectResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, &llm.Error{Provider: "cisco", Kind: llm.ErrMalformed, Message: "could not parse inspect response"}
	}
	return &parsed, nil
}

// buildSurface renders the declared MCP surface as plain text for a text classifier
// via internal/mcp/surface, stopping once budget characters have been used
func buildSurface(snap *model.Snapshot, budget int) (text string, included, skipped int) {
	return surface.Build(snap, budget, surface.Formatters{
		Instructions: func(instructions string) string {
			return fmt.Sprintf("[server instructions]\n%s\n\n", instructions)
		},
		Tool: func(t model.ToolInfo) string {
			entry := fmt.Sprintf("[tool %q]\n%s\ninput_schema: %s\n", t.Name, t.Description, surface.CompactJSON(t.InputSchema))
			return entry + surface.ToolExtras(t) + "\n"
		},
		Prompt: func(p model.PromptInfo) string {
			entry := fmt.Sprintf("[prompt %q]\n%s\n", p.Name, p.Description)
			entry += surface.PromptArguments(p.Arguments)
			if p.Text != "" {
				entry += p.Text + "\n"
			}
			return entry + "\n"
		},
		Resource: func(r model.ResourceInfo) string {
			name := r.Name
			if name == "" {
				name = r.URI
			}
			entry := fmt.Sprintf("[resource %q]\n%s\n", name, r.Description)
			entry += surface.ResourceIdentity(r)
			if r.Content != "" {
				entry += r.Content + "\n"
			}
			return entry + "\n"
		},
		Template: func(t model.ResourceInfo) string {
			name := t.Name
			if name == "" {
				name = t.URITemplate
			}
			entry := fmt.Sprintf("[resource template %q]\n%s\n", name, t.Description)
			return entry + surface.ResourceIdentity(t) + "\n"
		},
	})
}

var (
	_ analyzer.Applicable = (*Analyzer)(nil)
	_ analyzer.Describer  = (*Analyzer)(nil)
	_ analyzer.Analyzer   = (*Analyzer)(nil)
)
