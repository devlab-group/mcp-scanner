// Package runtime is the analyzer that actually calls ac.Runtime: it turns a tool's
// declared input schema into fuzz payloads, runs them inside the sandbox with canaries
// planted, and reports only what an observation actually demonstrated
package runtime

import (
	"context"
	"debug/elf"
	"fmt"
	"hash/fnv"
	"path/filepath"
	"strings"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/runtime/canary"
	"github.com/devlab-group/mcp-scanner/internal/runtime/fuzz"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

const name = "runtime"

func init() { analyzer.Register(New()) }

// Analyzer confirms static suspicions by actually running a target's tools
// inside internal/runtime/sandbox
type Analyzer struct {
	// Timeout bounds each sandboxed execution. Zero defers to whatever the configured
	// analyzer.RuntimeExecutor uses as its own default (see internal/app.NewRuntimeExecutor,
	// which sets that from runtime.timeout in configuration) - this analyzer is registered once
	// via init() and shared across every scan a long-lived process runs, so it cannot hold one
	// scan's configured timeout itself.
	Timeout time.Duration
}

// New builds the runtime analyzer
func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return name }

func (a *Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	started := time.Now().UTC()
	finish := func(res model.AnalyzerResult) model.AnalyzerResult {
		res.Analyzer = name
		res.StartedAt = started
		res.FinishedAt = time.Now().UTC()
		res.Duration = res.FinishedAt.Sub(started)
		return res
	}

	// 1. Gating, in the required order, each with its own visible status
	if ac.Runtime == nil {
		return finish(model.Skipped(name, "runtime confirmation is not enabled in this scan's configuration"))
	}
	if err := ac.Runtime.Available(ctx); err != nil {
		return finish(model.Unavailable(name, err.Error()))
	}
	if target.Kind == model.TargetRemote {
		return finish(model.Skipped(name,
			"remote targets are out of scope: even an allowlisted tool call would reach the live server, not a sandbox"))
	}
	switch target.Kind {
	case model.TargetStdio, model.TargetSource, model.TargetPackage:
		// proceed - these are the kinds where a process can be launched
		// under our control
	default:
		return finish(model.Skipped(name, fmt.Sprintf("no sandboxable process for target kind %q", target.Kind)))
	}

	command := target.Command
	if command == "" || !filepath.IsAbs(command) {
		return finish(model.Skipped(name,
			"target has no absolute command to run in the sandbox (source/package targets are only confirmable once something resolves an entrypoint into target.Command)"))
	}
	if reason, ok := interpreterLimitation(command); ok {
		return finish(model.Skipped(name, reason))
	}
	if reason, ok := dynamicLinkLimitation(command); ok {
		return finish(model.Skipped(name, reason))
	}

	candidates := discoverCandidates(ac)
	if len(candidates) == 0 {
		return finish(model.Skipped(name, "no tools available in the prepared snapshot"))
	}

	cset, err := canary.Generate()
	if err != nil {
		return finish(model.Errorf(name, "internal", "generating canaries: %v", err))
	}
	// Payloads assume the tool's file base is one level below the planted home.
	// This is a depth guess because the target layout is unknown.
	canaryFiles := make([]fuzz.CanaryFile, 0, len(cset.Canaries))
	for _, c := range cset.Canaries {
		if c.Path != "" {
			canaryFiles = append(canaryFiles, fuzz.CanaryFile{ID: c.ID, RelPath: c.Path})
		}
	}

	var findings []model.Finding
	// exposed records which tools already produced a canary-exposure
	// finding, so one leaky tool yields one finding rather than one per
	// payload that was running when it leaked
	exposed := map[string]bool{}
	cov := model.Coverage{CapabilitiesDiscovered: len(candidates)}
	var sandboxErr error

candidateLoop:
	for _, c := range candidates {
		if ctx.Err() != nil {
			cov.CapabilitiesSkipped++
			cov.AddSkipReason("scan deadline reached before every candidate could be run")
			continue
		}

		cases := fuzz.Generate(c.tool, seedFor(c.tool.Name), fuzz.Options{CanaryFiles: canaryFiles, CanaryHome: canary.ContainerHome})
		if len(cases) == 0 {
			cov.CapabilitiesSkipped++
			cov.AddSkipReason(fmt.Sprintf("%s: schema had no fuzzable string or numeric properties", c.tool.Name))
			continue
		}

		ran := false
		// incomplete, when set, is why some case for this capability
		// demonstrated nothing: the capability is not fully analyzed even
		// if another case for it ran cleanly
		incomplete := ""
		for _, fc := range cases {
			if ctx.Err() != nil {
				break
			}
			req := analyzer.RuntimeRequest{
				Target:    model.Target{Kind: model.TargetStdio, Command: command, Args: target.Args},
				Tool:      fc.Tool,
				Arguments: fc.Arguments,
				Timeout:   a.timeout(),
				Canaries:  cset.Canaries,
			}
			res := ac.Runtime.Execute(ctx, req)
			if res.Err != nil {
				sandboxErr = fmt.Errorf("running %s (%s payload on %s): %w", c.tool.Name, fc.Payload.Class, fc.Property, res.Err)
				break candidateLoop
			}
			if !res.Started {
				// The executor contract is: a run that did not start says
				// why through Err. One that reports neither is not evidence
				// about the target - it is the executor breaking its own
				// contract, and every other candidate would hit the same
				// thing, so this stops the whole analyzer rather than
				// silently skipping just this one.
				sandboxErr = fmt.Errorf("running %s (%s payload on %s): sandbox executor reported neither Started nor Err",
					c.tool.Name, fc.Payload.Class, fc.Property)
				break candidateLoop
			}
			if res.TimedOut {
				// Hitting the per-run deadline is not an observation: this
				// case demonstrated nothing, so it cannot stand in for a
				// completed run of this capability, even if another case
				// for the same tool ran cleanly
				incomplete = "a fuzz case hit the per-run sandbox deadline without completing, so this capability is not fully analyzed"
				continue
			}
			f := confirm(c.tool.Name, fc, res)
			if f == nil && abnormalExit(res.ExitCode) {
				// The container was killed or crashed rather than the target's own code choosing to exit,
				// and the payload confirmed nothing first - the same as the deadline case: a target that
				// allocates past the memory limit or segfaults on every payload demonstrated nothing and
				// must not be recorded as confirmed
				incomplete = fmt.Sprintf(
					"a fuzz case ended on exit %d - killed or crashed, not a normal process exit - without confirming anything, so this capability is not fully analyzed",
					res.ExitCode)
				continue
			}
			if f == nil && !res.Answered {
				// The process started, but no tools/call reply proves the tool ran. This includes a
				// target that rejects container-inaccessible arguments, prints usage and exits, or
				// answers initialization before crashing on the call.
				incomplete = "a fuzz case ran without a tools/call response, so this capability remains incomplete"
				continue
			}
			ran = true
			if f != nil {
				// An exposure finding says the target hands back canary
				// material; that is one fact about the tool, not one per
				// payload that happened to be running when it did
				if f.RuleID == exposureRuleID {
					if exposed[c.tool.Name] {
						continue
					}
					exposed[c.tool.Name] = true
				}
				findings = append(findings, *f)
			}
		}
		switch {
		case incomplete != "":
			cov.CapabilitiesSkipped++
			cov.AddSkipReason(fmt.Sprintf("%s: %s", c.tool.Name, incomplete))
		case ran:
			cov.CapabilitiesAnalyzed++
		default:
			cov.CapabilitiesSkipped++
			cov.AddSkipReason(fmt.Sprintf("%s: scan deadline reached before it could run", c.tool.Name))
		}
	}

	res := model.AnalyzerResult{Findings: findings, Coverage: cov}

	switch {
	case sandboxErr != nil:
		res.Status = model.AnalyzerFailed
		res.Required = true
		res.Errors = []model.AnalyzerError{{Kind: "internal", Message: sandboxErr.Error(), Fatal: true}}
	case ctx.Err() != nil, cov.CapabilitiesSkipped > 0:
		res.Status = model.AnalyzerPartial
	default:
		res.Status = model.AnalyzerCompleted
	}
	return finish(res)
}

// abnormalExit reports whether a sandboxed run ended some way other than the target's own
// process choosing an exit status: a negative code (the executor never obtained one) or
// 128+signal, how docker reports a container killed from outside - 137 for the SIGKILL the
// --memory cgroup limit sends, 139 for a SIGSEGV crash
func abnormalExit(code int) bool { return code < 0 || code >= 128 }

// timeout is a.Timeout, unmodified. Zero is passed straight through to the
// executor: RuntimeRequest.Timeout <= 0 tells Execute to fall back to its
// own configured default rather than this analyzer silently reasserting one
// of its own and shadowing whatever runtime.timeout configured.
func (a *Analyzer) timeout() time.Duration {
	return a.Timeout
}

// confirm accepts only canary_hit or process, file, network, and DNS observations from this
// payload run. It never reads error text; self-reported MCP-OBS effects must include the payload
// marker so an unrelated observation cannot confirm the case.
func confirm(toolName string, fc fuzz.Case, res analyzer.RuntimeResult) *model.Finding {
	for _, o := range res.Observations {
		if o.Kind != "canary_hit" {
			continue
		}
		// A canary_hit names the canary that fired, and only the payload that aimed at that exact
		// canary may claim it as the effect it predicted
		class := fuzz.Class("")
		if fc.Payload.Canary != "" && fc.Payload.Canary == o.CanaryID {
			class = fc.Payload.Class
		}
		return buildFinding(toolName, fc, class, model.EvidenceConfirmed, "canary_hit", o)
	}
	for _, o := range res.Observations {
		switch o.Kind {
		case "process_exec", "file_read", "file_write", "net_connect", "dns_query":
			if fc.Payload.Marker != "" && strings.Contains(o.Detail, fc.Payload.Marker) {
				return buildFinding(toolName, fc, fc.Payload.Class, model.EvidenceConfirmed, o.Kind, o)
			}
		}
	}
	return nil
}

func buildFinding(toolName string, fc fuzz.Case, class fuzz.Class, level model.EvidenceLevel, obsKind string, o analyzer.Observation) *model.Finding {
	ruleID, category, title, sev := classify(class, obsKind)
	f := model.Finding{
		RuleID:        ruleID,
		Category:      category,
		Title:         title,
		Severity:      sev,
		Confidence:    0.95,
		EvidenceLevel: level,
		Tool:          toolName,
		Analyzer:      name,
		Description: fmt.Sprintf("a %s payload against %q's %q argument produced observation %q: %s",
			fc.Payload.Class, toolName, fc.Property, o.Kind, o.Detail),
		Evidence: []model.Evidence{{
			Level:       level,
			Kind:        "runtime_observation",
			Description: fmt.Sprintf("sandbox observation from a %s payload", fc.Payload.Class),
			Data: map[string]any{
				"tool":          toolName,
				"property":      fc.Property,
				"payload_class": string(fc.Payload.Class),
				"marker":        fc.Payload.Marker,
				"observation":   o,
			},
		}},
	}
	return &f
}

// exposureRuleID is the finding a canary hit produces when no payload
// aimed at that canary
const exposureRuleID = "runtime.canary_exposure_confirmed"

func classify(class fuzz.Class, obsKind string) (ruleID, category, title string, sev model.Severity) {
	switch class {
	case fuzz.ClassCommandInjection, fuzz.ClassShellMetacharacter:
		return "runtime.command_injection_confirmed", "command_injection",
			"Sandboxed execution confirms command injection", model.SeverityCritical
	case fuzz.ClassPathTraversal, fuzz.ClassFileURI:
		return "runtime.path_traversal_confirmed", "path_traversal",
			"Sandboxed execution confirms path traversal", model.SeverityHigh
	case fuzz.ClassTemplateInjection:
		return "runtime.template_injection_confirmed", "template_injection",
			"Sandboxed execution confirms template injection", model.SeverityHigh
	default:
		if obsKind == "canary_hit" {
			return exposureRuleID, "information_disclosure",
				"Sandboxed execution exposed planted canary material", model.SeverityHigh
		}
		return "runtime.effect_confirmed", "input_validation",
			"Sandboxed execution confirms an unsanitized input reaches an observable effect", model.SeverityMedium
	}
}

// interpreterBinaries cannot run in the scratch image because only the named
// executable is staged. Skip them explicitly instead of reporting a clean run.
var interpreterBinaries = map[string]bool{
	"python": true, "python2": true, "python3": true,
	"node": true, "nodejs": true, "npx": true, "npm": true, "pnpm": true, "yarn": true,
	"bun": true, "deno": true, "ts-node": true,
	"ruby": true, "irb": true,
	"perl": true, "php": true, "lua": true,
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true,
	"java": true, "dotnet": true, "Rscript": true,
}

// interpreterVersionPrefixes catches versioned binaries such as python3.11
// or node20 that interpreterBinaries' exact-match lookup would miss
var interpreterVersionPrefixes = []string{"python", "node", "ruby", "php"}

func interpreterLimitation(command string) (string, bool) {
	base := filepath.Base(command)
	lower := strings.ToLower(base)
	interpreter := interpreterBinaries[lower]
	if !interpreter {
		for _, prefix := range interpreterVersionPrefixes {
			if strings.HasPrefix(lower, prefix) && lower != prefix {
				interpreter = true
				break
			}
		}
	}
	if !interpreter {
		return "", false
	}
	return fmt.Sprintf(
		"target command %q is an interpreter; the sandbox stages a single file into an empty base image and cannot supply an interpreter's runtime, standard library, or the script it would load, so this analyzer cannot confirm anything against it",
		command), true
}

// dynamicLinkLimitation generalizes interpreterLimitation from a filename allowlist to the
// property that actually matters: the sandbox's empty scratch image has no dynamic loader
// (no /lib, no ld.so), so a dynamically linked entrypoint fails to start, the same way an
// unlisted interpreter would
func dynamicLinkLimitation(command string) (string, bool) {
	f, err := elf.Open(command)
	if err != nil {
		return fmt.Sprintf(
			"target command %q could not be read as an ELF binary (%v); the sandbox has no way to tell whether it needs a dynamic loader the empty base image does not provide, so this analyzer skips it rather than guess",
			command, err), true
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return fmt.Sprintf(
				"target command %q is dynamically linked; the sandbox stages a single file into an empty base image with no dynamic loader (no /lib, no ld.so) for it to run against, so this analyzer cannot confirm anything against it",
				command), true
		}
	}
	return "", false
}

func seedFor(toolName string) int64 {
	h := fnv.New64a()
	h.Write([]byte(toolName))
	return int64(h.Sum64())
}

func (a *Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name: name,
		Purpose: "Runs a target's tools inside the sandbox with fuzzed arguments and planted canaries, " +
			"and reports only what an observation actually demonstrated - confirmation, not a static guess.",
		Threats: []string{
			"command injection", "path traversal", "server-side template injection",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceConfirmed},
		Active:   true,
		Limitations: []string{
			"never runs against a remote target: a tool call there reaches the live server, not a sandbox",
			"source and package targets are only sandboxed once the target already names an absolute, runnable entrypoint; target preparation does not derive one from a source tree or a downloaded package on its own",
			"reaches only a statically linked or otherwise self-contained executable; the sandbox stages a single file into an empty base image, so an interpreted server (python, node, npx, ruby, a shell script, ...) cannot get its runtime, standard library, or the script it would load, and is skipped with a reason rather than run against a broken environment that would look clean for having observed nothing",
			"a dynamically linked entrypoint is skipped for the same reason as an interpreter: the empty base image has no dynamic loader for it to run against. Detected by reading the ELF program headers for a PT_INTERP segment, not by a filename allowlist, so this covers any dynamically linked native binary, not only the interpreters named above",
			"containers have no network, so the analyzer generates no SSRF payloads and cannot confirm SSRF",
			"a tool that merely reflects its raw argument back (an error message, a log line) is not mistaken for confirmation - only a canary value or a self-reported observation counts, so a target that never demonstrates the effect produces no finding, which is coverage, not a clean result",
			"candidate priority uses keywords in tool names, descriptions and schema properties, not a dataflow trace; the analyzer receives no reusable static finding from another analyzer",
		},
		RequiresDocker: true,
	}
}
