// Package iac reads the infrastructure templates a repository ships for deploying its MCP server
// (Bicep, ARM JSON, Terraform) and reports database and administrator secrets that the template
// fixes: a password written as a literal, a parameter or variable whose default is one, or a
// password computed with a deterministic hash (uniqueString, guid) from deployment values. Each
// finding is weighed by what the same templates say about network access. Nothing is deployed
// and no network request is made.
package iac

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/source"
	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
	"github.com/devlab-group/mcp-scanner/pkg/model"
)

const name = "iac"

// Rule IDs
const (
	RuleHardcodedSecret   = "iac.hardcoded_secret"
	RulePredictableSecret = "iac.predictable_secret"
)

// limits bound the walk over a hostile tree
const (
	maxFiles    = 2000
	maxFileSize = 512 << 10
	maxDepth    = 24
)

func init() { analyzer.Register(&Analyzer{}) }

// Analyzer implements analyzer.Analyzer for source and package targets
type Analyzer struct{}

var (
	_ analyzer.Analyzer   = (*Analyzer)(nil)
	_ analyzer.Applicable = (*Analyzer)(nil)
	_ analyzer.Describer  = (*Analyzer)(nil)
)

func (*Analyzer) Name() string { return name }

func (*Analyzer) AppliesTo(kind model.TargetKind) bool {
	return kind == model.TargetSource || kind == model.TargetPackage
}

func (*Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name:    name,
		Purpose: "Reads the Bicep, ARM and Terraform templates shipped with a server and reports administrator and database passwords the template fixes: a literal, a default, or a deterministic hash of deployment values.",
		Threats: []string{
			"a database admin password written in the template, which every deployment that keeps the default shares with everyone who can read the repository",
			"a password computed with uniqueString or guid from a value that also names public resources, so anyone who sees a host name can compute it",
		},
		Evidence: []model.EvidenceLevel{model.EvidenceStatic},
		Active:   false,
		Limitations: []string{
			"Bicep and Terraform are read line by line, not parsed: a value split over several lines, built in another module, or set by a loop is not followed",
			"a parameter is taken as supplied when a parameters file or a module call names it; a default overridden by other means (a pipeline variable, the azd prompt) is still reported",
			"network access is read only from firewall rules, public-access flags and delegated subnets in the same templates; network security groups, private endpoints set elsewhere and policies are not read",
			"Pulumi, CDK, CloudFormation, Kubernetes and Compose files are not read",
		},
	}
}

// assign is one value a .tfvars or parameters file gives a variable
type assign struct {
	expr, file string
	line       int
}

// set is every template in the tree, read together: modules and variables live in other files
type set struct {
	bicep      []*bicepFile
	tf         []*tfFile
	arm        []*armFile
	tfVars     map[string]tfVariable
	tfLocals   map[string]bicepDecl
	tfAssigned map[string]assign
	// provided are parameters a parameters file or a module call sets, so their defaults are
	// not what a deployment uses
	provided map[string]bool
	// paramFileSecrets are literal secrets written in parameters files
	paramFileSecrets []prop
	raw              map[string]string
}

func (*Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	started := time.Now().UTC()
	var acRoot string
	if ac != nil {
		acRoot = ac.Root
	}
	root, err := source.ResolveRoot(target.Path, acRoot)
	if err != nil {
		return model.Errorf(name, "config", "%v", err)
	}
	if root == "" {
		return model.Errorf(name, "config", "no source path to scan")
	}
	files, cov, err := walk(ctx, root)
	if err != nil {
		return model.Errorf(name, "internal", "listing templates: %v", err)
	}
	if len(files) == 0 && cov.FilesFailed == 0 {
		res := model.Skipped(name, "the tree has no Bicep, ARM or Terraform templates")
		res.StartedAt, res.FinishedAt = started, time.Now().UTC()
		return res
	}
	s := build(files)
	findings := s.findings()
	model.SortFindings(findings)
	status := model.AnalyzerCompleted
	if ctx.Err() != nil {
		status = model.AnalyzerPartial
	}
	res := model.AnalyzerResult{
		Analyzer:  name,
		Status:    status,
		Required:  true,
		Coverage:  cov,
		Findings:  findings,
		StartedAt: started,
	}
	res.FinishedAt = time.Now().UTC()
	res.Duration = res.FinishedAt.Sub(started)
	return res
}

// skipDirs are directories that hold other people's code or build output
var skipDirs = map[string]bool{"node_modules": true, "vendor": true, ".venv": true, "venv": true, ".git": true, ".terraform": true, "__pycache__": true,
	// test inputs: a scanner's own fixtures are often vulnerable on purpose
	"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true, "fixtures": true, "fixture": true,
	"test-fixtures": true, "test_fixtures": true, "testdata": true, "test_data": true}

// walk lists the templates under root, read through os.Root so a symlink cannot leave it
func walk(ctx context.Context, root string) (map[string]string, model.Coverage, error) {
	var cov model.Coverage
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, cov, err
	}
	defer r.Close()
	files := map[string]string{}
	err = fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return fs.SkipAll
		}
		if d.IsDir() {
			if p != "." && (skipDirs[d.Name()] || strings.Count(p, "/") >= maxDepth) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !templateName(p) {
			return nil
		}
		if len(files) >= maxFiles {
			if lim := fmt.Sprintf("only the first %d template files were read", maxFiles); !slices.Contains(cov.LimitsHit, lim) {
				cov.LimitsHit = append(cov.LimitsHit, lim)
			}
			return fs.SkipAll
		}
		fh, err := r.Open(p)
		if err != nil {
			cov.FilesFailed++
			return nil
		}
		b, err := io.ReadAll(io.LimitReader(fh, maxFileSize+1))
		fh.Close()
		if err != nil {
			cov.FilesFailed++
			return nil
		}
		if strings.HasSuffix(p, ".json") && !isARM(string(b)) && !isARMParams(string(b)) {
			return nil
		}
		cov.FilesDiscovered++
		if len(b) > maxFileSize {
			cov.FilesSkipped++
			cov.AddSkipReason(fmt.Sprintf("template larger than %d KiB", maxFileSize>>10))
			return nil
		}
		cov.FilesParsed++
		files[p] = string(b)
		return nil
	})
	return files, cov, err
}

func templateName(p string) bool {
	return strings.HasSuffix(p, ".bicep") || strings.HasSuffix(p, ".bicepparam") || strings.HasSuffix(p, ".tf") ||
		strings.HasSuffix(p, ".tfvars") || strings.HasSuffix(p, ".json") && !strings.Contains(p, "package") && !strings.Contains(p, "tsconfig")
}

func isARMParams(src string) bool {
	return strings.Contains(src, "schema.management.azure.com/schemas/") && strings.Contains(src, "deploymentParameters.json")
}

var bicepparamLine = regexp.MustCompile(`^param\s+([A-Za-z_]\w*)\s*=\s*(.+)$`)

func build(files map[string]string) *set {
	s := &set{tfVars: map[string]tfVariable{}, tfLocals: map[string]bicepDecl{}, tfAssigned: map[string]assign{}, provided: map[string]bool{}, raw: files}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		src := files[p]
		switch {
		case strings.HasSuffix(p, ".bicep"):
			f := parseBicep(p, src)
			s.bicep = append(s.bicep, f)
			for k := range f.moduleParams {
				s.provided[k] = true
			}
		case strings.HasSuffix(p, ".bicepparam"):
			for i, line := range strings.Split(src, "\n") {
				if m := bicepparamLine.FindStringSubmatch(strings.TrimSpace(stripComment(line, false))); m != nil {
					s.noteParamValue(p, i+1, m[1], strings.TrimSpace(m[2]), m[2])
				}
			}
		case strings.HasSuffix(p, ".tf"):
			f := parseTerraform(p, src, false)
			s.tf = append(s.tf, f)
			for k, v := range f.vars {
				s.tfVars[k] = v
			}
			for k, v := range f.locals {
				s.tfLocals[k] = v
			}
		case strings.HasSuffix(p, ".tfvars"):
			f := parseTerraform(p, src, true)
			for k, v := range f.assigned {
				s.tfAssigned[k] = assign{expr: v.expr, file: p, line: v.line}
			}
		case strings.HasSuffix(p, ".json") && isARM(src):
			if f := parseARM(p, src); f != nil {
				s.arm = append(s.arm, f)
			}
		case strings.HasSuffix(p, ".json") && isARMParams(src):
			s.readParamsFile(p, src)
		}
	}
	return s
}

// readParamsFile notes every parameter an ARM/azd parameters file sets
func (s *set) readParamsFile(p, src string) {
	var doc struct {
		Parameters map[string]struct {
			Value any `json:"value"`
		} `json:"parameters"`
	}
	if json.Unmarshal([]byte(src), &doc) != nil {
		return
	}
	for k, v := range doc.Parameters {
		str, _ := v.Value.(string)
		line := 1
		if i := strings.Index(src, `"`+k+`"`); i >= 0 {
			line = strings.Count(src[:i], "\n") + 1
		}
		s.noteParamValue(p, line, k, `'`+str+`'`, str)
	}
}

// noteParamValue records that a parameter is set outside its template, and a literal secret if
// the parameters file itself writes one
func (s *set) noteParamValue(file string, line int, param, expr, value string) {
	s.provided[param] = true
	v := strings.Trim(strings.TrimSpace(value), `'"`)
	if secretKey(param) && v != "" && !strings.Contains(v, "${") && !strings.Contains(v, "getSecret") && !strings.HasPrefix(v, "[") &&
		!strings.Contains(v, "readEnvironmentVariable") && !strings.Contains(v, "az.getSecret") {
		s.paramFileSecrets = append(s.paramFileSecrets, prop{file: file, key: param, expr: expr, line: line})
	}
}

// secretUse is one classified secret
type secretUse struct {
	prop
	val val
}

func (s *set) uses() []secretUse {
	var out []secretUse
	for _, f := range s.bicep {
		for _, p := range f.props {
			out = append(out, secretUse{p, s.bicepValue(f, p.expr, 0)})
		}
	}
	for _, f := range s.tf {
		for _, p := range f.props {
			out = append(out, secretUse{p, s.tfValue(f, p.expr, 0)})
		}
	}
	for _, f := range s.arm {
		for _, p := range f.props {
			out = append(out, secretUse{p, s.armValue(f, p.expr, 0)})
		}
	}
	for _, p := range s.paramFileSecrets {
		out = append(out, secretUse{p, val{kind: kindLiteral, detail: "a literal in the parameters file"}})
	}
	for name, a := range s.tfAssigned {
		if tfvarsSecretName(name) {
			v := s.tfValue(nil, a.expr, 0)
			if v.kind == kindLiteral {
				out = append(out, secretUse{prop{file: a.file, key: name, expr: a.expr, line: a.line}, v})
			}
		}
	}
	return out
}

// exposure is what the templates say about who can reach the secured resources
type exposure struct {
	open, private string
	file          string
	line          int
}

var (
	startIP     = regexp.MustCompile(`(?i)["']?start_?ip_?address["']?\s*[:=]\s*["']([0-9.]+)["']`)
	endIP       = regexp.MustCompile(`(?i)["']?end_?ip_?address["']?\s*[:=]\s*["']([0-9.]+)["']`)
	publicTrue  = regexp.MustCompile(`(?i)\bpublicly_accessible\s*=\s*true`)
	privateFlag = regexp.MustCompile(`(?i)["']?publicNetworkAccess["']?\s*:\s*["']Disabled["']|public_network_access_enabled\s*=\s*false|publicly_accessible\s*=\s*false|delegated_?subnet_?(resource_?)?id`)
)

func (s *set) exposure() exposure {
	var e exposure
	paths := make([]string, 0, len(s.raw))
	for p := range s.raw {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		src := s.raw[p]
		starts, ends := startIP.FindAllStringSubmatchIndex(src, -1), endIP.FindAllStringSubmatchIndex(src, -1)
		for _, st := range starts {
			for _, en := range ends {
				if en[0] < st[0] || en[0]-st[1] > 400 {
					continue
				}
				a, b := src[st[2]:st[3]], src[en[2]:en[3]]
				line := strings.Count(src[:st[0]], "\n") + 1
				switch {
				case a == "0.0.0.0" && b == "255.255.255.255" && e.open == "":
					e.open, e.file, e.line = "a firewall rule admits every IPv4 address (0.0.0.0 - 255.255.255.255)", p, line
				case a == "0.0.0.0" && b == "0.0.0.0" && e.open == "":
					e.open, e.file, e.line = "a firewall rule admits all Azure addresses (0.0.0.0 - 0.0.0.0), including other customers' subscriptions", p, line
				}
				break
			}
		}
		if loc := publicTrue.FindStringIndex(src); loc != nil && e.open == "" {
			e.open, e.file, e.line = "the database instance is publicly accessible", p, strings.Count(src[:loc[0]], "\n")+1
		}
		if loc := privateFlag.FindStringIndex(src); loc != nil && e.private == "" {
			e.private = fmt.Sprintf("public network access is off (%s:%d)", p, strings.Count(src[:loc[0]], "\n")+1)
		}
	}
	return e
}

// names are every resource name expression in the templates
func (s *set) names() []string {
	var out []string
	for _, f := range s.bicep {
		out = append(out, f.names...)
	}
	for _, f := range s.tf {
		out = append(out, f.names...)
	}
	for _, f := range s.arm {
		out = append(out, f.names...)
	}
	return out
}

// publicInput returns an input of a predictable secret that also appears in a resource name, and
// so in a host name anyone can see
func (s *set) publicInput(inputs []string) (string, string) {
	for _, in := range inputs {
		pat := regexp.MustCompile(`\$\{\s*` + regexp.QuoteMeta(in) + `\s*\}|variables\(\s*'` + regexp.QuoteMeta(in) + `'\s*\)|parameters\(\s*'` + regexp.QuoteMeta(in) + `'\s*\)`)
		for _, n := range s.names() {
			if pat.MatchString(n) {
				return in, n
			}
		}
	}
	return "", ""
}

func (s *set) findings() []model.Finding {
	ex := s.exposure()
	var out []model.Finding
	seen := map[string]bool{}
	for _, u := range s.uses() {
		key := u.file + fmt.Sprint(u.line)
		if seen[key] {
			continue
		}
		switch u.val.kind {
		case kindLiteral:
			seen[key] = true
			out = append(out, s.hardcoded(u, ex))
		case kindPredictable:
			seen[key] = true
			out = append(out, s.predictable(u, ex))
		}
	}
	return out
}

func reachText(ex exposure) string {
	switch {
	case ex.open != "":
		return fmt.Sprintf(" The templates open the network: %s (%s:%d).", ex.open, ex.file, ex.line)
	case ex.private != "":
		return " The templates keep the server private: " + ex.private + "."
	}
	return " The templates do not say whether the server is reachable from outside."
}

func (s *set) hardcoded(u secretUse, ex exposure) model.Finding {
	where := u.val.detail
	if u.val.via != "" {
		where += " (" + u.val.via + ", " + u.val.viaFile + ":" + fmt.Sprint(u.val.viaLine) + ")"
	}
	sev, triage, reason := model.SeverityHigh, model.TriagePotential, "the password is published with the template and the network is open to it"
	if ex.open == "" {
		sev, triage = model.SeverityMedium, model.TriageNeedsReview
		reason = "the password is published with the template; who can reach the server decides how much that matters"
	}
	desc := fmt.Sprintf("%s (%s:%d) is %s. Every deployment that keeps it uses a password anyone who reads the repository knows.%s", u.key, u.file, u.line, where, reachText(ex))
	return finding(RuleHardcodedSecret, "hardcoded_secret", "Database or administrator password is fixed in the deployment template", sev, triage, reason, desc,
		"Make the password a @secure() parameter with no default (or newGuid()), a Terraform random_password, or a Key Vault reference; prefer Entra ID or IAM authentication where the service supports it.", u, ex)
}

func (s *set) predictable(u secretUse, ex exposure) model.Finding {
	in, nameExpr := s.publicInput(u.val.inputs)
	sev, triage := model.SeverityMedium, model.TriageNeedsReview
	reason := "the password is a deterministic hash of deployment values; how easily an attacker learns them decides how real the risk is"
	inputs := strings.Join(u.val.inputs, ", ")
	if inputs == "" {
		inputs = "the values hashed"
	}
	desc := fmt.Sprintf("%s (%s:%d) is computed as %s: a deterministic hash, not a random value, so anyone who knows its inputs (%s) can compute the password.", u.key, u.file, u.line, u.val.detail, inputs)
	if in != "" {
		desc += fmt.Sprintf(" The input %s also names public resources (%s), so it is visible in their host names.", in, nameExpr)
		if ex.open != "" {
			sev, triage = model.SeverityHigh, model.TriagePotential
			reason = "the hash input is part of public resource names and the network is open to the server"
		} else {
			reason = "the hash input is part of public resource names; who can reach the server decides how much that matters"
		}
	}
	desc += reachText(ex)
	return finding(RulePredictableSecret, "predictable_secret", "Password is computed from deployment values with a deterministic hash", sev, triage, reason, desc,
		"Generate the password randomly (a @secure() parameter defaulting to newGuid(), random_password, or a Key Vault secret) instead of hashing deployment values; prefer Entra ID or IAM authentication where the service supports it.", u, ex)
}

func finding(rule, category, title string, sev model.Severity, triage model.Triage, reason, desc, fix string, u secretUse, ex exposure) model.Finding {
	ev := []model.Evidence{{Level: model.EvidenceStatic, Kind: "secret_value", Description: u.key + " = " + u.val.detail, File: u.file, Line: u.line}}
	if u.val.viaFile != "" {
		ev = append(ev, model.Evidence{Level: model.EvidenceStatic, Kind: "secret_default", Description: u.val.via, File: u.val.viaFile, Line: u.val.viaLine})
	}
	if ex.open != "" {
		ev = append(ev, model.Evidence{Level: model.EvidenceStatic, Kind: "network_access", Description: ex.open, File: ex.file, Line: ex.line})
	}
	conf := 0.8
	if triage != model.TriagePotential {
		conf = 0.6
	}
	return model.Finding{
		RuleID:        rule,
		Analyzer:      name,
		Category:      category,
		Title:         title,
		Severity:      sev,
		Confidence:    conf,
		EvidenceLevel: model.EvidenceStatic,
		File:          u.file,
		Line:          u.line,
		Description:   desc,
		Remediation:   fix,
		Evidence:      ev,
		Triage:        triage,
		TriageReason:  reason,
	}
}
