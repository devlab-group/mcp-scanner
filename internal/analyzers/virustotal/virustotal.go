// Package virustotal looks up hashes for a bounded set of files under the scan root. Fixed cache,
// dependency, and VCS directories are excluded so the hash budget reaches first-party code;
// excluding .git also prevents an upload-enabled scan from sending repository history.
package virustotal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/revinand/mcp-scanner/internal/config"
	"github.com/revinand/mcp-scanner/internal/httpx"
	"github.com/revinand/mcp-scanner/internal/llm"
	"github.com/revinand/mcp-scanner/internal/source/language"
	"github.com/revinand/mcp-scanner/pkg/analyzer"
	"github.com/revinand/mcp-scanner/pkg/model"
)

func init() { analyzer.Register(&Analyzer{}) }

const (
	name             = "virustotal"
	defaultAPIKeyEnv = "VIRUSTOTAL_API_KEY"
	defaultBaseURL   = "https://www.virustotal.com/api/v3"
	defaultTimeout   = 30 * time.Second
	defaultMaxFiles  = 50
	// maxUploadBytes matches VirusTotal's standard (non-premium) upload
	// limit; larger files are reported as skipped rather than attempted
	maxUploadBytes = 32 << 20
)

// silentSkipDirs and reportedSkipDirs mirror internal/source/inventory's own lists of the
// same name (see inventory.go's doc comment for why the exclusion is a fixed set of names,
// never a wildcard or anything derived from a file's content)
var silentSkipDirs = map[string]bool{
	".git":          true,
	"__pycache__":   true,
	".mypy_cache":   true,
	".pytest_cache": true,
}

// reportedSkipDirs, unlike silentSkipDirs, holds third-party code - see
// internal/source/inventory's doc comment on the list of the same name.
// Excluding it is a resource decision, not a safety judgement, so every
// hit is recorded in Coverage.LimitsHit (see Analyze) instead of vanishing
// silently.
var reportedSkipDirs = map[string]bool{
	"vendor":       true,
	"node_modules": true,
	".venv":        true,
	"venv":         true,
}

// Analyzer is the "virustotal" analyzer
type Analyzer struct{}

func (a *Analyzer) Name() string { return name }

func (a *Analyzer) AppliesTo(kind model.TargetKind) bool {
	switch kind {
	case model.TargetSource, model.TargetPackage:
		return true
	}
	return false
}

func (a *Analyzer) Describe() analyzer.Description {
	return analyzer.Description{
		Name:                name,
		Purpose:             "Hashes a bounded set of regular files from the scan root with SHA-256 and looks them up in VirusTotal; optionally uploads unknown files when explicitly enabled.",
		Threats:             []string{"known_malware", "known_malicious_package_content"},
		Evidence:            []model.EvidenceLevel{model.EvidenceHeuristic},
		Active:              false,
		Limitations:         []string{"only catches previously-seen malware: a novel payload with no VirusTotal history produces no finding", "checks at most a bounded number of files per scan, source files a language adapter recognizes first; a tree can influence which of its own remaining files fall outside that budget by what they are named, which is why every file left over is recorded as a limit rather than passed over quietly", "skipped entirely when no API key is configured"},
		RequiresNetwork:     true,
		RequiresCredentials: true,
	}
}

type settings struct {
	baseURL               string
	apiKeyEnv             string
	timeout               time.Duration
	maxFiles              int
	allowUpload           bool
	allowInsecureEndpoint bool
}

func settingsFrom(ac *analyzer.AnalysisContext) settings {
	s := settings{baseURL: defaultBaseURL, apiKeyEnv: defaultAPIKeyEnv, timeout: defaultTimeout, maxFiles: defaultMaxFiles}
	if v, ok := ac.Option(name, "base_url"); ok {
		if str, ok := v.(string); ok && str != "" {
			s.baseURL = str
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
	if v, ok := ac.Option(name, "max_files"); ok {
		if n, ok := v.(int); ok && n > 0 {
			s.maxFiles = n
		}
	}
	if v, ok := ac.Option(name, "allow_upload"); ok {
		if b, ok := v.(bool); ok {
			s.allowUpload = b
		}
	}
	if v, ok := ac.Option(name, "allow_insecure_endpoint"); ok {
		if b, ok := v.(bool); ok {
			s.allowInsecureEndpoint = b
		}
	}
	return s
}

// Analyze hashes files under ac.Root and checks each hash against
// VirusTotal. It never runs, opens for write, or otherwise executes any
// scanned file - only reads bytes to hash them.
func (a *Analyzer) Analyze(ctx context.Context, target model.Target, ac *analyzer.AnalysisContext) model.AnalyzerResult {
	if ac.Root == "" {
		return model.Skipped(name, "no filesystem root to hash")
	}
	s := settingsFrom(ac)
	key := config.Secret(s.apiKeyEnv)
	if key == "" {
		return model.Skipped(name, fmt.Sprintf("no VirusTotal API key configured (set %s)", s.apiKeyEnv))
	}
	// s.baseURL is a value the operator configured deliberately - unlike a registry or OSV
	// fetch, it may legitimately point at a private network (a self-hosted
	// VirusTotal-compatible endpoint), so private networks are allowed here explicitly and only
	// for this client, not by default across the package
	policy := httpx.Policy{AllowPrivateNetworks: true, AllowedSchemes: httpx.EndpointSchemes(s.allowInsecureEndpoint)}
	if err := policy.CheckURL(s.baseURL); err != nil {
		return model.Errorf(name, "config", "configured base_url rejected: %v", err)
	}

	// root, not ac.Root by name, is what every file below is opened
	// through: a path resolved via root can't be walked back out by a
	// symlink planted after the fact, and - together with hashing and
	// uploading from the same open handle below - a file that mutates
	// underneath this scan can no longer have something other than what
	// was hashed be the thing that gets uploaded
	root, err := os.OpenRoot(ac.Root)
	if err != nil {
		return model.Errorf(name, "internal", "could not open scan root: %v", err)
	}
	defer root.Close()

	files, excludedDirs, walkErr := listFiles(root)
	if walkErr != nil {
		return model.Errorf(name, "internal", "could not list files under scan root: %v", walkErr)
	}
	if len(files) == 0 && len(excludedDirs) == 0 {
		return model.Skipped(name, "no files found under the scan root")
	}

	toCheck := files
	skippedCount := 0
	if len(toCheck) > s.maxFiles {
		toCheck = files[:s.maxFiles]
		skippedCount = len(files) - s.maxFiles
	}

	client := policy.Client(s.timeout)
	res := model.AnalyzerResult{
		Analyzer: name,
		Status:   model.AnalyzerCompleted,
		Required: true,
		Coverage: model.Coverage{
			FilesDiscovered: len(files),
		},
	}
	if len(excludedDirs) > 0 {
		res.Coverage.LimitsHit = append(res.Coverage.LimitsHit,
			fmt.Sprintf("files under vendored dependency directories were not hashed: %s", strings.Join(excludedDirs, ", ")))
	}
	if skippedCount > 0 {
		// The per-scan file cap is the scanner protecting itself, not an explanation of why the
		// excluded files are safe - it belongs in LimitsHit, which Coverage.Gaps always reports
		res.Coverage.FilesSkipped += skippedCount
		res.Coverage.LimitsHit = append(res.Coverage.LimitsHit,
			fmt.Sprintf("%d file(s) did not fit the per-scan VirusTotal lookup limit (%d files) and were excluded", skippedCount, s.maxFiles))
	}

	for _, rel := range toCheck {
		if ctx.Err() != nil {
			res.Coverage.FilesSkipped += len(toCheck) - res.Coverage.FilesParsed - res.Coverage.FilesFailed
			res.Coverage.SkipReasons = append(res.Coverage.SkipReasons, "scan deadline reached before every file was checked")
			res.Status = model.AnalyzerPartial
			break
		}
		// A closure per entry, not a shared defer, so each file's handle
		// closes at the end of its own iteration rather than piling up
		// until Analyze returns
		func() {
			f, err := root.Open(rel)
			if err != nil {
				res.Coverage.FilesFailed++
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: could not open file: %v", rel, err))
				return
			}
			defer f.Close()

			hash, size, err := sha256Reader(f)
			if err != nil {
				res.Coverage.FilesFailed++
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: could not hash file: %v", rel, err))
				return
			}

			report, err := lookup(ctx, client, s, key, hash)
			switch {
			case err != nil && isNotFound(err):
				res.Coverage.FilesParsed++
				if s.allowUpload && size <= maxUploadBytes {
					// Upload from the handle already hashed above, rewound
					// to the start, rather than opening rel a second time -
					// a second open-by-name is exactly what let a file
					// swapped in between the two opens be the one uploaded
					if _, serr := f.Seek(0, io.SeekStart); serr != nil {
						res.Warnings = append(res.Warnings, fmt.Sprintf("%s: could not rewind file for upload: %v", rel, serr))
						return
					}
					if analysisID, uerr := upload(ctx, client, s, key, rel, f); uerr != nil {
						res.Warnings = append(res.Warnings, fmt.Sprintf("%s: upload failed: %v", rel, uerr))
					} else {
						res.Warnings = append(res.Warnings, fmt.Sprintf("%s: unknown to VirusTotal, submitted for analysis (id=%s); result not available in this scan", rel, analysisID))
					}
				}
			case err != nil:
				res.Coverage.FilesFailed++
				res.Errors = append(res.Errors, model.AnalyzerError{Kind: llm.AnalyzerErrorKind(err), Message: fmt.Sprintf("%s: %v", rel, err), Fatal: false})
			default:
				res.Coverage.FilesParsed++
				if fnd, ok := toFinding(rel, hash, report); ok {
					res.Findings = append(res.Findings, fnd)
				}
			}
		}()
	}

	// A non-fatal per-file error (network hiccup on one hash) should not
	// silently pass as complete coverage: it is exactly the kind of gap
	// Coverage exists to surface
	if res.Coverage.FilesFailed > 0 && len(res.Coverage.SkipReasons) == 0 {
		res.Coverage.SkipReasons = append(res.Coverage.SkipReasons, fmt.Sprintf("%d file(s) failed a VirusTotal lookup", res.Coverage.FilesFailed))
	}

	return res
}

// listFiles walks root.FS(), the same os.Root every later open goes through, so the file
// list and the eventual opens agree on what "under the scan root" means. Claimed source files come
// first deterministically. Only directories in reportedSkipDirs are returned for coverage; silent
// exclusions such as .git are omitted from that list.
func listFiles(root *os.Root) (files []string, excludedDirs []string, err error) {
	var claimed, other []string
	excluded := map[string]bool{}
	walkErr := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == "." {
				return nil
			}
			name := d.Name()
			if silentSkipDirs[name] {
				return fs.SkipDir
			}
			if reportedSkipDirs[name] {
				excluded[name] = true
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if language.ForExt(filepath.Ext(p)) != nil {
			claimed = append(claimed, p)
		} else {
			other = append(other, p)
		}
		return nil
	})
	sort.Strings(claimed)
	sort.Strings(other)
	dirs := slices.Sorted(maps.Keys(excluded))
	return append(claimed, other...), dirs, walkErr
}

func sha256Reader(r io.Reader) (hash string, size int64, err error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type analysisStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
	Undetected int `json:"undetected"`
}

type fileReport struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats analysisStats `json:"last_analysis_stats"`
			Reputation        int           `json:"reputation"`
		} `json:"attributes"`
	} `json:"data"`
}

func lookup(ctx context.Context, client *http.Client, s settings, key, hash string) (*fileReport, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.baseURL, "/")+"/files/"+hash, nil)
	if err != nil {
		return nil, &llm.Error{Provider: "virustotal", Kind: llm.ErrProvider, Message: "build request: " + err.Error()}
	}
	req.Header.Set("x-apikey", key)

	raw, err := llm.Do(ctx, client, req, "virustotal")
	if err != nil {
		return nil, err
	}
	var parsed fileReport
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, &llm.Error{Provider: "virustotal", Kind: llm.ErrMalformed, Message: "could not parse file report"}
	}
	return &parsed, nil
}

// upload sends f - already opened and hashed by the caller, rewound to its
// start - to VirusTotal. It never opens rel itself: a second open by name
// would let a file swapped in between the hash and the upload be the one
// uploaded instead of the one hashed.
func upload(ctx context.Context, client *http.Client, s settings, key, rel string, f io.Reader) (string, error) {
	var body strings.Builder
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", filepath.Base(rel))
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(part, f); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.baseURL, "/")+"/files", strings.NewReader(body.String()))
	if err != nil {
		return "", &llm.Error{Provider: "virustotal", Kind: llm.ErrProvider, Message: "build upload request: " + err.Error()}
	}
	req.Header.Set("x-apikey", key)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	raw, err := llm.Do(ctx, client, req, "virustotal")
	if err != nil {
		return "", err
	}
	var parsed struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", &llm.Error{Provider: "virustotal", Kind: llm.ErrMalformed, Message: "could not parse upload response"}
	}
	return parsed.Data.ID, nil
}

func isNotFound(err error) bool {
	le, ok := err.(*llm.Error)
	return ok && le.StatusCode == http.StatusNotFound
}

func toFinding(rel, hash string, report *fileReport) (model.Finding, bool) {
	stats := report.Data.Attributes.LastAnalysisStats
	if stats.Malicious == 0 && stats.Suspicious == 0 {
		return model.Finding{}, false
	}
	sev := model.SeverityMedium
	if stats.Malicious >= 5 {
		sev = model.SeverityCritical
	} else if stats.Malicious >= 1 {
		sev = model.SeverityHigh
	}
	total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected
	conf := 0.5
	if total > 0 {
		conf = float64(stats.Malicious+stats.Suspicious) / float64(total)
		if conf > 1 {
			conf = 1
		} else if conf < 0.1 {
			conf = 0.1
		}
	}
	return model.Finding{
		RuleID:   "virustotal.known_malicious_file",
		Category: "known_malicious_file",
		// rel is a path under the scanned target - target-controlled text -
		// so it is quoted rather than interpolated raw
		Title:         fmt.Sprintf("%q is flagged by %d VirusTotal vendor(s)", rel, stats.Malicious+stats.Suspicious),
		Severity:      sev,
		Confidence:    conf,
		EvidenceLevel: model.EvidenceHeuristic,
		File:          rel,
		Description:   fmt.Sprintf("SHA-256 %s matched a known file with %d malicious and %d suspicious vendor detections on VirusTotal.", hash, stats.Malicious, stats.Suspicious),
		Analyzer:      name,
		Evidence: []model.Evidence{{
			Level:       model.EvidenceHeuristic,
			Kind:        "virustotal_hash_lookup",
			Description: fmt.Sprintf("%d malicious, %d suspicious, %d harmless, %d undetected", stats.Malicious, stats.Suspicious, stats.Harmless, stats.Undetected),
			File:        rel,
			Data: map[string]any{
				"sha256":     hash,
				"malicious":  stats.Malicious,
				"suspicious": stats.Suspicious,
				"permalink":  "https://www.virustotal.com/gui/file/" + hash,
			},
		}},
	}, true
}

var (
	_ analyzer.Applicable = (*Analyzer)(nil)
	_ analyzer.Describer  = (*Analyzer)(nil)
	_ analyzer.Analyzer   = (*Analyzer)(nil)
)
