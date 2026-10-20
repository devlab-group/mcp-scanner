// Package canary generates the fake secrets planted inside a sandbox run.
//
// Every value is synthetic, generated fresh for the run, and never derived
// from the real host environment or filesystem. A value showing up in
// sandbox output or in an outbound request is evidence the target read it
// and tried to use or exfiltrate it.
package canary

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/devlab-group/mcp-scanner/pkg/analyzer"
)

// Kind values, mirrored on analyzer.Canary.Kind
const (
	KindAWSKey     = "aws_key"
	KindSSHKey     = "ssh_key"
	KindAPIToken   = "api_token"
	KindDBPassword = "db_password"
	KindFile       = "file"
)

// Set is one run's worth of planted secrets: the analyzer.Canary records
// handed to the observer, the file tree that backs the file-based ones, and
// the environment variables to inject into the container
type Set struct {
	RunID    string
	Canaries []analyzer.Canary
	// Files maps a path relative to the fake home root to its content
	Files map[string]string
	// Env is the set of environment variables to inject, all synthetic
	Env map[string]string
}

// Generate builds a fresh set of synthetic secrets. It never reads os.Environ
// or any real file; every byte comes from crypto/rand.
func Generate() (*Set, error) {
	runID, err := randHex(4)
	if err != nil {
		return nil, fmt.Errorf("canary: generating run id: %w", err)
	}
	s := &Set{RunID: runID, Files: map[string]string{}, Env: map[string]string{}}

	awsKeyID, err := awsAccessKeyID()
	if err != nil {
		return nil, err
	}
	awsSecret, err := canaryToken("CANARY", 32)
	if err != nil {
		return nil, err
	}
	s.plant(KindAWSKey, ".aws/credentials",
		fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n", awsKeyID, awsSecret),
		"", awsSecret)
	s.plantEnv(KindAWSKey, "AWS_ACCESS_KEY_ID", awsKeyID)
	s.plantEnv(KindAWSKey, "AWS_SECRET_ACCESS_KEY", awsSecret)

	sshKey, err := syntheticSSHKey()
	if err != nil {
		return nil, err
	}
	s.plant(KindSSHKey, ".ssh/id_ed25519", sshKey, "", sshKey)

	apiToken, err := canaryToken("sk-canary", 24)
	if err != nil {
		return nil, err
	}
	s.plant(KindAPIToken, ".netrc",
		fmt.Sprintf("machine api.canary.invalid\nlogin canary\npassword %s\n", apiToken),
		"", apiToken)
	s.plantEnv(KindAPIToken, "API_TOKEN", apiToken)

	dbPassword, err := canaryToken("canary-db", 20)
	if err != nil {
		return nil, err
	}
	s.plant(KindDBPassword, "secrets/db_password.txt", dbPassword+"\n", "", dbPassword)
	s.plantEnv(KindDBPassword, "DB_PASSWORD", dbPassword)

	envFile := fmt.Sprintf("DB_PASSWORD=%s\nAPI_TOKEN=%s\n", dbPassword, apiToken)
	s.plant(KindFile, ".env", envFile, "", "")

	for i := range s.Canaries {
		s.Canaries[i].ID = fmt.Sprintf("%s-%s-%d", s.Canaries[i].Kind, runID, i)
	}
	return s, nil
}

// ContainerHome is where the sandbox mounts the directory a Set is materialized into, and
// the HOME it gives the container
const ContainerHome = "/sandbox/home"

func (s *Set) plant(kind, relPath, content, env, value string) {
	s.Files[relPath] = content
	if value == "" {
		value = content
	}
	s.Canaries = append(s.Canaries, analyzer.Canary{
		Path:    relPath,
		Env:     env,
		Value:   value,
		Kind:    kind,
		Content: content,
	})
}

func (s *Set) plantEnv(kind, env, value string) {
	s.Env[env] = value
	s.Canaries = append(s.Canaries, analyzer.Canary{
		Env:   env,
		Value: value,
		Kind:  kind,
	})
}

// ErrPathEscape is returned by Materialize for a canary file path that is absolute or
// contains a ".." component
var ErrPathEscape = errors.New("canary: path escapes the run directory")

// Materialize writes the fake home directory tree under root through os.Root. Lexical checks
// reject obvious escapes, while kernel-backed resolution remains the actual filesystem boundary.
func (s *Set) Materialize(root string) error {
	r, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("canary: opening run directory: %w", err)
	}
	defer r.Close()

	paths := slices.Sorted(maps.Keys(s.Files))
	for _, rel := range paths {
		clean, err := cleanRelPath(rel)
		if err != nil {
			return fmt.Errorf("canary: %s: %w", rel, err)
		}
		if dir := filepath.Dir(clean); dir != "." {
			if err := r.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("canary: creating %s: %w", dir, err)
			}
		}
		if err := r.WriteFile(clean, []byte(s.Files[rel]), 0o444); err != nil {
			return fmt.Errorf("canary: writing %s: %w", clean, err)
		}
	}
	return nil
}

// cleanRelPath rejects an absolute path or one with a ".." component,
// mirroring internal/supplychain/archive's sanitizedName: a fast,
// specific-error rejection for the common cases, not itself the
// containment guarantee - the *os.Root Materialize writes through is
func cleanRelPath(rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("%w: empty path", ErrPathEscape)
	}
	if filepath.IsAbs(rel) {
		return "", ErrPathEscape
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", ErrPathEscape
	}
	return clean, nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// canaryToken builds an obviously-fake token: a recognizable prefix followed
// by random hex, so a hit is unmistakable in a log or report
func canaryToken(prefix string, randBytes int) (string, error) {
	h, err := randHex(randBytes)
	if err != nil {
		return "", err
	}
	return prefix + "-" + h, nil
}

// awsAccessKeyID produces an AWS-shaped key id (AKIA + 16 chars) with a
// CANARY marker baked into the random portion
func awsAccessKeyID() (string, error) {
	h, err := randHex(5) // 10 hex chars
	if err != nil {
		return "", err
	}
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	upper := make([]byte, len(h))
	for i, c := range []byte(h) {
		upper[i] = alphabet[int(c)%len(alphabet)]
	}
	return "AKIA" + "CANARY" + string(upper), nil
}

// syntheticSSHKey generates a real, freshly-random ed25519 key pair (never
// used for anything but sitting in the sandbox as bait) and PEM-encodes the
// private key, with a synthetic marker comment above it
func syntheticSSHKey() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return "# SYNTHETIC CANARY KEY - generated by mcp-scanner, not a real credential\n" + string(pem.EncodeToMemory(block)), nil
}
