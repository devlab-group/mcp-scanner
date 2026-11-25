package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/devlab-group/mcp-scanner/internal/attestation"
	"github.com/devlab-group/mcp-scanner/internal/policy"
)

const testArtifactSHA = "cffd5602aff8d49a26dbf711add9c46e7f89c2cd821541afcae113c73dadbf86"

// writeBundle builds a signed bundle on disk the way a producer would publish one. The PAE
// construction is spelled out here rather than imported so the wire format is exercised
// independently of the verifier that reads it.
func writeBundle(t *testing.T, verdict string, expiresAt time.Time) (bundlePath, keyPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	statement := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{map[string]any{
			"name":   "npm:express@5.0.0",
			"digest": map[string]string{"sha256": testArtifactSHA},
		}},
		"predicateType": "https://canari.dev/attestation/v0.1",
		"predicate": map[string]any{
			"verdict":    verdict,
			"expires_at": expiresAt.UTC().Format(time.RFC3339),
		},
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	pae := "DSSEv1 " + strconv.Itoa(len(attestation.PayloadType)) + " " + attestation.PayloadType +
		" " + strconv.Itoa(len(payload)) + " " + string(payload)
	sig := ed25519.Sign(priv, []byte(pae))

	bundle, err := json.Marshal(map[string]any{
		"payloadType": attestation.PayloadType,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures":  []any{map[string]string{"keyid": "test", "sig": base64.StdEncoding.EncodeToString(sig)}},
	})
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	key, err := json.Marshal(map[string]any{
		"keytype": "ed25519",
		"scheme":  "ed25519",
		"keyval":  map[string]string{"public": hex.EncodeToString(pub)},
	})
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	bundlePath = filepath.Join(dir, "bundle.json")
	keyPath = filepath.Join(dir, "key.json")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return bundlePath, keyPath
}

func TestVerifyAttestationCommandExitCodes(t *testing.T) {
	future := time.Now().Add(48 * time.Hour)
	past := time.Now().Add(-48 * time.Hour)

	allowBundle, allowKey := writeBundle(t, "pass", future)
	expiredBundle, expiredKey := writeBundle(t, "pass", past)
	reviewBundle, reviewKey := writeBundle(t, "pass-with-findings", future)
	unsupportedBundle, unsupportedKey := writeBundle(t, "unsupported", future)

	cases := []struct {
		name string
		args []string
		want int
	}{
		{
			name: "a bound passing record is OK",
			args: []string{"verify-attestation", "--bundle", allowBundle, "--key", allowKey, "--artifact-sha256", testArtifactSHA},
			want: policy.ExitOK,
		},
		{
			name: "a passing record for other bytes blocks",
			args: []string{"verify-attestation", "--bundle", allowBundle, "--key", allowKey, "--artifact-sha256", "0000000000000000000000000000000000000000000000000000000000000000"},
			want: policy.ExitPolicyFail,
		},
		{
			name: "an expired record blocks even with a valid signature",
			args: []string{"verify-attestation", "--bundle", expiredBundle, "--key", expiredKey, "--artifact-sha256", testArtifactSHA},
			want: policy.ExitPolicyFail,
		},
		{
			name: "pass-with-findings is OK by default",
			args: []string{"verify-attestation", "--bundle", reviewBundle, "--key", reviewKey, "--artifact-sha256", testArtifactSHA},
			want: policy.ExitOK,
		},
		{
			name: "pass-with-findings fails when asked to",
			args: []string{"verify-attestation", "--bundle", reviewBundle, "--key", reviewKey, "--artifact-sha256", testArtifactSHA, "--fail-on-review"},
			want: policy.ExitPolicyFail,
		},
		{
			name: "unsupported cannot answer",
			args: []string{"verify-attestation", "--bundle", unsupportedBundle, "--key", unsupportedKey, "--artifact-sha256", testArtifactSHA},
			want: policy.ExitIncomplete,
		},
		{
			name: "a missing artifact digest is a usage error",
			args: []string{"verify-attestation", "--bundle", allowBundle, "--key", allowKey},
			want: policy.ExitUsage,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exitCode = policy.ExitOK
			t.Cleanup(func() { exitCode = policy.ExitOK })
			got := run(func() error {
				root := newRootCmd()
				root.SetArgs(tc.args)
				root.SetOut(io.Discard)
				root.SetErr(io.Discard)
				return root.Execute()
			})
			if got != tc.want {
				t.Fatalf("exit code = %d, want %d", got, tc.want)
			}
		})
	}
}
