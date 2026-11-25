package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"
)

const testSHA = "cffd5602aff8d49a26dbf711add9c46e7f89c2cd821541afcae113c73dadbf86"

type fixture struct {
	bundle []byte
	key    []byte
}

// newFixture signs a statement with a fresh key and returns the bundle plus the public key in the
// in-toto/sigstore shape (hex keyval), which is what a producer publishes.
func newFixture(t *testing.T, verdict, expiresAt, digest, payloadType string) fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	statement := map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{map[string]any{
			"name":   "npm:express@5.0.0",
			"digest": map[string]string{"sha256": digest},
		}},
		"predicateType": "https://canari.dev/attestation/v0.1",
		"predicate": map[string]any{
			"verdict":      verdict,
			"generated_at": "2026-11-24T00:00:00Z",
			"expires_at":   expiresAt,
		},
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	sig := ed25519.Sign(priv, preAuthenticate(payloadType, payload))
	bundle, err := json.Marshal(map[string]any{
		"payloadType": payloadType,
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
	return fixture{bundle: bundle, key: key}
}

func fixedNow() time.Time { return time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC) }

func TestVerify_AllowsABoundPassingRecord(t *testing.T) {
	f := newFixture(t, "pass", "2026-12-07T00:00:00Z", testSHA, PayloadType)
	got := Verify(f.bundle, f.key, testSHA, fixedNow())
	if got.Decision != DecisionAllow || !got.OK {
		t.Fatalf("decision = %s ok=%v reasons=%v, want allow", got.Decision, got.OK, got.Reasons)
	}
	if got.ArtifactSHA256 != testSHA {
		t.Fatalf("artifact digest = %q, want %q", got.ArtifactSHA256, testSHA)
	}
}

func TestVerify_PassWithFindingsIsReview(t *testing.T) {
	f := newFixture(t, "pass-with-findings", "2026-12-07T00:00:00Z", testSHA, PayloadType)
	got := Verify(f.bundle, f.key, testSHA, fixedNow())
	if got.Decision != DecisionReview {
		t.Fatalf("decision = %s, want review", got.Decision)
	}
}

func TestVerify_BlocksAnExpiredRecordEvenWhenTheSignatureIsValid(t *testing.T) {
	f := newFixture(t, "pass", "2026-11-24T00:00:00Z", testSHA, PayloadType)
	got := Verify(f.bundle, f.key, testSHA, fixedNow())
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want block", got.Decision)
	}
}

func TestVerify_BlocksWhenTheRecordDescribesOtherBytes(t *testing.T) {
	f := newFixture(t, "pass", "2026-12-07T00:00:00Z", testSHA, PayloadType)
	other := "0000000000000000000000000000000000000000000000000000000000000000"
	got := Verify(f.bundle, f.key, other, fixedNow())
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want block", got.Decision)
	}
}

func TestVerify_BlocksWhenThePayloadWasEditedAfterSigning(t *testing.T) {
	f := newFixture(t, "pass", "2026-12-07T00:00:00Z", testSHA, PayloadType)
	var env map[string]any
	if err := json.Unmarshal(f.bundle, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
	payload[len(payload)-2] ^= 0x01
	env["payload"] = base64.StdEncoding.EncodeToString(payload)
	tampered, _ := json.Marshal(env)

	got := Verify(tampered, f.key, testSHA, fixedNow())
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want block", got.Decision)
	}
}

func TestVerify_BlocksAnUnknownPayloadTypeBeforeAnySignatureWork(t *testing.T) {
	f := newFixture(t, "pass", "2026-12-07T00:00:00Z", testSHA, "application/json")
	got := Verify(f.bundle, f.key, testSHA, fixedNow())
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want block", got.Decision)
	}
}

func TestVerify_BlocksWithoutAnExpectedDigest(t *testing.T) {
	f := newFixture(t, "pass", "2026-12-07T00:00:00Z", testSHA, PayloadType)
	got := Verify(f.bundle, f.key, "   ", fixedNow())
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want block", got.Decision)
	}
}

func TestVerify_UnsupportedVerdictIsInconclusiveNotClean(t *testing.T) {
	f := newFixture(t, "unsupported", "2026-12-07T00:00:00Z", testSHA, PayloadType)
	got := Verify(f.bundle, f.key, testSHA, fixedNow())
	if got.Decision != DecisionInconclusive {
		t.Fatalf("decision = %s, want inconclusive", got.Decision)
	}
}

func TestVerify_FailVerdictBlocks(t *testing.T) {
	f := newFixture(t, "fail", "2026-12-07T00:00:00Z", testSHA, PayloadType)
	got := Verify(f.bundle, f.key, testSHA, fixedNow())
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want block", got.Decision)
	}
}

func TestVerify_ARecordWithNoDigestIsInconclusive(t *testing.T) {
	f := newFixture(t, "pass", "2026-12-07T00:00:00Z", "", PayloadType)
	got := Verify(f.bundle, f.key, testSHA, fixedNow())
	if got.Decision != DecisionInconclusive {
		t.Fatalf("decision = %s, want inconclusive", got.Decision)
	}
}

func TestVerify_AcceptsAJWKPublicKey(t *testing.T) {
	f := newFixture(t, "pass", "2026-12-07T00:00:00Z", testSHA, PayloadType)

	var key map[string]any
	if err := json.Unmarshal(f.key, &key); err != nil {
		t.Fatalf("unmarshal key: %v", err)
	}
	keyval, ok := key["keyval"].(map[string]any)
	if !ok {
		t.Fatalf("key has no keyval object")
	}
	raw, err := hex.DecodeString(keyval["public"].(string))
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	jwk, _ := json.Marshal(map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(raw),
	})

	if got := Verify(f.bundle, jwk, testSHA, fixedNow()); got.Decision != DecisionAllow {
		t.Fatalf("decision with JWK = %s, want allow", got.Decision)
	}
}

func TestVerify_AKeyThatDoesNotMatchTheSignatureBlocks(t *testing.T) {
	f := newFixture(t, "pass", "2026-12-07T00:00:00Z", testSHA, PayloadType)
	other := newFixture(t, "pass", "2026-12-07T00:00:00Z", testSHA, PayloadType)
	got := Verify(f.bundle, other.key, testSHA, fixedNow())
	if got.Decision != DecisionBlock {
		t.Fatalf("decision = %s, want block", got.Decision)
	}
}

func TestVerify_AcceptsAPEMPublicKey(t *testing.T) {
	f := newFixture(t, "pass", "2026-12-07T00:00:00Z", testSHA, PayloadType)

	var key map[string]any
	if err := json.Unmarshal(f.key, &key); err != nil {
		t.Fatalf("unmarshal key: %v", err)
	}
	keyval := key["keyval"].(map[string]any)
	raw, err := hex.DecodeString(keyval["public"].(string))
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	if got := Verify(f.bundle, pemKey, testSHA, fixedNow()); got.Decision != DecisionAllow {
		t.Fatalf("decision with PEM = %s, want allow", got.Decision)
	}
}
