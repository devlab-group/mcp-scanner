// Copyright 2025 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package attestation verifies a signed, offline-verifiable scan record and turns it into the
// same allow/review/block vocabulary the scanner already uses for its own findings.
//
// The record format is deliberately not defined here. It is a DSSE envelope whose payload is an
// in-toto Statement v1 - the shape produced by Canari and readable by cosign, GUAC and
// slsa-verifier without any vendor-specific code. Verifying a third-party record is the only way
// this scanner can tell a consumer what was observed about an artifact by a party the consumer
// does not have to trust at install time.
//
// Everything here refuses rather than degrades: an unknown payload type is rejected before any
// signature work, a signature that does not verify never yields a decision, and a record that is
// expired or carries no artifact digest is reported as inconclusive instead of being folded into
// a pass.
package attestation

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PayloadType is the only DSSE payload type this verifier understands. An unknown type is refused
// before any signature work: verifying a signature over a payload we then misread is worse than
// not verifying.
const PayloadType = "application/vnd.in-toto+json"

// Decision is the caller-facing answer.
type Decision string

const (
	// DecisionAllow means a valid signature over a statement that binds to the expected artifact
	// and whose verdict passed.
	DecisionAllow Decision = "allow"
	// DecisionReview means the record is valid and bound but records findings a human should see.
	DecisionReview Decision = "review"
	// DecisionBlock means the record is valid and says the artifact failed, or it does not
	// describe the artifact the caller is about to install.
	DecisionBlock Decision = "block"
	// DecisionInconclusive means the record cannot answer the question: no artifact digest, an
	// expired record, or a verdict that states nothing was verified.
	DecisionInconclusive Decision = "inconclusive"
)

// Result is the outcome of verifying one bundle.
type Result struct {
	OK             bool      `json:"ok"`
	Decision       Decision  `json:"decision"`
	Reasons        []string  `json:"reasons"`
	Verdict        string    `json:"verdict,omitempty"`
	Subject        string    `json:"subject,omitempty"`
	ArtifactSHA256 string    `json:"artifact_sha256,omitempty"`
	SignedAt       time.Time `json:"signed_at,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
}

// envelope mirrors the DSSE wire shape.
type envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

// statement mirrors only the parts of an in-toto Statement v1 this verifier reads.
type statement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string `json:"name"`
		Digest struct {
			SHA256 string `json:"sha256"`
		} `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		Verdict   string `json:"verdict"`
		ExpiresAt string `json:"expires_at"`
		Generated string `json:"generated_at"`
	} `json:"predicate"`
}

// Verify checks one bundle against one public key and one expected artifact digest.
//
// expectedSHA256 is not optional. A verdict that is not bound to the bytes the caller is about to
// install says nothing about those bytes, so an empty value blocks.
func Verify(bundleJSON, keyJSON []byte, expectedSHA256 string, now time.Time) Result {
	res := Result{Reasons: []string{}}
	block := func(format string, a ...any) Result {
		res.OK = false
		res.Decision = DecisionBlock
		res.Reasons = append(res.Reasons, fmt.Sprintf(format, a...))
		return res
	}
	inconclusive := func(format string, a ...any) Result {
		res.OK = false
		res.Decision = DecisionInconclusive
		res.Reasons = append(res.Reasons, fmt.Sprintf(format, a...))
		return res
	}

	if strings.TrimSpace(expectedSHA256) == "" {
		return block("no expected artifact digest was supplied")
	}
	expectedSHA256 = strings.ToLower(strings.TrimSpace(expectedSHA256))

	var env envelope
	if err := json.Unmarshal(bundleJSON, &env); err != nil {
		return block("bundle is not valid JSON: %v", err)
	}
	if env.PayloadType != PayloadType {
		return block("unsupported DSSE payload type %q (want %q)", env.PayloadType, PayloadType)
	}
	if len(env.Signatures) == 0 {
		return block("envelope carries no signature")
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.Payload))
	if err != nil {
		return block("envelope payload is not base64: %v", err)
	}

	pub, err := parsePublicKey(keyJSON)
	if err != nil {
		return block("%v", err)
	}

	verified := false
	for _, sig := range env.Signatures {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sig.Sig))
		if err != nil || len(raw) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pub, preAuthenticate(env.PayloadType, payload), raw) {
			verified = true
			break
		}
	}
	if !verified {
		return block("no signature on this bundle verifies against the supplied public key")
	}

	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return block("signed payload is not an in-toto statement: %v", err)
	}
	if len(st.Subject) == 0 {
		return inconclusive("signed statement has no subject")
	}
	gotSHA := strings.ToLower(strings.TrimSpace(st.Subject[0].Digest.SHA256))
	if gotSHA == "" {
		return inconclusive("signed statement has no sha256 subject digest")
	}
	res.Subject = st.Subject[0].Name
	res.ArtifactSHA256 = gotSHA
	res.Verdict = st.Predicate.Verdict

	if gotSHA != expectedSHA256 {
		return block("record describes artifact %s, not the artifact you are about to install (%s)", gotSHA, expectedSHA256)
	}

	if st.Predicate.Generated != "" {
		if ts, err := time.Parse(time.RFC3339, st.Predicate.Generated); err == nil {
			res.SignedAt = ts.UTC()
		}
	}
	if st.Predicate.ExpiresAt == "" {
		return inconclusive("record carries no expiry, so it cannot be dated")
	}
	expires, err := time.Parse(time.RFC3339, st.Predicate.ExpiresAt)
	if err != nil {
		return inconclusive("record expiry %q is not RFC 3339", st.Predicate.ExpiresAt)
	}
	res.ExpiresAt = expires.UTC()
	if !now.UTC().Before(expires.UTC()) {
		return block("record expired at %s; a correct signature over a stale statement is not evidence about today", res.ExpiresAt.Format(time.RFC3339))
	}

	switch strings.ToLower(strings.TrimSpace(st.Predicate.Verdict)) {
	case "pass":
		res.OK = true
		res.Decision = DecisionAllow
		res.Reasons = append(res.Reasons, "signature verifies, record binds this artifact, verdict is pass")
	case "pass-with-findings":
		res.OK = true
		res.Decision = DecisionReview
		res.Reasons = append(res.Reasons, "signature verifies, record binds this artifact, verdict is pass-with-findings")
	case "fail", "error":
		res.Decision = DecisionBlock
		res.Reasons = append(res.Reasons, "record verdict is "+strings.ToLower(st.Predicate.Verdict))
	case "unsupported":
		res.Decision = DecisionInconclusive
		res.Reasons = append(res.Reasons, "record verdict is unsupported: nothing about this artifact was verified")
	case "":
		res.Decision = DecisionInconclusive
		res.Reasons = append(res.Reasons, "record carries no verdict")
	default:
		res.Decision = DecisionInconclusive
		res.Reasons = append(res.Reasons, "unrecognised verdict "+strconv.Quote(st.Predicate.Verdict))
	}
	return res
}

// preAuthenticate implements the DSSE PAE construction:
//
//	DSSEv1 SP LEN(type) SP type SP LEN(body) SP body
func preAuthenticate(payloadType string, payload []byte) []byte {
	var b strings.Builder
	b.Grow(len(payloadType) + len(payload) + 32)
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return []byte(b.String())
}

// parsePublicKey accepts the three shapes a producer might hand a consumer: an in-toto/sigstore
// key object (hex), a JWK (base64url), or a PEM-encoded PKIX public key.
func parsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, errors.New("public key is empty")
	}

	if strings.HasPrefix(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, errors.New("public key looks like PEM but does not decode")
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("PEM public key is not a PKIX Ed25519 key")
		}
		ed, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("PEM public key is not Ed25519")
		}
		return ed, nil
	}

	var obj struct {
		KeyType string `json:"keytype"`
		KeyVal  struct {
			Public string `json:"public"`
		} `json:"keyval"`
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, fmt.Errorf("public key is neither PEM nor JSON: %w", err)
	}

	if obj.Kty == "OKP" || strings.EqualFold(obj.Crv, "Ed25519") {
		rawKey, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(obj.X))
		if err != nil || len(rawKey) != ed25519.PublicKeySize {
			return nil, errors.New("JWK x is not a 32-byte Ed25519 public key")
		}
		return ed25519.PublicKey(rawKey), nil
	}
	if strings.EqualFold(obj.KeyType, "ed25519") {
		rawKey, err := hex.DecodeString(strings.TrimSpace(obj.KeyVal.Public))
		if err != nil || len(rawKey) != ed25519.PublicKeySize {
			return nil, errors.New("keyval.public is not a 32-byte hex Ed25519 public key")
		}
		return ed25519.PublicKey(rawKey), nil
	}
	return nil, errors.New("unrecognised public key shape: want PEM, JWK OKP/Ed25519, or in-toto ed25519 key")
}
