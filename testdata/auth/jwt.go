// Package auth provides local mock identity infrastructure for testing the auth analyzer: a
// hand-rolled JWT signer (no dependency needed for three base64 segments and an HMAC) and a
// set of MCP-shaped HTTP servers, one vulnerable/fixed pair per auth class the analyzer
// probes for
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Secret is the shared HMAC key for this mock authorization server. It is
// only ever used against the mock MCP servers in this package.
const Secret = "test-only-hmac-secret-never-use-in-production"

// Claims is the subset of a JWT payload the mock servers understand
type Claims struct {
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Extra     []string `json:"-"`
}

// SignJWT hand-rolls a JWT: header.payload.signature, each base64url (no padding),
// HMAC-SHA256 over "header.payload"
func SignJWT(c Claims) string {
	header := base64URL([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, _ := json.Marshal(c)
	payload := base64URL(body)
	signingInput := header + "." + payload
	sig := hmacSign(signingInput, Secret)
	return signingInput + "." + sig
}

// SignJWTWithSecret signs with an arbitrary key, for building "invalid
// signature" test tokens without touching the real secret
func SignJWTWithSecret(c Claims, secret string) string {
	header := base64URL([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, _ := json.Marshal(c)
	payload := base64URL(body)
	signingInput := header + "." + payload
	sig := hmacSign(signingInput, secret)
	return signingInput + "." + sig
}

// VerifyJWT checks the signature and returns the claims
func VerifyJWT(token string) (Claims, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, false
	}
	signingInput := parts[0] + "." + parts[1]
	want := hmacSign(signingInput, Secret)
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		return Claims{}, false
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, false
	}
	var c Claims
	if err := json.Unmarshal(body, &c); err != nil {
		return Claims{}, false
	}
	return c, true
}

// Expired reports whether the claims' exp has passed
func (c Claims) Expired() bool {
	return c.ExpiresAt != 0 && time.Now().Unix() > c.ExpiresAt
}

// HasScope reports whether the claims' space-separated scope string
// contains want
func (c Claims) HasScope(want string) bool {
	for _, s := range strings.Fields(c.Scope) {
		if s == want {
			return true
		}
	}
	return false
}

func hmacSign(input, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(input))
	return base64URL(mac.Sum(nil))
}

func base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// BearerToken formats an Authorization header value
func BearerToken(token string) string { return fmt.Sprintf("Bearer %s", token) }
