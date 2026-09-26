package auth

import (
	"testing"
	"time"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	claims := Claims{Subject: "userA", Audience: "res", Issuer: "iss", Scope: "tools:call read", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	token := SignJWT(claims)

	got, ok := VerifyJWT(token)
	if !ok {
		t.Fatalf("VerifyJWT rejected a token signed with the right secret")
	}
	if got.Subject != claims.Subject || got.Audience != claims.Audience || got.Issuer != claims.Issuer {
		t.Fatalf("round-tripped claims changed: got %+v, want %+v", got, claims)
	}
	if got.Expired() {
		t.Fatalf("a token expiring in an hour reported as expired")
	}
	if !got.HasScope("tools:call") || !got.HasScope("read") {
		t.Fatalf("HasScope missed a scope present in %q", got.Scope)
	}
	if got.HasScope("admin") {
		t.Fatalf("HasScope found a scope that was never granted")
	}
}

func TestVerifyRejectsTamperedOrWrongSecret(t *testing.T) {
	claims := Claims{Subject: "userA", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	token := SignJWT(claims)

	if _, ok := VerifyJWT(token[:len(token)-2] + "xx"); ok {
		t.Fatalf("VerifyJWT accepted a token with a tampered signature")
	}
	wrongSecret := SignJWTWithSecret(claims, "a-different-secret")
	if _, ok := VerifyJWT(wrongSecret); ok {
		t.Fatalf("VerifyJWT accepted a token signed with the wrong secret")
	}
	if _, ok := VerifyJWT("not-a-jwt-at-all"); ok {
		t.Fatalf("VerifyJWT accepted a structurally invalid token")
	}
}

func TestExpiredClaim(t *testing.T) {
	past := Claims{ExpiresAt: time.Now().Add(-time.Minute).Unix()}
	if !past.Expired() {
		t.Fatalf("a token with exp in the past should report Expired()")
	}
	noExp := Claims{}
	if noExp.Expired() {
		t.Fatalf("a token with no exp claim should not report Expired()")
	}
}
