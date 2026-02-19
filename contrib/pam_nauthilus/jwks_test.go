package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testRSAKey generates an RSA key pair for tests.
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	return key
}

// signJWT creates a minimal RS256 JWT signed with the given key.
func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()

	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerB64 + "." + claimsB64

	hash := sha256.Sum256([]byte(signingInput))

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64
}

// jwksJSON returns the JWKS JSON for a public key with the given kid.
func jwksJSON(t *testing.T, pub *rsa.PublicKey, kid string) []byte {
	t.Helper()

	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	resp := jwksResponse{
		Keys: []jwkKey{
			{
				Kty: "RSA",
				Alg: "RS256",
				Use: "sig",
				Kid: kid,
				N:   n,
				E:   e,
			},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	return data
}

func newTestFlow(t *testing.T, serverURL string, client *http.Client) *DeviceFlow {
	t.Helper()

	clock := &testClock{now: time.Unix(0, 0)}

	settings := Settings{
		Issuer:         serverURL,
		ClientID:       "client",
		ClientSecret:   "secret",
		Scope:          "openid",
		Timeout:        2 * time.Minute,
		RequestTimeout: 5 * time.Second,
		UserClaim:      "preferred_username",
		AllowHTTP:      true,
	}

	flow, err := NewDeviceFlow(settings, client, clock)
	if err != nil {
		t.Fatalf("new flow: %v", err)
	}

	return flow
}

func TestVerifyTokenSignatureSuccess(t *testing.T) {
	key := testRSAKey(t)
	kid := "test-key-1"

	token := signJWT(t, key, kid, map[string]any{
		"sub": "alice",
		"aud": "client",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, &key.PublicKey, kid))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	flow := newTestFlow(t, server.URL, server.Client())

	if err := flow.VerifyTokenSignature(t.Context(), token); err != nil {
		t.Fatalf("expected signature verification to succeed: %v", err)
	}
}

func TestVerifyTokenSignatureInvalid(t *testing.T) {
	signingKey := testRSAKey(t)
	wrongKey := testRSAKey(t)
	kid := "test-key-1"

	// Sign with signingKey but serve wrongKey's public key.
	token := signJWT(t, signingKey, kid, map[string]any{
		"sub": "alice",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, &wrongKey.PublicKey, kid))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	flow := newTestFlow(t, server.URL, server.Client())

	err := flow.VerifyTokenSignature(t.Context(), token)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerifyTokenSignatureInvalidJWTFormat(t *testing.T) {
	mux := http.NewServeMux()

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	flow := newTestFlow(t, server.URL, server.Client())

	if err := flow.VerifyTokenSignature(t.Context(), "not-a-jwt"); err == nil {
		t.Fatalf("expected error for invalid JWT format")
	}
}

func TestVerifyTokenSignatureUnsupportedAlgorithm(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice"}`))
	fakeToken := header + "." + payload + ".fake-sig"

	mux := http.NewServeMux()

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	flow := newTestFlow(t, server.URL, server.Client())

	err := flow.VerifyTokenSignature(t.Context(), fakeToken)
	if err == nil {
		t.Fatalf("expected error for unsupported algorithm")
	}

	if !strings.Contains(err.Error(), "unsupported signing algorithm") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyTokenSignatureNoMatchingKey(t *testing.T) {
	key := testRSAKey(t)

	// Sign with kid "key-A" but serve kid "key-B".
	token := signJWT(t, key, "key-A", map[string]any{"sub": "alice"})

	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, &key.PublicKey, "key-B"))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	flow := newTestFlow(t, server.URL, server.Client())

	err := flow.VerifyTokenSignature(t.Context(), token)
	if err == nil {
		t.Fatalf("expected error for no matching key")
	}

	if !strings.Contains(err.Error(), "no matching signing key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIntrospectTokenActive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/introspect", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "client" || secret != "secret" {
			t.Fatalf("expected valid basic auth")
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}

		if r.FormValue("token") != "valid-token" {
			t.Fatalf("unexpected token value: %s", r.FormValue("token"))
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"active": true})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	flow := newTestFlow(t, server.URL, server.Client())

	if err := flow.IntrospectToken(t.Context(), "valid-token"); err != nil {
		t.Fatalf("expected active token: %v", err)
	}
}

func TestIntrospectTokenInactive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	flow := newTestFlow(t, server.URL, server.Client())

	err := flow.IntrospectToken(t.Context(), "expired-token")
	if !errors.Is(err, ErrTokenInactive) {
		t.Fatalf("expected ErrTokenInactive, got %v", err)
	}
}

func TestIntrospectTokenEmptyToken(t *testing.T) {
	mux := http.NewServeMux()

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	flow := newTestFlow(t, server.URL, server.Client())

	if err := flow.IntrospectToken(t.Context(), ""); err == nil {
		t.Fatalf("expected error for empty token")
	}
}

func TestIntrospectTokenServerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	flow := newTestFlow(t, server.URL, server.Client())

	err := flow.IntrospectToken(t.Context(), "some-token")
	if err == nil {
		t.Fatalf("expected error for server error")
	}

	if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFindSigningKeyFallbackNoKid(t *testing.T) {
	keys := []jwkKey{
		{Kty: "RSA", Alg: "RS256", Use: "sig", Kid: "key-1", N: "abc", E: "AQAB"},
	}

	// Empty kid should fall back to first signing key.
	key, err := findSigningKey(keys, "")
	if err != nil {
		t.Fatalf("expected fallback key: %v", err)
	}

	if key.Kid != "key-1" {
		t.Fatalf("expected key-1, got %s", key.Kid)
	}
}

func TestFindSigningKeyNoKeys(t *testing.T) {
	if _, err := findSigningKey(nil, "any"); err == nil {
		t.Fatalf("expected error for empty key set")
	}
}

func TestParseRSAPublicKeyUnsupportedType(t *testing.T) {
	key := jwkKey{Kty: "EC", N: "abc", E: "AQAB"}

	if _, err := parseRSAPublicKey(key); err == nil {
		t.Fatalf("expected error for non-RSA key type")
	}
}

func TestDeviceFlowFullWithJWKSAndIntrospection(t *testing.T) {
	rsaKey := testRSAKey(t)
	kid := "full-test-key"
	clock := &testClock{now: time.Unix(0, 0)}
	tokenCalls := 0

	accessToken := signJWT(t, rsaKey, kid, map[string]any{
		"sub": "alice",
		"aud": "client",
	})

	mux := http.NewServeMux()

	mux.HandleFunc("/oidc/device", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(deviceResponse{
			DeviceCode:      "dev-code",
			UserCode:        "USER-123",
			VerificationURI: "https://example.test/verify",
			ExpiresIn:       60,
			Interval:        1,
		})
	})

	mux.HandleFunc("/oidc/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++

		if tokenCalls == 1 {
			_ = json.NewEncoder(w).Encode(tokenResponse{Error: "authorization_pending"})

			return
		}

		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   30,
		})
	})

	mux.HandleFunc("/oidc/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, &rsaKey.PublicKey, kid))
	})

	mux.HandleFunc("/oidc/introspect", func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "client" || secret != "secret" {
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"active": true})
	})

	mux.HandleFunc("/oidc/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+accessToken {
			t.Fatalf("unexpected authorization header: %s", got)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"preferred_username": "alice"})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	settings := Settings{
		Issuer:         server.URL,
		ClientID:       "client",
		ClientSecret:   "secret",
		Scope:          "openid",
		Timeout:        2 * time.Minute,
		RequestTimeout: 5 * time.Second,
		UserClaim:      "preferred_username",
		AllowHTTP:      true,
	}

	flow, err := NewDeviceFlow(settings, server.Client(), clock)
	if err != nil {
		t.Fatalf("new flow: %v", err)
	}

	ctx := t.Context()

	device, err := flow.StartDeviceAuthorization(ctx)
	if err != nil {
		t.Fatalf("start device: %v", err)
	}

	deadline := clock.Now().Add(device.ExpiresIn)

	token, err := flow.PollToken(ctx, device.DeviceCode, device.Interval, deadline)
	if err != nil {
		t.Fatalf("poll token: %v", err)
	}

	if err := flow.VerifyTokenSignature(ctx, token.AccessToken); err != nil {
		t.Fatalf("verify signature: %v", err)
	}

	if err := flow.IntrospectToken(ctx, token.AccessToken); err != nil {
		t.Fatalf("introspect token: %v", err)
	}

	claims, err := flow.FetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		t.Fatalf("fetch userinfo: %v", err)
	}

	if err := flow.VerifyUser(claims, "alice"); err != nil {
		t.Fatalf("verify user: %v", err)
	}
}

func TestEndpointsFromIssuerIncludesJWKSAndIntrospection(t *testing.T) {
	settings := Settings{
		Issuer:         "https://example.test",
		ClientID:       "client",
		ClientSecret:   "secret",
		Scope:          "openid",
		Timeout:        time.Minute,
		RequestTimeout: time.Second,
		UserClaim:      "preferred_username",
	}

	endpoints, err := settings.Endpoints()
	if err != nil {
		t.Fatalf("endpoints: %v", err)
	}

	if endpoints.JWKS != "https://example.test/oidc/jwks" {
		t.Fatalf("unexpected JWKS endpoint: %s", endpoints.JWKS)
	}

	if endpoints.Introspection != "https://example.test/oidc/introspect" {
		t.Fatalf("unexpected introspection endpoint: %s", endpoints.Introspection)
	}
}
