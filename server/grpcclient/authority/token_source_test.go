// Package authority tests outbound authority client helpers.
package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/idp/clientauth"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
)

const (
	tokenSourceAuthorityName       = "edge"
	tokenSourceEndpoint            = "https://authority.example.test/oidc/token"
	tokenSourceClientID            = "edge-client"
	tokenSourceClientSecret        = "edge-secret"
	tokenSourceCachedToken         = "cached-token"
	tokenSourceNearExpiryToken     = "near-expiry-token"
	tokenSourceOpaqueToken         = "opaque-token"
	tokenSourceFreshToken          = "fresh-token"
	tokenSourcePrivateKeyID        = "edge-key"
	tokenSourcePrivateKeyAlgorithm = "EdDSA"
	tokenSourceRedisCacheBackend   = "redis"
	tokenSourceRedisKeyPrefix      = "test:authority-token:"
)

func TestBearerTokenSourceUsesRedisCacheHit(t *testing.T) {
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	source := newTestBearerTokenSource(BearerTokenSourceOptions{
		AuthorityName: tokenSourceAuthorityName,
		Config:        clientCredentialsConfig(tokenSourceEndpoint),
		Redis:         redisClient,
		Now:           fixedTokenSourceNow,
	})

	cached := mustEncodeCachedToken(t, cachedBearerToken{
		AccessToken: tokenSourceCachedToken,
		ExpiresAt:   fixedTokenSourceNow().Add(time.Minute),
	})
	mock.ExpectGet(source.cacheKey()).SetVal(cached)

	token, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	if token != tokenSourceCachedToken {
		t.Fatalf("Token() = %q, want %s", token, tokenSourceCachedToken)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestBearerTokenSourceUsesRefreshLockForNearExpiryToken(t *testing.T) {
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	source := newTestBearerTokenSource(BearerTokenSourceOptions{
		AuthorityName: tokenSourceAuthorityName,
		Config:        clientCredentialsConfig(tokenSourceEndpoint),
		Redis:         redisClient,
		Now:           fixedTokenSourceNow,
	})

	cached := mustEncodeCachedToken(t, cachedBearerToken{
		AccessToken: tokenSourceNearExpiryToken,
		ExpiresAt:   fixedTokenSourceNow().Add(20 * time.Second),
	})
	mock.ExpectGet(source.cacheKey()).SetVal(cached)
	mock.ExpectSetNX(source.lockKey(), tokenSourceAuthorityName, 10*time.Second).SetVal(false)

	token, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	if token != tokenSourceNearExpiryToken {
		t.Fatalf("Token() = %q, want %s", token, tokenSourceNearExpiryToken)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestBearerTokenSourceRefreshesExpiredToken(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != tokenSourceEndpoint {
			t.Fatalf("token endpoint = %q, want %q", r.URL.String(), tokenSourceEndpoint)
		}

		if r.FormValue("grant_type") != config.AuthorityClientCredentialsMode {
			t.Fatalf("grant_type = %q, want %s", r.FormValue("grant_type"), config.AuthorityClientCredentialsMode)
		}

		return jsonResponse(`{"access_token":"fresh-token","token_type":"Bearer","expires_in":90}`), nil
	})}

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	source := newTestBearerTokenSource(BearerTokenSourceOptions{
		AuthorityName: tokenSourceAuthorityName,
		Config:        clientCredentialsConfig(tokenSourceEndpoint),
		Redis:         redisClient,
		HTTPClient:    httpClient,
		Now:           fixedTokenSourceNow,
	})

	cached := mustEncodeCachedToken(t, cachedBearerToken{
		AccessToken: "expired-token",
		ExpiresAt:   fixedTokenSourceNow().Add(-time.Second),
	})
	mock.ExpectGet(source.cacheKey()).SetVal(cached)
	mock.ExpectSetNX(source.lockKey(), tokenSourceAuthorityName, 10*time.Second).SetVal(true)
	mock.Regexp().ExpectSet(source.cacheKey(), ".*fresh-token.*", 90*time.Second).SetVal("OK")
	mock.ExpectDel(source.lockKey()).SetVal(1)

	token, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	if token != tokenSourceFreshToken {
		t.Fatalf("Token() = %q, want %s", token, tokenSourceFreshToken)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestBearerTokenSourceBuildsPrivateKeyJWTAssertion(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	keyPath := writeEd25519PrivateKey(t, privateKey)

	var assertion string

	httpClient := privateKeyJWTHTTPClient(t, &assertion)

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	cfg := privateKeyJWTConfig(keyPath)

	source := newTestBearerTokenSource(BearerTokenSourceOptions{
		AuthorityName: tokenSourceAuthorityName,
		Config:        cfg,
		Redis:         redisClient,
		HTTPClient:    httpClient,
		Now:           fixedTokenSourceNow,
	})

	mock.ExpectGet(source.cacheKey()).RedisNil()
	mock.ExpectSetNX(source.lockKey(), tokenSourceAuthorityName, 10*time.Second).SetVal(true)
	mock.Regexp().ExpectSet(source.cacheKey(), ".*opaque-token.*", 90*time.Second).SetVal("OK")
	mock.ExpectDel(source.lockKey()).SetVal(1)

	token, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}

	if token != tokenSourceOpaqueToken {
		t.Fatalf("Token() = %q, want %s", token, tokenSourceOpaqueToken)
	}

	assertPrivateKeyJWT(t, assertion)
}

func TestBearerTokenSourceStaticTokenFileFallbackRejectsJWTInStrictMode(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("aaa.bbb.ccc\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg := clientCredentialsConfig(tokenSourceEndpoint)
	cfg.Enabled = false
	cfg.StaticTokenFile = tokenPath

	source := newTestBearerTokenSource(BearerTokenSourceOptions{
		AuthorityName:    tokenSourceAuthorityName,
		Config:           cfg,
		StrictSplitMode:  true,
		Now:              fixedTokenSourceNow,
		StaticTokenFiles: true,
	})

	_, err := source.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "JWT caller tokens") {
		t.Fatalf("Token() error = %v, want strict JWT rejection", err)
	}

	if err := os.WriteFile(tokenPath, []byte("opaque-dev-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	token, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("Token() opaque fallback error = %v", err)
	}

	if token != "opaque-dev-token" {
		t.Fatalf("Token() = %q, want opaque-dev-token", token)
	}
}

func newTestBearerTokenSource(opts BearerTokenSourceOptions) *bearerTokenSource {
	return NewBearerTokenSource(opts).(*bearerTokenSource)
}

func clientCredentialsConfig(tokenEndpoint string) *config.AuthorityOIDCBearerSection {
	return &config.AuthorityOIDCBearerSection{
		Enabled:                 true,
		Mode:                    config.AuthorityClientCredentialsMode,
		TokenEndpoint:           tokenEndpoint,
		ClientID:                tokenSourceClientID,
		ClientSecret:            secret.New(tokenSourceClientSecret),
		TokenEndpointAuthMethod: clientauth.MethodClientSecretPost,
		TokenCache: config.AuthorityTokenCacheSection{
			Backend:             tokenSourceRedisCacheBackend,
			KeyPrefix:           tokenSourceRedisKeyPrefix,
			RefreshBeforeExpiry: 30 * time.Second,
			RefreshLockTTL:      10 * time.Second,
		},
	}
}

func privateKeyJWTConfig(keyPath string) *config.AuthorityOIDCBearerSection {
	cfg := clientCredentialsConfig(tokenSourceEndpoint)
	cfg.TokenEndpointAuthMethod = clientauth.MethodPrivateKeyJWT
	cfg.ClientSecret = secret.Value{}
	cfg.ClientPrivateKeyFile = keyPath
	cfg.ClientKeyID = tokenSourcePrivateKeyID
	cfg.ClientAssertionAlg = tokenSourcePrivateKeyAlgorithm

	return cfg
}

func privateKeyJWTHTTPClient(t *testing.T, assertion *string) *http.Client {
	t.Helper()

	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		*assertion = r.FormValue("client_assertion")
		if r.FormValue("client_assertion_type") != clientauth.AssertionTypeJWTBearer {
			t.Fatalf("client_assertion_type = %q, want jwt-bearer", r.FormValue("client_assertion_type"))
		}

		return jsonResponse(`{"access_token":"opaque-token","token_type":"Bearer","expires_in":90}`), nil
	})}
}

func assertPrivateKeyJWT(t *testing.T, assertion string) {
	t.Helper()

	parsed, _, err := jwt.NewParser().ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified() error = %v", err)
	}

	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != tokenSourceClientID || claims["sub"] != tokenSourceClientID || claims["aud"] != tokenSourceEndpoint {
		t.Fatalf("private_key_jwt claims = %#v", claims)
	}

	if parsed.Header["kid"] != tokenSourcePrivateKeyID || parsed.Header["alg"] != tokenSourcePrivateKeyAlgorithm {
		t.Fatalf("private_key_jwt header = %#v", parsed.Header)
	}
}

func fixedTokenSourceNow() time.Time {
	return time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
}

func mustEncodeCachedToken(t *testing.T, token cachedBearerToken) string {
	t.Helper()

	raw, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	return string(raw)
}

func writeEd25519PrivateKey(t *testing.T, privateKey ed25519.PrivateKey) string {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "edge-key.pem")

	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
