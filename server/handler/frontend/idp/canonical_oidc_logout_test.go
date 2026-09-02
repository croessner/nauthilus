// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	domainidp "github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func TestOIDCLogoutCanonicalUsesTypedIndexRevokesAndIgnoresLegacyManager(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	session := openCanonicalFixture(t, runtime, browserCookie)

	identity, ok := session.Identity()
	if !ok {
		t.Fatal("canonical logout fixture has no identity")
	}

	if err := session.RecordOIDCClient(context.Background(), identity, "logout-client"); err != nil {
		t.Fatalf("record canonical logout client: %v", err)
	}

	handler, tokenRedis := newCanonicalOIDCLogoutTestHandler(t)
	legacyManager := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:      "legacy-mallory",
		definitions.SessionKeyUniqueUserID: "legacy-identity",
		definitions.SessionKeyOIDCClients:  "legacy-client",
		definitions.SessionKeyIDPFlowID:    "legacy-flow",
	}}
	router := canonicalOIDCLogoutTestRouter(runtime, legacyManager, handler.LogoutCanonical)
	request := httptest.NewRequest(http.MethodGet, "/oidc/logout", nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusFound || response.Header().Get("Location") != "https://logout.example.com" {
		t.Fatalf("canonical logout response = %d %q, want typed client redirect", response.Code, response.Header().Get("Location"))
	}

	assertCanonicalOIDCLogoutRevoked(t, runtime, browserCookie, response)

	if tokenRedis.Exists("test:oidc:dcr:{dynamic}:dynamic_user_epoch:identity-42") != true ||
		tokenRedis.Exists("test:oidc:dcr:{dynamic}:dynamic_user_epoch:legacy-identity") {
		t.Fatalf("canonical logout token epochs = %v", tokenRedis.Keys())
	}

	if legacyManager.GetString(definitions.SessionKeyAccount, "") != "legacy-mallory" ||
		legacyManager.GetString(definitions.SessionKeyOIDCClients, "") != "legacy-client" {
		t.Fatalf("canonical logout mutated legacy manager: %#v", legacyManager.data)
	}
}

func TestOIDCLogoutCanonicalWithoutBrowserSessionIsIdempotent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, _, _ := seedCanonicalIDPFlow(t, nil)
	handler, _ := newCanonicalOIDCLogoutTestHandler(t)
	router := canonicalOIDCLogoutTestRouter(runtime, nil, handler.LogoutCanonical)
	request := httptest.NewRequest(http.MethodGet, "/oidc/logout", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusFound || response.Header().Get("Location") != "/logged_out" {
		t.Fatalf(
			"canonical idempotent logout response = %d %q, want logged-out redirect",
			response.Code,
			response.Header().Get("Location"),
		)
	}

	assertCanonicalBrowserPurge(t, response)
}

func TestOIDCLogoutCanonicalPurgesBrowserWhenTokenRevocationFails(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	handler, tokenRedis := newCanonicalOIDCLogoutTestHandler(t)
	tokenRedis.Close()

	router := canonicalOIDCLogoutTestRouter(runtime, nil, handler.LogoutCanonical)
	request := httptest.NewRequest(http.MethodGet, "/oidc/logout", nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Location") != "" {
		t.Fatalf("canonical failed logout response = %d %q", response.Code, response.Header().Get("Location"))
	}

	assertCanonicalOIDCLogoutRevoked(t, runtime, browserCookie, response)
}

func TestOIDCLogoutCanonicalRejectsMismatchedIDTokenHintWithoutTokenMutation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, browserCookie, _ := seedCanonicalIDPFlow(t, nil)
	authenticateCanonicalFixture(t, runtime, browserCookie)
	handler, tokenRedis := newCanonicalOIDCLogoutTestHandler(t)
	idToken, _, _, _, _ := handler.idp.IssueTokens(context.Background(), &domainidp.OIDCSession{
		ClientID: "logout-client", UserID: "legacy-identity",
		Scopes: []string{definitions.ScopeOpenID}, AuthTime: time.Now(),
	})
	legacyManager := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:      "legacy-mallory",
		definitions.SessionKeyUniqueUserID: "legacy-identity",
	}}

	router := canonicalOIDCLogoutTestRouter(runtime, legacyManager, handler.LogoutCanonical)
	request := httptest.NewRequest(http.MethodGet, "/oidc/logout?id_token_hint="+url.QueryEscape(idToken), nil)
	request.AddCookie(browserCookie)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || response.Header().Get("Location") != "" {
		t.Fatalf("canonical mismatched hint response = %d %q", response.Code, response.Header().Get("Location"))
	}

	assertCanonicalOIDCLogoutRevoked(t, runtime, browserCookie, response)

	if tokenRedis.Exists("test:oidc:dcr:{dynamic}:dynamic_user_epoch:identity-42") ||
		tokenRedis.Exists("test:oidc:dcr:{dynamic}:dynamic_user_epoch:legacy-identity") {
		t.Fatalf("mismatched hint mutated token epochs = %v", tokenRedis.Keys())
	}

	if legacyManager.GetString(definitions.SessionKeyAccount, "") != "legacy-mallory" {
		t.Fatalf("mismatched hint mutated legacy manager: %#v", legacyManager.data)
	}
}

func newCanonicalOIDCLogoutTestHandler(t *testing.T) (*OIDCHandler, *miniredis.Miniredis) {
	t.Helper()

	tokenRedis := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: tokenRedis.Addr()})
	cfg := &mockOIDCCfg{
		issuer:     "https://auth.example.com",
		signingKey: secret.New(generateTestKey()),
		clients: []config.OIDCClient{{
			ClientID: "logout-client", LogoutRedirectURI: "https://logout.example.com",
		}},
	}
	handlerDeps := &deps.Deps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(), Redis: rediscli.NewTestClient(client),
		LangManager: &mockLangManager{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	idpInstance := domainidp.NewNauthilusIDP(handlerDeps)

	return NewOIDCHandler(handlerDeps, idpInstance, nil), tokenRedis
}

func canonicalOIDCLogoutTestRouter(
	runtime *cookie.CanonicalRuntime,
	legacyManager cookie.Manager,
	handler gin.HandlerFunc,
) *gin.Engine {
	router := gin.New()
	if legacyManager != nil {
		router.Use(func(ctx *gin.Context) {
			ctx.Set(definitions.CtxSecureDataKey, legacyManager)
			ctx.Next()
		})
	}

	router.GET("/oidc/logout", cookie.CanonicalMiddleware(runtime, cookie.CanonicalLogoutEntry), handler)

	return router
}

func assertCanonicalOIDCLogoutRevoked(
	t *testing.T,
	runtime *cookie.CanonicalRuntime,
	browserCookie *http.Cookie,
	response *httptest.ResponseRecorder,
) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(browserCookie)

	if _, err := runtime.Open(context.Background(), request); !errors.Is(err, cookie.ErrEnvelopeRejected) {
		t.Fatalf("canonical logout revoked session open error = %v, want envelope rejected", err)
	}

	cookies := response.Result().Cookies()
	if len(cookies) != 2 || cookies[0].MaxAge >= 0 || cookies[1].MaxAge >= 0 {
		t.Fatalf("canonical logout browser purge = %#v", cookies)
	}
}

// assertCanonicalBrowserPurge verifies that an idempotent logout clears both browser representations.
func assertCanonicalBrowserPurge(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()

	cookies := response.Result().Cookies()
	if len(cookies) != 2 || cookies[0].MaxAge >= 0 || cookies[1].MaxAge >= 0 {
		t.Fatalf("canonical logout browser purge = %#v", cookies)
	}
}
