// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package idp

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/handler/deps"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func TestCanonicalFrontendRouteChainsNeverInstallLegacySecureMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, testCase := range []struct {
		name     string
		chain    func(frontendRouteMiddlewares, gin.HandlerFunc) []gin.HandlerFunc
		expected []string
	}{
		{
			name: "login_and_mfa", chain: frontendRouteHandlers,
			expected: []string{"security", "canonical", "csrf", "i18n", "handler"},
		},
		{
			name: "authenticated_self_service", chain: frontendAuthRouteHandlers,
			expected: []string{"security", "canonical", "csrf", "i18n", "handler"},
		},
		{
			name: "self_service_entry", chain: frontendSelfServiceEntryRouteHandlers,
			expected: []string{"security", "self-service-entry", "csrf", "i18n", "handler"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			sequence := make([]string, 0, 5)
			middleware := func(name string) gin.HandlerFunc {
				return func(ctx *gin.Context) {
					sequence = append(sequence, name)

					ctx.Next()
				}
			}
			middlewares := frontendRouteMiddlewares{
				security: middleware("security"), csrf: middleware("csrf"),
				canonical:        middleware("canonical"),
				selfServiceEntry: middleware("self-service-entry"),
				i18n:             middleware("i18n"),
			}
			final := func(ctx *gin.Context) {
				sequence = append(sequence, "handler")

				ctx.Status(http.StatusNoContent)
			}

			router := gin.New()
			router.GET("/route", testCase.chain(middlewares, final)...)

			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/route", nil))

			if response.Code != http.StatusNoContent || slices.Contains(sequence, "legacy-secure") ||
				!slices.Equal(sequence, testCase.expected) {
				t.Fatalf("canonical route sequence = %v, status = %d", sequence, response.Code)
			}
		})
	}
}

type canonicalRuntimeConfig struct {
	config.FileSettings
	server config.ServerSection
}

func (c *canonicalRuntimeConfig) GetServer() *config.ServerSection { return &c.server }

func TestNewCanonicalBrowserRuntimeUsesExplicitV1Composition(t *testing.T) {
	mini := miniredis.RunT(t)
	cfg := &canonicalRuntimeConfig{server: config.ServerSection{
		Redis: config.Redis{Prefix: "canonical-runtime-test"},
		Frontend: config.Frontend{
			EncryptionSecret: secret.New("canonical-runtime-composition-secret-32bytes"),
		},
	}}

	runtime, err := NewCanonicalBrowserRuntime(&deps.Deps{
		Cfg: cfg, Env: &config.EnvironmentSettings{DevMode: true},
		Redis: rediscli.NewTestClient(redis.NewClient(&redis.Options{Addr: mini.Addr()})),
	})
	if err != nil {
		t.Fatalf("compose canonical browser runtime: %v", err)
	}

	response := httptest.NewRecorder()
	if _, err = runtime.Create(context.Background(), response, false); err != nil {
		t.Fatalf("create canonical browser session: %v", err)
	}

	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Secure {
		t.Fatalf("canonical runtime cookie = %#v", cookies)
	}

	cfg.server.Frontend.EncryptionSecret = secret.Value{}
	if _, err = NewCanonicalBrowserRuntime(&deps.Deps{
		Cfg: cfg, Env: &config.EnvironmentSettings{DevMode: true},
		Redis: rediscli.NewTestClient(redis.NewClient(&redis.Options{Addr: mini.Addr()})),
	}); err == nil {
		t.Fatal("compose canonical browser runtime without secret: error = nil")
	}
}

func TestFrontendRegisterCanonicalBindsLoginAndProtectedRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, _, _ := seedCanonicalIDPFlow(t, nil)

	handler, err := NewCanonicalFrontendHandler(&deps.Deps{
		Cfg: &mockFrontendCfg{}, Env: config.NewTestEnvironmentConfig(),
		LangManager: &mockLangManager{}, Logger: slog.Default(),
	}, runtime)
	if err != nil {
		t.Fatalf("compose canonical frontend registrar: %v", err)
	}

	router := gin.New()
	handler.Register(router)

	routes := router.Routes()
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, frontendLoginPath}, {http.MethodPost, frontendLoginPath},
		{http.MethodGet, "/login/mfa"}, {http.MethodPost, "/login/totp"},
		{http.MethodGet, "/login/webauthn/begin"}, {http.MethodPost, "/login/webauthn/finish"},
		{http.MethodGet, definitions.MFARoot + "/register/home"},
		{http.MethodDelete, definitions.MFARoot + "/totp"},
		{http.MethodGet, definitions.MFARoot + "/webauthn/devices"},
		{http.MethodGet, definitions.MFARoot + "/register/continue"},
		{http.MethodGet, "/logged_out"},
	} {
		if !slices.ContainsFunc(routes, func(info gin.RouteInfo) bool {
			return info.Method == route.method && info.Path == route.path
		}) {
			t.Fatalf("canonical frontend route missing: %s %s", route.method, route.path)
		}
	}

	assertCanonicalContinuationRejectsAbsentEnvelope(t, router, frontendLoginPath)
}

func TestCanonicalSelfServiceHomeStartsLoginForMissingEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, _, _ := seedCanonicalIDPFlow(t, nil)

	handler, err := NewCanonicalFrontendHandler(&deps.Deps{
		Cfg: &mockFrontendCfg{}, Env: config.NewTestEnvironmentConfig(),
		LangManager: &mockMultiLangManager{}, Logger: slog.Default(),
	}, runtime)
	if err != nil {
		t.Fatalf("compose canonical frontend registrar: %v", err)
	}

	router := gin.New()
	handler.Register(router)

	request := httptest.NewRequest(http.MethodGet, definitions.MFARoot+"/register/home/de", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf("self-service entry status = %d, want %d", response.Code, http.StatusFound)
	}

	location := response.Header().Get("Location")
	if !strings.HasPrefix(location, "/login/de?flow=") {
		t.Fatalf("self-service login location = %q", location)
	}

	cookies := response.Result().Cookies()
	if !slices.ContainsFunc(cookies, func(current *http.Cookie) bool {
		return current.Name == definitions.SecureDataCookieName && current.Value != ""
	}) {
		t.Fatalf("self-service entry cookies = %#v, want purge pair and fresh canonical envelope", cookies)
	}
}

func TestOIDCRegisterCanonicalBindsExplicitBrowserModesWithoutLegacyFailurePage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, _, _ := seedCanonicalIDPFlow(t, nil)
	handler, _ := newCanonicalOIDCLogoutTestHandler(t)
	router := gin.New()
	handler.Register(router, runtime)

	routes := router.Routes()

	hasRoute := func(method string, path string) bool {
		return slices.ContainsFunc(routes, func(route gin.RouteInfo) bool {
			return route.Method == method && route.Path == path
		})
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/oidc/authorize"}, {http.MethodGet, "/oidc/authorize/:languageTag"},
		{http.MethodGet, frontendDeviceVerifyPath}, {http.MethodGet, frontendDeviceVerifyPath + "/:languageTag"},
		{http.MethodPost, frontendDeviceVerifyPath}, {http.MethodPost, frontendDeviceVerifyPath + "/:languageTag"},
		{http.MethodGet, frontendDeviceConsentPath}, {http.MethodGet, frontendDeviceConsentPath + "/:languageTag"},
		{http.MethodPost, frontendDeviceConsentPath}, {http.MethodPost, frontendDeviceConsentPath + "/:languageTag"},
		{http.MethodGet, "/oidc/logout"}, {http.MethodGet, "/logout"},
		{http.MethodGet, "/oidc/consent"}, {http.MethodPost, "/oidc/consent"},
		{http.MethodGet, "/.well-known/openid-configuration"}, {http.MethodPost, "/oidc/token"},
		{http.MethodGet, "/oidc/userinfo"}, {http.MethodPost, "/oidc/introspect"},
		{http.MethodGet, "/oidc/jwks"}, {http.MethodPost, "/oidc/device"},
	} {
		if !hasRoute(route.method, route.path) {
			t.Fatalf("canonical OIDC route missing: %s %s", route.method, route.path)
		}
	}

	if hasRoute(http.MethodGet, "/oidc/device/verify/failed") ||
		hasRoute(http.MethodGet, "/oidc/device/verify/failed/:languageTag") {
		t.Fatal("canonical OIDC registrar retained legacy cookie-backed device failure page")
	}

	assertCanonicalContinuationRejectsAbsentEnvelope(t, router, "/oidc/consent")

	logoutRequest := httptest.NewRequest(http.MethodGet, "/oidc/logout", nil)
	logoutResponse := httptest.NewRecorder()
	router.ServeHTTP(logoutResponse, logoutRequest)

	if logoutResponse.Code != http.StatusFound || logoutResponse.Header().Get("Location") != "/logged_out" {
		t.Fatalf(
			"canonical idempotent logout = %d %q, want logged-out redirect",
			logoutResponse.Code,
			logoutResponse.Header().Get("Location"),
		)
	}

	request := httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code == http.StatusConflict {
		t.Fatal("canonical OIDC protocol entry rejected absent envelope instead of starting a fresh anchor")
	}
}

func assertCanonicalContinuationRejectsAbsentEnvelope(t *testing.T, router *gin.Engine, target string) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, target, nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("canonical continuation %s = %d, want %d", target, response.Code, http.StatusConflict)
	}

	deleted := response.Result().Cookies()
	if len(deleted) != 2 || deleted[0].MaxAge >= 0 || deleted[1].MaxAge >= 0 {
		t.Fatalf("canonical continuation %s purge = %#v", target, deleted)
	}
}

func TestSAMLRegisterCanonicalSplitsProtocolEntryFromSLOContinuation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	runtime, _, _ := seedCanonicalIDPFlow(t, nil)
	handler, _, _, _ := newSAMLSSOTestFixture(t, config.SAML2ServiceProvider{
		EntityID: "https://sp.example.com/saml/metadata", ACSURL: "https://sp.example.com/saml/acs",
	}, nil)
	router := gin.New()
	handler.Register(router, runtime)

	routes := router.Routes()
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/saml/metadata"}, {http.MethodGet, "/saml/sso"},
		{http.MethodGet, frontendSAMLLogoutPath}, {http.MethodPost, frontendSAMLLogoutPath},
	} {
		if !slices.ContainsFunc(routes, func(info gin.RouteInfo) bool {
			return info.Method == route.method && info.Path == route.path
		}) {
			t.Fatalf("canonical SAML route missing: %s %s", route.method, route.path)
		}
	}

	for _, target := range []string{"/saml/sso", frontendSAMLLogoutPath + "?SAMLRequest=opaque"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		if response.Code == http.StatusConflict {
			t.Fatalf("canonical SAML protocol entry %s rejected absent envelope", target)
		}
	}

	assertCanonicalContinuationRejectsAbsentEnvelope(
		t, router, frontendSAMLLogoutPath+"?SAMLResponse=opaque",
	)
}
