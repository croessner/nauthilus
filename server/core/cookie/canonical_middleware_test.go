// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func TestCanonicalMiddlewareCreatesEntrySession(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	for _, testCase := range []struct {
		name string
		path string
		mode CanonicalMode
	}{
		{name: "protocol", path: "/oidc/authorize", mode: CanonicalProtocolEntry},
		{name: "self_service", path: "/mfa/register/home/de", mode: CanonicalSelfServiceEntry},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			mini := miniredis.RunT(t)
			runtime := newCanonicalMiddlewareRuntime(t, mini, "canonical-entry-"+testCase.name)
			called := false
			router := gin.New()
			router.GET(testCase.path, CanonicalMiddleware(runtime, testCase.mode), func(ctx *gin.Context) {
				called = true

				if GetCanonicalSession(ctx) == nil {
					t.Fatalf("%s entry did not receive canonical session", testCase.name)
				}

				ctx.Status(http.StatusNoContent)
			})

			writer := httptest.NewRecorder()
			router.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, testCase.path, nil))

			if !called || writer.Code != http.StatusNoContent {
				t.Fatalf("%s entry: called=%t status=%d", testCase.name, called, writer.Code)
			}

			cookies := writer.Result().Cookies()
			if len(cookies) != 3 || cookies[2].Name != definitions.SecureDataCookieName {
				t.Fatalf("%s entry cookies = %#v, want purge pair and canonical envelope", testCase.name, cookies)
			}
		})
	}
}

func TestCanonicalMiddlewareRejectsLegacyContinuationBeforeHandler(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	mini := miniredis.RunT(t)
	runtime := newCanonicalMiddlewareRuntime(t, mini, "canonical-middleware-reject")
	legacyCodec := NewSecureCodec([]byte("canonical-middleware-test-secret-32bytes"))

	legacy, err := legacyCodec.Encode(definitions.SecureDataCookieName, map[string]any{"idp_flow_id": "legacy"})
	if err != nil {
		t.Fatalf("encode legacy cookie: %v", err)
	}

	called := false
	router := gin.New()
	router.GET("/login", CanonicalMiddleware(runtime, CanonicalContinuation), func(ctx *gin.Context) {
		called = true

		ctx.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/login", nil)
	request.AddCookie(&http.Cookie{Name: definitions.SecureDataCookieName, Value: legacy})

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)

	if called || writer.Code != http.StatusConflict {
		t.Fatalf("legacy continuation: called=%t status=%d", called, writer.Code)
	}

	assertCanonicalPurgeCookies(t, writer)
}

func TestCanonicalMiddlewareDoesNotRunHandlerWhenRedisCreateFails(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	mini := miniredis.RunT(t)
	runtime := newCanonicalMiddlewareRuntime(t, mini, "canonical-middleware-failure")
	mini.Close()

	called := false
	router := gin.New()
	router.GET("/saml/sso", CanonicalMiddleware(runtime, CanonicalProtocolEntry), func(ctx *gin.Context) {
		called = true

		ctx.Status(http.StatusNoContent)
	})

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/saml/sso", nil))

	if called || writer.Code != http.StatusServiceUnavailable {
		t.Fatalf("Redis failure: called=%t status=%d", called, writer.Code)
	}

	assertCanonicalPurgeCookies(t, writer)
}

func newCanonicalMiddlewareRuntime(t *testing.T, mini *miniredis.Miniredis, prefix string) *CanonicalRuntime {
	t.Helper()

	runtime, err := NewCanonicalRuntime(
		[]byte("canonical-middleware-test-secret-32bytes"), 1,
		redis.NewClient(&redis.Options{Addr: mini.Addr()}), prefix,
		canonicalRuntimeClock{now: time.Date(2026, time.August, 17, 12, 0, 0, 0, time.UTC)},
		sessionstate.NewRandomHandleGenerator(nil), false,
	)
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}

	return runtime
}

func assertCanonicalPurgeCookies(t *testing.T, writer *httptest.ResponseRecorder) {
	t.Helper()

	cookies := writer.Result().Cookies()
	if len(cookies) != 2 || cookies[0].MaxAge >= 0 || cookies[1].MaxAge >= 0 {
		t.Fatalf("purge cookies = %#v, want two browser deletions", cookies)
	}
}
