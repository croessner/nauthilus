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

func TestCanonicalMiddlewareCreatesProtocolEntrySession(t *testing.T) {
	t.Parallel()
	gin.SetMode(gin.TestMode)

	mini := miniredis.RunT(t)
	runtime := newCanonicalMiddlewareRuntime(t, mini, "canonical-middleware")
	called := false
	router := gin.New()
	router.GET("/oidc/authorize", CanonicalMiddleware(runtime, CanonicalProtocolEntry), func(ctx *gin.Context) {
		called = true

		if GetCanonicalSession(ctx) == nil {
			t.Fatal("protocol entry did not receive canonical session")
		}

		ctx.Status(http.StatusNoContent)
	})

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil))

	if !called || writer.Code != http.StatusNoContent {
		t.Fatalf("protocol entry: called=%t status=%d", called, writer.Code)
	}

	if cookies := writer.Result().Cookies(); len(cookies) != 3 || cookies[2].Name != definitions.SecureDataCookieName {
		t.Fatalf("protocol entry cookies = %#v, want two purge cookies then one canonical envelope", cookies)
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
