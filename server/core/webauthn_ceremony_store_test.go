// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestWebAuthnCeremonyStoreKeepsOversizedReferenceOutOfPrimaryCookie(t *testing.T) { //nolint:funlen // Keeps the size regression visible end to end.
	gin.SetMode(gin.TestMode)

	secret := []byte("test-secret-32bytes-1234567890!!")
	env := &config.EnvironmentSettings{DevMode: true}
	util.SetDefaultEnvironment(env)
	paddingLength := legacyWebAuthnReferenceOverflowPadding(t, env)
	db, mock := redismock.NewClientMock()
	deps := AuthDeps{
		Cfg:   &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}}},
		Redis: rediscli.NewTestClient(db),
	}

	store, err := newWebAuthnCeremonyStore(deps)
	if err != nil {
		t.Fatalf("new ceremony store: %v", err)
	}

	var (
		storeErr           error
		baselineCookieSize int
	)

	router := gin.New()
	router.Use(cookie.Middleware(secret, deps.Cfg, env))
	router.GET("/login/webauthn/begin", func(ctx *gin.Context) {
		mgr := cookie.MustGetManager(ctx)
		mgr.Set(definitions.SessionKeyIDPState, strings.Repeat("x", paddingLength))

		if saveErr := mgr.Save(ctx); saveErr != nil {
			t.Fatalf("primary session must fit before WebAuthn begins: %v", saveErr)
		}

		baselineCookieSize = latestSetCookieSize(ctx.Writer.Header().Values("Set-Cookie"), definitions.SecureDataCookieName)

		mock.Regexp().ExpectSet("test:webauthn:ceremony:.*", ".*", webAuthnCeremonyTTL).SetVal("OK")

		storeErr = store.Store(ctx, mgr, webAuthnCeremonyLogin, &webauthn.SessionData{Challenge: "challenge"})
		ctx.Status(http.StatusOK)
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/login/webauthn/begin", nil))

	if storeErr != nil {
		t.Fatalf("WebAuthn ceremony reference must not overflow the primary cookie: %v", storeErr)
	}

	responseCookies := recorder.Result().Cookies()
	primaryCookie := latestResponseCookie(responseCookies, definitions.SecureDataCookieName)

	ceremonyCookie := latestResponseCookie(responseCookies, definitions.WebAuthnCeremonyCookieName)
	if primaryCookie == nil || ceremonyCookie == nil {
		t.Fatalf("expected primary and dedicated ceremony cookies, got %#v", responseCookies)
	}

	if got := len(primaryCookie.String()); got != baselineCookieSize {
		t.Fatalf("primary cookie size changed from %d to %d bytes", baselineCookieSize, got)
	}

	if got := len(ceremonyCookie.String()); got >= 512 {
		t.Fatalf("dedicated ceremony cookie is %d bytes, want below 512", got)
	}

	if ceremonyCookie.Path != "/" || ceremonyCookie.MaxAge != int(webAuthnCeremonyTTL/time.Second) ||
		ceremonyCookie.HttpOnly != true || ceremonyCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected dedicated ceremony cookie properties: %#v", ceremonyCookie)
	}

	assertDedicatedCeremonyCookieContents(t, secret, env, primaryCookie, ceremonyCookie)
}

// latestSetCookieSize returns the serialized size of the latest named response cookie.
func latestSetCookieSize(headers []string, cookieName string) int {
	prefix := cookieName + "="

	for index := len(headers) - 1; index >= 0; index-- {
		if strings.HasPrefix(headers[index], prefix) {
			return len(headers[index])
		}
	}

	return 0
}

// latestResponseCookie returns the final response representation for one cookie name.
func latestResponseCookie(cookies []*http.Cookie, cookieName string) *http.Cookie {
	for index := len(cookies) - 1; index >= 0; index-- {
		if cookies[index].Name == cookieName {
			return cookies[index]
		}
	}

	return nil
}

// assertDedicatedCeremonyCookieContents proves primary isolation and the tiny cookie contract.
func assertDedicatedCeremonyCookieContents(
	t *testing.T,
	secret []byte,
	env config.Environment,
	primaryCookie *http.Cookie,
	ceremonyCookie *http.Cookie,
) {
	t.Helper()

	primary := cookie.NewSecureManager(secret, definitions.SecureDataCookieName, nil, env)
	loadResponseCookie(t, primary, primaryCookie)

	if primary.HasKey(definitions.SessionKeyWebAuthnCeremony) {
		t.Fatal("new ceremony reference leaked into the primary cookie")
	}

	dedicated := cookie.NewSecureManager(secret, definitions.WebAuthnCeremonyCookieName, nil, env)
	loadResponseCookie(t, dedicated, ceremonyCookie)

	if keys := dedicated.Keys(); len(keys) != 1 || keys[0] != definitions.SessionKeyWebAuthnCeremony {
		t.Fatalf("dedicated cookie keys = %#v, want only ceremony reference", keys)
	}

	if reference := dedicated.GetString(definitions.SessionKeyWebAuthnCeremony, ""); len(reference) != 32 {
		t.Fatalf("dedicated ceremony reference length = %d, want 32", len(reference))
	}
}

// loadResponseCookie loads one response cookie into a concrete secure manager.
func loadResponseCookie(t *testing.T, mgr *cookie.SecureManager, responseCookie *http.Cookie) {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(responseCookie)

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = request

	if err := mgr.Load(ctx); err != nil {
		t.Fatalf("load response cookie %q: %v", responseCookie.Name, err)
	}
}

// legacyWebAuthnReferenceOverflowPadding finds a deterministic payload size that
// fits before the legacy ceremony reference is added and crosses the hard limit after it.
func legacyWebAuthnReferenceOverflowPadding(t *testing.T, env config.Environment) int {
	t.Helper()

	for paddingLength := 2500; paddingLength < 3200; paddingLength++ {
		mgr := cookie.NewSecureManager([]byte("test-secret-32bytes-1234567890!!"), definitions.SecureDataCookieName, nil, env)
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

		mgr.Set(definitions.SessionKeyIDPState, strings.Repeat("x", paddingLength))

		if err := mgr.Save(ctx); err != nil {
			continue
		}

		mgr.Set(definitions.SessionKeyWebAuthnCeremony, strings.Repeat("r", 32))

		if err := mgr.Save(ctx); err != nil {
			return paddingLength
		}
	}

	t.Fatal("could not construct a primary cookie that only the legacy ceremony reference overflows")

	return 0
}

func TestWebAuthnCeremonyStoreConsumesLegacyReferenceOnce(t *testing.T) {
	for _, kind := range []string{webAuthnCeremonyLogin, webAuthnCeremonyRegister} {
		t.Run(kind, func(t *testing.T) {
			testWebAuthnCeremonyStoreConsumesLegacyReferenceOnce(t, kind)
		})
	}
}

// testWebAuthnCeremonyStoreConsumesLegacyReferenceOnce verifies one legacy compatibility path.
func testWebAuthnCeremonyStoreConsumesLegacyReferenceOnce(t *testing.T, kind string) { //nolint:funlen // Keeps the legacy store-take-replay lifecycle intact.
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, mock := redismock.NewClientMock()
	deps := AuthDeps{
		Cfg:   &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}}},
		Redis: rediscli.NewTestClient(db),
	}
	store, err := newWebAuthnCeremonyStore(deps)
	if err != nil {
		t.Fatalf("new ceremony store: %v", err)
	}

	mgr := &mockCookieManager{data: make(map[string]any)}
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/login/webauthn/begin", nil)

	mock.Regexp().ExpectSet("test:webauthn:ceremony:.*", ".*", webAuthnCeremonyTTL).SetVal("OK")

	if err = store.Store(ctx, mgr, kind, &webauthn.SessionData{Challenge: "challenge"}); err != nil {
		t.Fatalf("store ceremony: %v", err)
	}

	reference := mgr.GetString(definitions.SessionKeyWebAuthnCeremony, "")
	if reference == "" {
		t.Fatal("expected opaque ceremony reference in the browser session")
	}

	payload, err := jsonIter.Marshal(webAuthnCeremonyRecord{
		Kind:        kind,
		Binding:     webAuthnCeremonyBinding(mgr, kind),
		SessionData: webauthn.SessionData{Challenge: "challenge"},
	})
	if err != nil {
		t.Fatalf("marshal expected ceremony: %v", err)
	}

	mock.ExpectGetDel(store.redisKey(reference)).SetVal(string(payload))

	sessionData, err := store.Take(ctx, mgr, kind)
	if err != nil {
		t.Fatalf("take ceremony: %v", err)
	}

	if sessionData.Challenge != "challenge" {
		t.Fatalf("challenge = %q, want challenge", sessionData.Challenge)
	}

	if mgr.GetString(definitions.SessionKeyWebAuthnCeremony, "") != "" {
		t.Fatal("consumed ceremony reference remained in browser session")
	}

	mgr.Set(definitions.SessionKeyWebAuthnCeremony, reference)
	mock.ExpectGetDel(store.redisKey(reference)).RedisNil()

	if _, err = store.Take(ctx, mgr, kind); err == nil {
		t.Fatal("expected a consumed ceremony reference to be rejected")
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations: %v", err)
	}
}

func TestWebAuthnCeremonyStoreConsumesDedicatedReferenceOnce(t *testing.T) {
	for _, kind := range []string{webAuthnCeremonyLogin, webAuthnCeremonyRegister} {
		t.Run(kind, func(t *testing.T) {
			testWebAuthnCeremonyStoreConsumesDedicatedReferenceOnce(t, kind)
		})
	}
}

// testWebAuthnCeremonyStoreConsumesDedicatedReferenceOnce verifies the real middleware path.
func testWebAuthnCeremonyStoreConsumesDedicatedReferenceOnce(t *testing.T, kind string) { //nolint:funlen // Covers the complete real middleware lifecycle.
	t.Helper()
	gin.SetMode(gin.TestMode)

	env := &config.EnvironmentSettings{DevMode: true}
	util.SetDefaultEnvironment(env)

	db, mock := redismock.NewClientMock()
	deps := AuthDeps{
		Cfg:   &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}}},
		Redis: rediscli.NewTestClient(db),
	}

	store, err := newWebAuthnCeremonyStore(deps)
	if err != nil {
		t.Fatalf("new ceremony store: %v", err)
	}

	var handlerErr error

	router := gin.New()
	router.Use(cookie.Middleware([]byte("test-secret-32bytes-1234567890!!"), deps.Cfg, env))
	router.GET("/ceremony", func(ctx *gin.Context) {
		mgr := cookie.MustGetManager(ctx)
		mgr.Set(definitions.SessionKeyMFAFactorAccount, "user@example.test")
		mgr.Set(definitions.SessionKeyMFAFactorUniqueUserID, "user-id")
		mgr.Set(definitions.SessionKeyAccount, "user@example.test")
		mgr.Set(definitions.SessionKeyUniqueUserID, "user-id")

		mock.Regexp().ExpectSet("test:webauthn:ceremony:.*", ".*", webAuthnCeremonyTTL).SetVal("OK")

		if handlerErr = store.Store(ctx, mgr, kind, &webauthn.SessionData{Challenge: "challenge"}); handlerErr != nil {
			return
		}

		reference := mgr.GetString(definitions.SessionKeyWebAuthnCeremony, "")

		payload, marshalErr := jsonIter.Marshal(webAuthnCeremonyRecord{
			Kind:        kind,
			Binding:     webAuthnCeremonyBinding(mgr, kind),
			SessionData: webauthn.SessionData{Challenge: "challenge"},
		})
		if marshalErr != nil {
			handlerErr = marshalErr

			return
		}

		mock.ExpectGetDel(store.redisKey(reference)).SetVal(string(payload))

		_, handlerErr = store.Take(ctx, mgr, kind)
		if handlerErr != nil {
			return
		}

		mgr.Set(definitions.SessionKeyWebAuthnCeremony, reference)
		mock.ExpectGetDel(store.redisKey(reference)).RedisNil()

		if _, replayErr := store.Take(ctx, mgr, kind); replayErr == nil {
			handlerErr = errors.New("expected dedicated reference replay to fail")
		}
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/ceremony", nil))

	if handlerErr != nil {
		t.Fatal(handlerErr)
	}

	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations: %v", err)
	}
}

type multiReferenceCookieManager struct {
	*mockCookieManager
	references []string
}

// WebAuthnCeremonyReferences returns both rolling-compatible test references.
func (m *multiReferenceCookieManager) WebAuthnCeremonyReferences() []string {
	return append([]string(nil), m.references...)
}

func TestWebAuthnCeremonyStoreCleansDedicatedAndLegacyRedisReferences(t *testing.T) {
	t.Run("replacement", func(t *testing.T) {
		store, ctx, mock := newTestWebAuthnCeremonyStore(t)
		mgr := &multiReferenceCookieManager{
			mockCookieManager: &mockCookieManager{data: map[string]any{
				definitions.SessionKeyWebAuthnCeremony: "legacy-reference",
			}},
			references: []string{"dedicated-reference", "legacy-reference"},
		}

		mock.Regexp().ExpectSet("test:webauthn:ceremony:.*", ".*", webAuthnCeremonyTTL).SetVal("OK")
		mock.ExpectDel(store.redisKey("dedicated-reference")).SetVal(1)
		mock.ExpectDel(store.redisKey("legacy-reference")).SetVal(1)

		if err := store.Store(ctx, mgr, webAuthnCeremonyLogin, &webauthn.SessionData{Challenge: "replacement"}); err != nil {
			t.Fatalf("replace ceremony: %v", err)
		}

		assertRedisExpectations(t, mock)
	})

	t.Run("take", func(t *testing.T) {
		store, ctx, mock := newTestWebAuthnCeremonyStore(t)
		mgr := &multiReferenceCookieManager{
			mockCookieManager: &mockCookieManager{data: map[string]any{
				definitions.SessionKeyWebAuthnCeremony: "legacy-reference",
			}},
			references: []string{"dedicated-reference", "legacy-reference"},
		}
		payload := mustCeremonyPayload(t, mgr, webAuthnCeremonyLogin, webAuthnCeremonyLogin)

		mock.ExpectGetDel(store.redisKey("dedicated-reference")).SetVal(string(payload))
		mock.ExpectDel(store.redisKey("legacy-reference")).SetVal(1)

		if _, err := store.Take(ctx, mgr, webAuthnCeremonyLogin); err != nil {
			t.Fatalf("take ceremony: %v", err)
		}

		assertRedisExpectations(t, mock)
	})

	t.Run("delete", func(t *testing.T) {
		store, ctx, mock := newTestWebAuthnCeremonyStore(t)
		mgr := &multiReferenceCookieManager{
			mockCookieManager: &mockCookieManager{data: map[string]any{
				definitions.SessionKeyWebAuthnCeremony: "legacy-reference",
			}},
			references: []string{"dedicated-reference", "legacy-reference"},
		}

		mock.ExpectDel(store.redisKey("dedicated-reference")).SetVal(1)
		mock.ExpectDel(store.redisKey("legacy-reference")).SetVal(1)
		DeleteWebAuthnCeremony(ctx, store.deps, mgr)

		if mgr.HasKey(definitions.SessionKeyWebAuthnCeremony) {
			t.Fatal("browser reference survived delete")
		}

		assertRedisExpectations(t, mock)
	})
}

type webAuthnCeremonyInvalidRecordCase struct {
	name          string
	payload       func(*testing.T, cookie.Manager) []byte
	configure     func(cookie.Manager)
	wantErrorText string
}

var webAuthnCeremonyInvalidRecordCases = []webAuthnCeremonyInvalidRecordCase{
	{
		name: "cross kind",
		payload: func(t *testing.T, mgr cookie.Manager) []byte {
			return mustCeremonyPayload(t, mgr, webAuthnCeremonyRegister, webAuthnCeremonyLogin)
		},
		wantErrorText: "kind mismatch",
	},
	{
		name: "cross flow",
		configure: func(mgr cookie.Manager) {
			mgr.Set(definitions.SessionKeyIDPFlowID, "current-flow")
		},
		payload: func(t *testing.T, _ cookie.Manager) []byte {
			other := &mockCookieManager{data: map[string]any{definitions.SessionKeyIDPFlowID: "other-flow"}}

			return mustCeremonyPayload(t, other, webAuthnCeremonyLogin, webAuthnCeremonyLogin)
		},
		wantErrorText: "binding mismatch",
	},
	{
		name: "cross identity",
		configure: func(mgr cookie.Manager) {
			mgr.Set(definitions.SessionKeyMFAFactorAccount, "current@example.test")
			mgr.Set(definitions.SessionKeyMFAFactorUniqueUserID, "current-id")
		},
		payload: func(t *testing.T, _ cookie.Manager) []byte {
			other := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyMFAFactorAccount:      "other@example.test",
				definitions.SessionKeyMFAFactorUniqueUserID: "other-id",
			}}

			return mustCeremonyPayload(t, other, webAuthnCeremonyLogin, webAuthnCeremonyLogin)
		},
		wantErrorText: "binding mismatch",
	},
	{
		name: "decode failure",
		payload: func(_ *testing.T, _ cookie.Manager) []byte {
			return []byte("not-json")
		},
		wantErrorText: "decode webauthn ceremony",
	},
}

func TestWebAuthnCeremonyStoreRejectsMismatchedOrInvalidRecords(t *testing.T) {
	for _, test := range webAuthnCeremonyInvalidRecordCases {
		t.Run(test.name, func(t *testing.T) {
			store, ctx, mock := newTestWebAuthnCeremonyStore(t)

			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyWebAuthnCeremony: "reference",
			}}
			if test.configure != nil {
				test.configure(mgr)
			}

			mock.ExpectGetDel(store.redisKey("reference")).SetVal(string(test.payload(t, mgr)))

			_, err := store.Take(ctx, mgr, webAuthnCeremonyLogin)
			if err == nil || !strings.Contains(err.Error(), test.wantErrorText) {
				t.Fatalf("Take() error = %v, want %q", err, test.wantErrorText)
			}

			if mgr.HasKey(definitions.SessionKeyWebAuthnCeremony) {
				t.Fatal("rejected ceremony reference remained in browser state")
			}

			assertRedisExpectations(t, mock)
		})
	}
}

func TestWebAuthnCeremonyStoreCleansFailures(t *testing.T) {
	t.Run("Redis store failure", testWebAuthnCeremonyRedisStoreFailure)
	t.Run("browser save failure", testWebAuthnCeremonyBrowserSaveFailure)
	t.Run("Redis load failure", testWebAuthnCeremonyRedisLoadFailure)
	t.Run("replacement cleanup failure", testWebAuthnCeremonyReplacementCleanupFailure)
}

func testWebAuthnCeremonyRedisStoreFailure(t *testing.T) {
	store, ctx, mock := newTestWebAuthnCeremonyStore(t)
	mgr := &mockCookieManager{data: make(map[string]any)}

	mock.Regexp().ExpectSet("test:webauthn:ceremony:.*", ".*", webAuthnCeremonyTTL).SetErr(errors.New("Redis unavailable"))

	if err := store.Store(ctx, mgr, webAuthnCeremonyLogin, &webauthn.SessionData{Challenge: "challenge"}); err == nil {
		t.Fatal("expected Redis store failure")
	}

	if mgr.HasKey(definitions.SessionKeyWebAuthnCeremony) {
		t.Fatal("Redis store failure left a browser reference")
	}

	assertRedisExpectations(t, mock)
}

func testWebAuthnCeremonyBrowserSaveFailure(t *testing.T) {
	store, ctx, mock := newTestWebAuthnCeremonyStore(t)
	mgr := &mockCookieManager{data: make(map[string]any), saveErr: errors.New("browser save failed")}

	mock.Regexp().ExpectSet("test:webauthn:ceremony:.*", ".*", webAuthnCeremonyTTL).SetVal("OK")
	mock.Regexp().ExpectDel("test:webauthn:ceremony:.*").SetVal(1)

	if err := store.Store(ctx, mgr, webAuthnCeremonyLogin, &webauthn.SessionData{Challenge: "challenge"}); err == nil {
		t.Fatal("expected browser save failure")
	}

	if mgr.HasKey(definitions.SessionKeyWebAuthnCeremony) {
		t.Fatal("browser save failure left an in-memory reference")
	}

	assertRedisExpectations(t, mock)
}

func testWebAuthnCeremonyRedisLoadFailure(t *testing.T) {
	store, ctx, mock := newTestWebAuthnCeremonyStore(t)
	mgr := &mockCookieManager{data: map[string]any{definitions.SessionKeyWebAuthnCeremony: "reference"}}

	mock.ExpectGetDel(store.redisKey("reference")).SetErr(errors.New("Redis unavailable"))

	if _, err := store.Take(ctx, mgr, webAuthnCeremonyLogin); err == nil {
		t.Fatal("expected Redis load failure")
	}

	if mgr.HasKey(definitions.SessionKeyWebAuthnCeremony) {
		t.Fatal("Redis load failure left an in-memory reference")
	}

	assertRedisExpectations(t, mock)
}

func testWebAuthnCeremonyReplacementCleanupFailure(t *testing.T) {
	store, ctx, mock := newTestWebAuthnCeremonyStore(t)
	mgr := &mockCookieManager{data: map[string]any{definitions.SessionKeyWebAuthnCeremony: "previous-reference"}}

	mock.Regexp().ExpectSet("test:webauthn:ceremony:.*", ".*", webAuthnCeremonyTTL).SetVal("OK")
	mock.ExpectDel(store.redisKey("previous-reference")).SetErr(errors.New("cleanup failed"))
	mock.ExpectDel(store.redisKey("previous-reference")).SetVal(1)
	mock.Regexp().ExpectDel("test:webauthn:ceremony:.*").SetVal(1)

	if err := store.Store(ctx, mgr, webAuthnCeremonyLogin, &webauthn.SessionData{Challenge: "replacement"}); err == nil {
		t.Fatal("expected replacement cleanup failure")
	}

	if mgr.HasKey(definitions.SessionKeyWebAuthnCeremony) {
		t.Fatal("replacement cleanup failure left an in-memory reference")
	}

	assertRedisExpectations(t, mock)
}

func TestWebAuthnCeremonyStoreRejectsTamperedDedicatedCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	env := &config.EnvironmentSettings{DevMode: true}
	util.SetDefaultEnvironment(env)

	store, _, mock := newTestWebAuthnCeremonyStore(t)

	var takeErr error

	router := gin.New()
	router.Use(cookie.Middleware([]byte("test-secret-32bytes-1234567890!!"), store.deps.Cfg, env))
	router.GET("/ceremony", func(ctx *gin.Context) {
		_, takeErr = store.Take(ctx, cookie.MustGetManager(ctx), webAuthnCeremonyLogin)
		ctx.Status(http.StatusBadRequest)
	})

	request := httptest.NewRequest(http.MethodGet, "/ceremony", nil)
	request.AddCookie(&http.Cookie{
		Name:  definitions.WebAuthnCeremonyCookieName,
		Value: "tampered-cookie-value",
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if takeErr == nil || !strings.Contains(takeErr.Error(), "missing webauthn ceremony reference") {
		t.Fatalf("Take() error = %v, want missing reference", takeErr)
	}

	deleted := latestResponseCookie(recorder.Result().Cookies(), definitions.WebAuthnCeremonyCookieName)
	if deleted == nil || deleted.MaxAge >= 0 || deleted.Value != "" {
		t.Fatalf("tampered dedicated cookie was not deleted: %#v", deleted)
	}

	assertRedisExpectations(t, mock)
}

// newTestWebAuthnCeremonyStore constructs a Redis-mocked ceremony store and request.
func newTestWebAuthnCeremonyStore(t *testing.T) (*webAuthnCeremonyStore, *gin.Context, redismock.ClientMock) {
	t.Helper()

	db, mock := redismock.NewClientMock()
	deps := AuthDeps{
		Cfg:   &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}}},
		Redis: rediscli.NewTestClient(db),
	}

	store, err := newWebAuthnCeremonyStore(deps)
	if err != nil {
		t.Fatalf("new ceremony store: %v", err)
	}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/ceremony", nil)

	return store, ctx, mock
}

// mustCeremonyPayload encodes one test ceremony record with the selected binding.
func mustCeremonyPayload(t *testing.T, mgr cookie.Manager, recordKind string, bindingKind string) []byte {
	t.Helper()

	payload, err := jsonIter.Marshal(webAuthnCeremonyRecord{
		Kind:        recordKind,
		Binding:     webAuthnCeremonyBinding(mgr, bindingKind),
		SessionData: webauthn.SessionData{Challenge: "challenge"},
	})
	if err != nil {
		t.Fatalf("marshal ceremony payload: %v", err)
	}

	return payload
}

// assertRedisExpectations verifies the complete Redis interaction contract.
func assertRedisExpectations(t *testing.T, mock redismock.ClientMock) {
	t.Helper()

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations: %v", err)
	}
}
