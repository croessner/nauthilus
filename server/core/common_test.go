// Copyright (C) 2025 Christian Rößner
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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
)

func TestClearBrowserCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("deletes both encrypted browser cookies", func(t *testing.T) {
		util.SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

		ctx, writer := newClearBrowserCookiesContext()
		ClearBrowserCookies(ctx)

		assertOnlySecureDataCookieDeleted(t, writer.Result().Cookies())
	})

	t.Run("secure flag based on dev mode", func(t *testing.T) {
		for _, test := range clearBrowserCookiesSecureCases() {
			t.Run(test.name, func(t *testing.T) {
				util.SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: test.devMode})

				ctx, writer := newClearBrowserCookiesContext()
				ClearBrowserCookies(ctx)

				assertCookieSecureFlag(t, writer.Result().Cookies(), test.wantSecure)
			})
		}
	})
}

func TestClearBrowserCookiesRemainsFinalAtResponseCommit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, test := range clearBrowserCookiesCommitCases() {
		t.Run(test.name, func(t *testing.T) {
			assertBrowserCookieDeletionFinal(t, test)
		})
	}
}

type clearBrowserCookiesCommitCase struct {
	respond      func(*gin.Context)
	name         string
	wantStatus   int
	explicitSave bool
}

func clearBrowserCookiesCommitCases() []clearBrowserCookiesCommitCase {
	return []clearBrowserCookiesCommitCase{
		{
			name:       "redirect logout",
			wantStatus: http.StatusFound,
			respond: func(ctx *gin.Context) {
				ctx.Redirect(http.StatusFound, "/logged_out")
			},
		},
		{
			name:       "front-channel logout body",
			wantStatus: http.StatusOK,
			respond: func(ctx *gin.Context) {
				ctx.String(http.StatusOK, "logged out")
			},
		},
		{
			name:       "logout error response",
			wantStatus: http.StatusInternalServerError,
			respond: func(ctx *gin.Context) {
				ctx.String(http.StatusInternalServerError, "logout failed")
			},
		},
		{
			name:         "saved session rotation followed by logout",
			wantStatus:   http.StatusFound,
			explicitSave: true,
			respond: func(ctx *gin.Context) {
				ctx.Redirect(http.StatusFound, "/logged_out")
			},
		},
	}
}

func assertBrowserCookieDeletionFinal(t *testing.T, test clearBrowserCookiesCommitCase) {
	t.Helper()

	env := &config.EnvironmentSettings{DevMode: true}
	util.SetDefaultEnvironment(env)

	router := gin.New()
	router.Use(cookie.Middleware([]byte("0123456789abcdef0123456789abcdef"), nil, env))
	router.GET("/logout", func(ctx *gin.Context) {
		mgr := cookie.MustGetManager(ctx)
		mgr.Set(definitions.SessionKeyIDPFlowID, "flow-left-after-cleaner")
		mgr.Set(definitions.SessionKeyRequireMFAFlow, true)

		if test.explicitSave {
			if err := mgr.Save(ctx); err != nil {
				t.Errorf("save rotating session: %v", err)
			}
		}

		ClearBrowserCookies(ctx)
		test.respond(ctx)
	})

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/logout", nil))

	if writer.Code != test.wantStatus {
		t.Fatalf("status = %d, want %d", writer.Code, test.wantStatus)
	}

	assertNoSecureCookieAfterDeletion(t, writer.Result().Cookies())
}

// assertNoSecureCookieAfterDeletion verifies that response finalization cannot
// append a live session after an explicit browser-cookie deletion.
func assertNoSecureCookieAfterDeletion(t *testing.T, cookies []*http.Cookie) {
	t.Helper()

	deletionSeen := map[string]bool{
		definitions.SecureDataCookieName:       false,
		definitions.WebAuthnCeremonyCookieName: false,
	}

	for _, responseCookie := range cookies {
		if _, tracked := deletionSeen[responseCookie.Name]; !tracked {
			continue
		}

		if responseCookie.MaxAge < 0 && responseCookie.Value == "" {
			deletionSeen[responseCookie.Name] = true

			continue
		}

		if deletionSeen[responseCookie.Name] {
			t.Fatalf("live %s cookie was emitted after deletion: MaxAge=%d", responseCookie.Name, responseCookie.MaxAge)
		}
	}

	for cookieName, seen := range deletionSeen {
		if !seen {
			t.Fatalf("%s cookie deletion was not emitted", cookieName)
		}
	}
}

type clearBrowserCookiesSecureCase struct {
	name       string
	devMode    bool
	wantSecure bool
}

// clearBrowserCookiesSecureCases returns secure-cookie environment cases.
func clearBrowserCookiesSecureCases() []clearBrowserCookiesSecureCase {
	return []clearBrowserCookiesSecureCase{
		{
			name:       "secure cookies in non-dev mode",
			devMode:    false,
			wantSecure: true,
		},
		{
			name:       "insecure cookies in dev mode",
			devMode:    true,
			wantSecure: false,
		},
	}
}

// newClearBrowserCookiesContext creates a request context for cookie clearing.
func newClearBrowserCookiesContext() (*gin.Context, *httptest.ResponseRecorder) {
	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	return ctx, writer
}

// assertOnlySecureDataCookieDeleted verifies the expected deletion cookie.
func assertOnlySecureDataCookieDeleted(t *testing.T, cookies []*http.Cookie) {
	t.Helper()

	if len(cookies) != 2 {
		t.Fatalf("expected exactly 2 cookies, got %d", len(cookies))
	}

	wantNames := map[string]bool{
		definitions.SecureDataCookieName:       false,
		definitions.WebAuthnCeremonyCookieName: false,
	}
	for _, responseCookie := range cookies {
		if _, ok := wantNames[responseCookie.Name]; !ok {
			t.Errorf("unexpected cookie %q", responseCookie.Name)
		}

		wantNames[responseCookie.Name] = true

		if responseCookie.MaxAge != -1 {
			t.Errorf("cookie %q MaxAge=%d, want -1", responseCookie.Name, responseCookie.MaxAge)
		}
	}
}

// assertCookieSecureFlag verifies that all cookies use the expected Secure flag.
func assertCookieSecureFlag(t *testing.T, cookies []*http.Cookie, wantSecure bool) {
	t.Helper()

	if len(cookies) == 0 {
		t.Fatalf("expected cookies to be set")
	}

	for _, cookie := range cookies {
		if cookie.Secure != wantSecure {
			t.Errorf("cookie %q secure=%v, want %v", cookie.Name, cookie.Secure, wantSecure)
		}
	}
}

func TestSessionCleaner_RemovesLegacyLanguageFromSecureSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	writer := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(writer)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyLang:    "de",
		definitions.SessionKeyAccount: "user@example.com",
	}}
	ctx.Set(definitions.CtxSecureDataKey, mgr)

	SessionCleaner(ctx)

	if _, ok := mgr.Get(definitions.SessionKeyLang); ok {
		t.Fatalf("expected %q to be removed from secure session", definitions.SessionKeyLang)
	}
}

func TestSessionCleanerDeletesDedicatedWebAuthnCeremonyCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	env := &config.EnvironmentSettings{DevMode: true}
	util.SetDefaultEnvironment(env)

	router := gin.New()
	router.Use(cookie.Middleware([]byte("0123456789abcdef0123456789abcdef"), nil, env))
	router.GET("/cleanup", func(ctx *gin.Context) {
		mgr := cookie.MustGetManager(ctx)
		mgr.Set(definitions.SessionKeyAccount, "user@example.test")
		mgr.Set(definitions.SessionKeyWebAuthnCeremony, "dedicated-reference")

		if err := mgr.Save(ctx); err != nil {
			t.Fatalf("save browser session: %v", err)
		}

		SessionCleaner(ctx)
		ctx.Status(http.StatusOK)
	})

	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "/cleanup", nil))
	assertNoSecureCookieAfterDeletion(t, writer.Result().Cookies())
}
