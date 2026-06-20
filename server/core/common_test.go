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
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
)

func TestClearBrowserCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("sets only secure data cookie", func(t *testing.T) {
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

	if len(cookies) != 1 {
		t.Fatalf("expected exactly 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != definitions.SecureDataCookieName {
		t.Errorf("unexpected cookie %q", cookie.Name)
	}

	if cookie.MaxAge != -1 {
		t.Errorf("cookie %q MaxAge=%d, want -1", cookie.Name, cookie.MaxAge)
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
