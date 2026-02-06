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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

func TestClearBrowserCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("sets only secure data cookie", func(t *testing.T) {
		util.SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

		writer := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(writer)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

		ClearBrowserCookies(ctx)

		cookies := writer.Result().Cookies()

		if len(cookies) != 1 {
			t.Fatalf("expected exactly 1 cookie, got %d", len(cookies))
		}

		expectedNames := map[string]bool{
			definitions.SecureDataCookieName: false,
		}

		for _, cookie := range cookies {
			if _, ok := expectedNames[cookie.Name]; !ok {
				t.Errorf("unexpected cookie %q", cookie.Name)
			}

			expectedNames[cookie.Name] = true

			// Verify cookie is being deleted (MaxAge=-1)
			if cookie.MaxAge != -1 {
				t.Errorf("cookie %q MaxAge=%d, want -1", cookie.Name, cookie.MaxAge)
			}
		}

		for name, found := range expectedNames {
			if !found {
				t.Errorf("expected cookie %q not found", name)
			}
		}
	})

	t.Run("secure flag based on dev mode", func(t *testing.T) {
		tests := []struct {
			name       string
			devMode    bool
			wantSecure bool
		}{
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

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				util.SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: test.devMode})

				writer := httptest.NewRecorder()
				ctx, _ := gin.CreateTestContext(writer)
				ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)

				ClearBrowserCookies(ctx)

				cookies := writer.Result().Cookies()

				if len(cookies) == 0 {
					t.Fatalf("expected cookies to be set")
				}

				for _, cookie := range cookies {
					if cookie.Secure != test.wantSecure {
						t.Errorf("cookie %q secure=%v, want %v", cookie.Name, cookie.Secure, test.wantSecure)
					}
				}
			})
		}
	})
}
