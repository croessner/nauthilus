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

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestIsWebAuthnRegistrationAuthenticated(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := cookie.NewStore([]byte("secret"))

	tests := []struct {
		name  string
		setup func(session sessions.Session)
		want  bool
	}{
		{
			name: "auth result ok",
			setup: func(session sessions.Session) {
				session.Set(definitions.CookieAuthResult, uint8(definitions.AuthResultOK))
			},
			want: true,
		},
		{
			name: "auth result fail overrides account",
			setup: func(session sessions.Session) {
				session.Set(definitions.CookieAuthResult, uint8(definitions.AuthResultFail))
				session.Set(definitions.CookieAccount, "testuser")
			},
			want: false,
		},
		{
			name: "account without auth result",
			setup: func(session sessions.Session) {
				session.Set(definitions.CookieAccount, "testuser")
			},
			want: true,
		},
		{
			name:  "missing auth result and account",
			setup: func(session sessions.Session) {},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(sessions.Sessions("test-session", store))

			var got bool
			r.GET("/check", func(c *gin.Context) {
				session := sessions.Default(c)
				tt.setup(session)
				got = isWebAuthnRegistrationAuthenticated(session)
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/check", nil)
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveWebAuthnDisplayNameFallbacksToUserName(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := cookie.NewStore([]byte("secret"))

	r := gin.New()
	r.Use(sessions.Sessions("test-session", store))

	r.GET("/check", func(c *gin.Context) {
		session := sessions.Default(c)
		displayName, updated := resolveWebAuthnDisplayName(session, "testuser")

		assert.Equal(t, "testuser", displayName)
		assert.True(t, updated)

		storedName, _ := util.GetSessionValue[string](session, definitions.CookieDisplayName)
		assert.Equal(t, "testuser", storedName)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/check", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
