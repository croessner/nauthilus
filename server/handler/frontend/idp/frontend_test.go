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

package idp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

type mockFrontendCfg struct {
	config.File
}

func (m *mockFrontendCfg) GetServer() *config.ServerSection {
	return &config.ServerSection{
		Frontend: config.Frontend{
			DefaultLanguage: "en",
		},
	}
}

func TestBasePageData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("test-session", store))

	cfg := &mockFrontendCfg{}

	r.GET("/test", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(definitions.CookieAccount, "testuser")
		session.Set(definitions.CookieLang, "de")
		session.Save()

		data := BasePageData(c, cfg)
		assert.Equal(t, "de", data["LanguageTag"])
		assert.Equal(t, "testuser", data["Username"])
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
}
