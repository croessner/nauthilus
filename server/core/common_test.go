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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandleErrWithDeps(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("NoError", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		HandleErrWithDeps(ctx, nil, AuthDeps{})
		assert.Equal(t, http.StatusBadRequest, ctx.Writer.Status())
	})

	t.Run("WithError", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		err := errors.New("test error")
		HandleErrWithDeps(ctx, err, AuthDeps{})
		assert.Equal(t, http.StatusBadRequest, ctx.Writer.Status())
		assert.Equal(t, "test error", w.Body.String())
	})
}

func TestSessionCleaner(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("test-session", store))

	r.GET("/set", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(definitions.CookieUsername, "testuser")
		session.Set(definitions.CookieAccount, "testaccount")
		session.Save()
		c.Status(http.StatusOK)
	})

	r.GET("/clean", func(c *gin.Context) {
		SessionCleaner(c)
		c.Status(http.StatusOK)
	})

	r.GET("/check", func(c *gin.Context) {
		session := sessions.Default(c)
		assert.Nil(t, session.Get(definitions.CookieUsername))
		assert.Nil(t, session.Get(definitions.CookieAccount))
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/set", nil)
	r.ServeHTTP(w, req)
	sessionCookie := w.Header().Get("Set-Cookie")

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/clean", nil)
	req.Header.Set("Cookie", sessionCookie)
	r.ServeHTTP(w, req)
	sessionCookie = w.Header().Get("Set-Cookie")

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/check", nil)
	req.Header.Set("Cookie", sessionCookie)
	r.ServeHTTP(w, req)
}
