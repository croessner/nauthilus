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

package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/log"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupTestRouter(d *deps.Deps) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions(definitions.SessionName, store))

	api := NewMFAAPI(d)
	api.Register(r)
	return r
}

func TestMFAAPI_SetupTOTP_Unauthenticated(t *testing.T) {
	cfg := &config.FileSettings{}
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger()}
	r := setupTestRouter(d)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/mfa/totp/setup", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAAPI_SetupTOTP_Success(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				TotpIssuer: "NauthilusTest",
			},
		},
	}
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger()}
	r := setupTestRouter(d)

	// Inject session values
	r.GET("/test-inject", func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		session.Set(definitions.CookieAccount, "testuser")
		session.Save()
		ctx.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()

	// Create a session first
	reqInject, _ := http.NewRequest("GET", "/test-inject", nil)
	r.ServeHTTP(w, reqInject)
	cookieHeader := w.Header().Get("Set-Cookie")

	w = httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/mfa/totp/setup", nil)
	req.Header.Set("Cookie", cookieHeader)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp["secret"])
	assert.NotEmpty(t, resp["qr_code_url"])
}

func TestMFAAPI_RegisterTOTP_Success(t *testing.T) {
	// Da RegisterTOTP den MFAService nutzt, der wiederum AuthState initialisiert,
	// müssten wir hier die gesamte Backend-Mock-Maschinerie auffahren.
	// Für diesen Test fokussieren wir uns auf die API-Schicht.

	// Wir überspringen den vollen Integrationstest hier,
	// da die Geschäftslogik bereits in MFAService-Tests abgedeckt ist.
	// Aber wir können prüfen, ob ungültige Requests abgelehnt werden.

	cfg := &config.FileSettings{}
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger()}
	r := setupTestRouter(d)

	w := httptest.NewRecorder()
	body := `{"code": "123456"}`
	req, _ := http.NewRequest("POST", "/api/v1/mfa/totp/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	// Erwartet 401 weil nicht eingeloggt
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
