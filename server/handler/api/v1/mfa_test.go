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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/log"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// mockCookieManager implements cookie.Manager for testing.
type mockCookieManager struct {
	data map[string]any
}

func (m *mockCookieManager) Set(key string, value any) {
	m.data[key] = value
}

func (m *mockCookieManager) Get(key string) (any, bool) {
	val, ok := m.data[key]
	return val, ok
}

func (m *mockCookieManager) Delete(key string) {
	delete(m.data, key)
}

func (m *mockCookieManager) Clear() {
	m.data = make(map[string]any)
}

func (m *mockCookieManager) Save(_ *gin.Context) error {
	return nil
}

func (m *mockCookieManager) Load(_ *gin.Context) error {
	return nil
}

func (m *mockCookieManager) GetString(key string, defaultValue string) string {
	if val, ok := m.data[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetInt(key string, defaultValue int) int {
	if val, ok := m.data[key]; ok {
		if i, ok := val.(int); ok {
			return i
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetInt64(key string, defaultValue int64) int64 {
	if val, ok := m.data[key]; ok {
		if i, ok := val.(int64); ok {
			return i
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetUint8(key string, defaultValue uint8) uint8 {
	if val, ok := m.data[key]; ok {
		if i, ok := val.(uint8); ok {
			return i
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetBool(key string, defaultValue bool) bool {
	if val, ok := m.data[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetStringSlice(key string, defaultValue []string) []string {
	if val, ok := m.data[key]; ok {
		if s, ok := val.([]string); ok {
			return s
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetDuration(key string, defaultValue time.Duration) time.Duration {
	if val, ok := m.data[key]; ok {
		if d, ok := val.(time.Duration); ok {
			return d
		}
	}
	return defaultValue
}

func (m *mockCookieManager) GetBytes(key string, defaultValue []byte) []byte {
	if val, ok := m.data[key]; ok {
		if b, ok := val.([]byte); ok {
			return b
		}
	}
	return defaultValue
}

func (m *mockCookieManager) Debug(_ *gin.Context, _ *slog.Logger, _ string) {}

func (m *mockCookieManager) HasKey(key string) bool {
	_, ok := m.data[key]
	return ok
}

func (m *mockCookieManager) SetMaxAge(_ int) {}

func setupTestRouterWithMockCookie(d *deps.Deps, mgr cookie.Manager) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Add middleware that sets up the mock cookie manager
	r.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, mgr)
		ctx.Next()
	})

	api := NewMFAAPI(d)
	api.Register(r)
	return r
}

// newOIDCSessionData returns session data for an OIDC flow with the given scope string.
func newOIDCSessionData(account, scope string) map[string]any {
	return map[string]any{
		definitions.SessionKeyAccount:     account,
		definitions.SessionKeyIdPFlowType: definitions.ProtoOIDC,
		definitions.SessionKeyIdPScope:    scope,
	}
}

// newSAMLSessionData returns session data for a SAML flow with the given entity ID.
func newSAMLSessionData(account, entityID string) map[string]any {
	return map[string]any{
		definitions.SessionKeyAccount:         account,
		definitions.SessionKeyIdPFlowType:     definitions.ProtoSAML,
		definitions.SessionKeyIdPSAMLEntityID: entityID,
	}
}

func TestMFAAPI_SetupTOTP_Unauthenticated(t *testing.T) {
	cfg := &config.FileSettings{}
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger()}

	// Use mock cookie manager with no session data
	mgr := &mockCookieManager{data: make(map[string]any)}
	r := setupTestRouterWithMockCookie(d, mgr)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/mfa/totp/setup", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAAPI_SetupTOTP_Success(t *testing.T) {
	cfg := &config.FileSettings{
		IdP: &config.IdPSection{
			OIDC: config.OIDCConfig{
				Enabled: true,
			},
		},
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				TotpIssuer: "NauthilusTest",
			},
		},
	}
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger()}

	// Use mock cookie manager with authenticated OIDC session
	mgr := &mockCookieManager{data: newOIDCSessionData("testuser", "openid profile")}
	r := setupTestRouterWithMockCookie(d, mgr)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/mfa/totp/setup", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp["secret"])
	assert.NotEmpty(t, resp["qr_code_url"])
}

func TestMFAAPI_RegisterTOTP_Unauthenticated(t *testing.T) {
	cfg := &config.FileSettings{}
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger()}

	// Use mock cookie manager with no session data
	mgr := &mockCookieManager{data: make(map[string]any)}
	r := setupTestRouterWithMockCookie(d, mgr)

	w := httptest.NewRecorder()
	body := `{"code": "123456"}`
	req, _ := http.NewRequest("POST", "/api/v1/mfa/totp/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAAPI_MFAManageMiddleware_ValidSession(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				TotpIssuer: "NauthilusTest",
			},
		},
	}
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger()}

	// Any authenticated session should pass the middleware
	mgr := &mockCookieManager{data: newOIDCSessionData("testuser", "openid profile")}
	r := setupTestRouterWithMockCookie(d, mgr)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/mfa/totp/setup", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMFAAPI_MFAManageMiddleware_SAMLValidSession(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Frontend: config.Frontend{
				TotpIssuer: "NauthilusTest",
			},
		},
	}
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger()}

	// SAML session with any entity ID should pass the middleware
	mgr := &mockCookieManager{data: newSAMLSessionData("testuser", "https://sp.example.com")}
	r := setupTestRouterWithMockCookie(d, mgr)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/mfa/totp/setup", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
