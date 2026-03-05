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
	"errors"
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
	nauthilusidp "github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
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

type mockMFAProvider struct {
	deleteWebAuthnErr error
}

func (m *mockMFAProvider) GenerateTOTPSecret(_ *gin.Context, _ string) (string, string, error) {
	return "secret", "otpauth://example", nil
}

func (m *mockMFAProvider) VerifyAndSaveTOTP(_ *gin.Context, _ string, _ string, _ string, _ uint8) error {
	return nil
}

func (m *mockMFAProvider) DeleteTOTP(_ *gin.Context, _ string, _ uint8) error {
	return nil
}

func (m *mockMFAProvider) GenerateRecoveryCodes(_ *gin.Context, _ string, _ uint8) ([]string, error) {
	return []string{"code1"}, nil
}

func (m *mockMFAProvider) SaveRecoveryCodes(_ *gin.Context, _ string, _ []string, _ uint8) error {
	return nil
}

func (m *mockMFAProvider) UseRecoveryCode(_ *gin.Context, _ string, _ string, _ uint8) (bool, error) {
	return true, nil
}

func (m *mockMFAProvider) DeleteWebAuthnCredential(_ *gin.Context, _ string, _ string, _ uint8) error {
	return m.deleteWebAuthnErr
}

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

func TestMFAAPI_DeleteWebAuthn_SuccessInvalidatesRedisCache(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{Prefix: "nt:"},
		},
	}

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger(), Redis: redisClient}

	api := NewMFAAPI(d)
	api.mfa = &mockMFAProvider{}

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:      "alice",
		definitions.SessionKeyUniqueUserID: "uid-123",
		definitions.SessionKeyUserBackend:  uint8(definitions.BackendLDAP),
	}}

	mock.ExpectDel("nt:webauthn:user:uid-123").SetVal(1)

	r := gin.New()
	r.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, mgr)
		ctx.Next()
	})
	r.DELETE("/api/v1/mfa/webauthn/:credentialID", api.DeleteWebAuthn)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/mfa/webauthn/cred-1", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAAPI_DeleteWebAuthn_RedisDeleteFails(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{Prefix: "nt:"},
		},
	}

	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger(), Redis: redisClient}

	api := NewMFAAPI(d)
	api.mfa = &mockMFAProvider{}

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:      "alice",
		definitions.SessionKeyUniqueUserID: "uid-123",
		definitions.SessionKeyUserBackend:  uint8(definitions.BackendLDAP),
	}}

	mock.ExpectDel("nt:webauthn:user:uid-123").SetErr(errors.New("redis down"))

	r := gin.New()
	r.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, mgr)
		ctx.Next()
	})
	r.DELETE("/api/v1/mfa/webauthn/:credentialID", api.DeleteWebAuthn)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/mfa/webauthn/cred-1", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestMFAAPI_DeleteWebAuthn_BackendDeleteFails(t *testing.T) {
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{Prefix: "nt:"},
		},
	}

	db, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	d := &deps.Deps{Cfg: cfg, Logger: log.GetLogger(), Redis: redisClient}

	api := NewMFAAPI(d)
	api.mfa = &mockMFAProvider{deleteWebAuthnErr: errors.New("backend failed")}

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:      "alice",
		definitions.SessionKeyUniqueUserID: "uid-123",
		definitions.SessionKeyUserBackend:  uint8(definitions.BackendLDAP),
	}}

	r := gin.New()
	r.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxSecureDataKey, mgr)
		ctx.Next()
	})
	r.DELETE("/api/v1/mfa/webauthn/:credentialID", api.DeleteWebAuthn)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/mfa/webauthn/cred-1", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

var _ nauthilusidp.MFAProvider = (*mockMFAProvider)(nil)
