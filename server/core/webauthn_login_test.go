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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
)

type webAuthnTestConfig struct {
	config.File
}

func (c *webAuthnTestConfig) GetServer() *config.ServerSection {
	return &config.ServerSection{
		Redis: config.Redis{
			Prefix: "test:",
		},
		Timeouts: config.Timeouts{
			RedisRead: time.Second,
		},
	}
}

func TestLoginWebAuthnBeginUsesSessionUniqueUserID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	store := cookie.NewStore([]byte("secret"))
	r.Use(sessions.Sessions("test-session", store))

	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("failed to create Redis mock client")
	}

	client := rediscli.NewTestClient(db)
	deps := AuthDeps{
		Cfg:    &webAuthnTestConfig{},
		Logger: slog.Default(),
		Redis:  client,
	}

	uniqueUserID := "uid-123"
	key := "test:webauthn:user:" + uniqueUserID
	mock.ExpectHGetAll(key).SetVal(map[string]string{
		"id":           uniqueUserID,
		"name":         "test1",
		"display_name": "Test User",
	})

	r.GET("/set", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(definitions.CookieUsername, "test1")
		session.Set(definitions.CookieUniqueUserID, uniqueUserID)
		session.Save()
		c.Status(http.StatusOK)
	})

	r.GET("/login/webauthn/begin", LoginWebAuthnBegin(deps))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/set", nil)
	r.ServeHTTP(w, req)
	sessionCookie := w.Header().Get("Set-Cookie")

	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/login/webauthn/begin", nil)
	req.Header.Set("Cookie", sessionCookie)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateWebAuthnCredentialAfterLoginKeepsDeviceData(t *testing.T) {
	now := time.Date(2026, time.January, 30, 12, 0, 0, 0, time.UTC)

	credentials := []mfa.PersistentCredential{
		{
			Credential: webauthn.Credential{
				ID: []byte("device-a"),
				Authenticator: webauthn.Authenticator{
					SignCount: 3,
				},
			},
			Name:     "TouchID",
			LastUsed: time.Date(2026, time.January, 29, 10, 0, 0, 0, time.UTC),
		},
		{
			Credential: webauthn.Credential{
				ID: []byte("device-b"),
				Authenticator: webauthn.Authenticator{
					SignCount: 0,
				},
			},
			Name:     "YubiKey",
			LastUsed: time.Date(2026, time.January, 28, 11, 0, 0, 0, time.UTC),
		},
	}

	loginCredential := &webauthn.Credential{
		ID: []byte("device-b"),
		Authenticator: webauthn.Authenticator{
			SignCount: 6,
		},
	}

	oldCredential, updatedCredential := updateWebAuthnCredentialAfterLogin(credentials, loginCredential, now)

	if assert.NotNil(t, oldCredential) && assert.NotNil(t, updatedCredential) {
		assert.Equal(t, "YubiKey", oldCredential.Name)
		assert.Equal(t, "YubiKey", updatedCredential.Name)
		assert.Equal(t, uint32(6), updatedCredential.Authenticator.SignCount)
		assert.Equal(t, now, updatedCredential.LastUsed)
		assert.Equal(t, []byte("device-b"), updatedCredential.ID)
	}
}
