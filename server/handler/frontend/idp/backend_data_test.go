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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/go-webauthn/webauthn/webauthn"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
)

type webAuthnBackendTestConfig struct {
	config.File
	prefix string
	ttl    time.Duration
}

func (c *webAuthnBackendTestConfig) GetServer() *config.ServerSection {
	return &config.ServerSection{
		Redis: config.Redis{
			Prefix:      c.prefix,
			PosCacheTTL: c.ttl,
		},
	}
}

type mockWebAuthnProvider struct {
	credentials []mfa.PersistentCredential
	err         error
}

func (m *mockWebAuthnProvider) GetWebAuthnCredentials() ([]mfa.PersistentCredential, error) {
	return m.credentials, m.err
}

func TestResolveWebAuthnUserFallbacksToBackend(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &webAuthnBackendTestConfig{
		prefix: "test:",
		ttl:    time.Minute,
	}

	db, mockRedis := redismock.NewClientMock()
	if db == nil || mockRedis == nil {
		t.Fatalf("failed to create Redis mock client")
	}

	redisClient := rediscli.NewTestClient(db)
	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg:    cfg,
			Logger: slog.Default(),
			Redis:  redisClient,
		},
	}

	uniqueUserID := "uid-123"
	redisKey := cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + uniqueUserID

	mockRedis.ExpectHGetAll(redisKey).SetVal(map[string]string{})

	provider := &mockWebAuthnProvider{
		credentials: []mfa.PersistentCredential{
			{
				Credential: webauthn.Credential{ID: []byte("cred-1")},
				Name:       "Test Key",
			},
		},
	}

	credentialsJSON, err := jsoniter.ConfigFastest.Marshal(provider.credentials)
	if err != nil {
		t.Fatalf("failed to marshal credentials: %v", err)
	}

	credentialsValue := string(credentialsJSON)
	if encrypted, err := redisClient.GetSecurityManager().Encrypt(credentialsValue); err == nil {
		credentialsValue = encrypted
	}

	expected := map[string]any{
		"id":           uniqueUserID,
		"name":         "test1",
		"display_name": "Test User",
		"credentials":  credentialsValue,
	}

	mockRedis.ExpectHSet(redisKey, expected).SetVal(4)
	mockRedis.ExpectExpire(redisKey, cfg.GetServer().GetRedis().GetPosCacheTTL()).SetVal(true)

	r := gin.New()
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyUniqueUserID: uniqueUserID,
	}}

	var data *UserBackendData

	r.GET("/test", func(c *gin.Context) {
		data = &UserBackendData{
			Username:    "test1",
			DisplayName: "Test User",
		}

		h.resolveWebAuthnUser(c, mgr, data, provider)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	if assert.NotNil(t, data) {
		assert.Equal(t, uniqueUserID, data.UniqueUserID)
		assert.True(t, data.HaveWebAuthn)
		assert.NotNil(t, data.WebAuthnUser)
		assert.Len(t, data.WebAuthnUser.Credentials, 1)
	}

	assert.NoError(t, mockRedis.ExpectationsWereMet())
}

func TestHasWebAuthnWithProviderFallbacksToBackend(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &webAuthnBackendTestConfig{
		prefix: "test:",
		ttl:    time.Minute,
	}

	db, mockRedis := redismock.NewClientMock()
	if db == nil || mockRedis == nil {
		t.Fatalf("failed to create Redis mock client")
	}

	redisClient := rediscli.NewTestClient(db)
	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg:    cfg,
			Logger: slog.Default(),
			Redis:  redisClient,
		},
	}

	uniqueUserID := "uid-123"
	redisKey := cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + uniqueUserID

	mockRedis.ExpectHGetAll(redisKey).SetVal(map[string]string{})

	provider := &mockWebAuthnProvider{
		credentials: []mfa.PersistentCredential{
			{
				Credential: webauthn.Credential{ID: []byte("cred-1")},
				Name:       "Test Key",
			},
		},
	}

	credentialsJSON, err := jsoniter.ConfigFastest.Marshal(provider.credentials)
	if err != nil {
		t.Fatalf("failed to marshal credentials: %v", err)
	}

	credentialsValue := string(credentialsJSON)
	if encrypted, err := redisClient.GetSecurityManager().Encrypt(credentialsValue); err == nil {
		credentialsValue = encrypted
	}

	expected := map[string]any{
		"id":           uniqueUserID,
		"name":         "test1",
		"display_name": "Test User",
		"credentials":  credentialsValue,
	}

	mockRedis.ExpectHSet(redisKey, expected).SetVal(4)
	mockRedis.ExpectExpire(redisKey, cfg.GetServer().GetRedis().GetPosCacheTTL()).SetVal(true)

	r := gin.New()

	r.GET("/test", func(c *gin.Context) {
		user := &backend.User{Id: uniqueUserID, Name: "test1", DisplayName: "Test User"}
		haveWebAuthn := h.hasWebAuthnWithProvider(c, user, "", provider)
		assert.True(t, haveWebAuthn)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, mockRedis.ExpectationsWereMet())
}
