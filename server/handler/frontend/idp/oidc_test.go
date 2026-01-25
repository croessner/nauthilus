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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/stretchr/testify/assert"
)

type mockOIDCCfg struct {
	config.File
	issuer     string
	signingKey string
	clients    []config.OIDCClient
}

func (m *mockOIDCCfg) GetIdP() *config.IdPSection {
	return &config.IdPSection{
		OIDC: config.OIDCConfig{
			Issuer:     m.issuer,
			SigningKey: m.signingKey,
			Clients:    m.clients,
		},
	}
}

func generateTestKey() string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	return string(pemData)
}

func (m *mockOIDCCfg) GetServer() *config.ServerSection {
	return &config.ServerSection{
		Redis: config.Redis{
			Prefix: "test:",
		},
	}
}

func TestOIDCHandler_Discovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	cfg := &mockOIDCCfg{issuer: issuer, signingKey: generateTestKey()}

	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:   cfg,
		Redis: rClient,
	}

	h := NewOIDCHandler(nil, d, nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	h.Discovery(ctx)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, issuer, resp["issuer"])
	assert.Equal(t, issuer+"/oidc/authorize", resp["authorization_endpoint"])
	assert.Equal(t, issuer+"/oidc/logout", resp["end_session_endpoint"])
}

func TestOIDCHandler_JWKS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &mockOIDCCfg{issuer: "https://auth.example.com", signingKey: generateTestKey()}
	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)
	d := &deps.Deps{Cfg: cfg, Redis: rClient}
	h := NewOIDCHandler(nil, d, nil)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	h.JWKS(ctx)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.NotNil(t, resp["keys"])
}

func TestOIDCHandler_Logout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	signingKey := generateTestKey()
	client := config.OIDCClient{
		ClientID:               "test-client",
		PostLogoutRedirectURIs: []string{"https://app.com/post-logout"},
	}

	cfg := &mockOIDCCfg{
		issuer:     issuer,
		signingKey: signingKey,
		clients:    []config.OIDCClient{client},
	}

	db, _ := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	idpInstance := idp.NewNauthilusIdP(d)
	store := cookie.NewStore([]byte("secret"))
	h := NewOIDCHandler(store, d, idpInstance)

	t.Run("Logout without session redirects to login", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := gin.New()
		r.GET("/logout", sessions.Sessions("test-session", store), h.Logout)

		req, _ := http.NewRequest(http.MethodGet, "/logout", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/idp/login", w.Header().Get("Location"))
	})

	t.Run("Logout with valid post_logout_redirect_uri", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := gin.New()
		r.GET("/logout", sessions.Sessions("test-session", store), h.Logout)

		// Create a mock ID token hint
		idToken, _, _ := idpInstance.IssueTokens(context.Background(), &idp.OIDCSession{
			ClientID: "test-client",
			UserID:   "user123",
			AuthTime: time.Now(),
		})

		url := "/logout?id_token_hint=" + idToken + "&post_logout_redirect_uri=https://app.com/post-logout"
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://app.com/post-logout", w.Header().Get("Location"))
	})
}
