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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
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
	var log config.Log
	_ = log.Level.Set("debug")
	all := &config.DbgModule{}
	_ = all.Set("all")
	log.DbgModules = []*config.DbgModule{all}

	return &config.ServerSection{
		Redis: config.Redis{
			Prefix: "test:",
		},
		Log: log,
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
	scopes := resp["scopes_supported"].([]any)
	assert.Contains(t, scopes, "offline_access")
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
		idToken, _, _, _, _ := idpInstance.IssueTokens(context.Background(), &idp.OIDCSession{
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

func TestOIDCHandler_Consent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	signingKey := generateTestKey()
	client := config.OIDCClient{
		ClientID:     "test-client",
		RedirectURIs: []string{"https://app.com/callback"},
	}

	cfg := &mockOIDCCfg{
		issuer:     issuer,
		signingKey: signingKey,
		clients:    []config.OIDCClient{client},
	}

	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	idpInstance := idp.NewNauthilusIdP(d)
	store := cookie.NewStore([]byte("secret"))
	h := NewOIDCHandler(store, d, idpInstance)

	t.Run("ConsentPOST redirects with code and state", func(t *testing.T) {
		consentChallenge := "challenge123"
		state := "state456"
		oidcSession := &idp.OIDCSession{
			ClientID:    "test-client",
			UserID:      "user123",
			RedirectURI: "https://app.com/callback",
		}
		sessionData, _ := json.Marshal(oidcSession)

		// Mock GetSession for consent
		mock.ExpectGet("test:nauthilus:oidc:code:consent:" + consentChallenge).SetVal(string(sessionData))

		// Mock StoreSession for code (code is random)
		mock.Regexp().ExpectSet("test:nauthilus:oidc:code:.*", string(sessionData), 10*time.Minute).SetVal("OK")

		// Mock DeleteSession for consent
		mock.ExpectDel("test:nauthilus:oidc:code:consent:" + consentChallenge).SetVal(1)

		w := httptest.NewRecorder()
		r := gin.New()
		r.Use(sessions.Sessions("test-session", store))
		r.POST("/consent", h.ConsentPOST)

		form := "consent_challenge=" + consentChallenge + "&state=" + state + "&submit=allow"
		req, _ := http.NewRequest(http.MethodPost, "/consent", io.NopCloser(strings.NewReader(form)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "https://app.com/callback?code=")
		assert.Contains(t, location, "&state="+state)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("ConsentPOST with state in query", func(t *testing.T) {
		consentChallenge := "challenge-query"
		state := "state-in-query"
		oidcSession := &idp.OIDCSession{
			ClientID:    "test-client",
			UserID:      "user123",
			RedirectURI: "https://app.com/callback",
		}
		sessionData, _ := json.Marshal(oidcSession)

		mock.ExpectGet("test:nauthilus:oidc:code:consent:" + consentChallenge).SetVal(string(sessionData))
		mock.Regexp().ExpectSet("test:nauthilus:oidc:code:.*", string(sessionData), 10*time.Minute).SetVal("OK")
		mock.ExpectDel("test:nauthilus:oidc:code:consent:" + consentChallenge).SetVal(1)

		w := httptest.NewRecorder()
		r := gin.New()
		r.Use(sessions.Sessions("test-session", store))
		r.POST("/consent", h.ConsentPOST)

		form := "consent_challenge=" + consentChallenge + "&submit=allow"
		req, _ := http.NewRequest(http.MethodPost, "/consent?state="+state, io.NopCloser(strings.NewReader(form)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "&state="+state)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestOIDCHandler_Token(t *testing.T) {
	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())
	gin.SetMode(gin.TestMode)
	issuer := "https://auth.example.com"
	signingKey := generateTestKey()
	client := config.OIDCClient{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURIs: []string{"https://app.com/callback"},
	}

	cfg := &mockOIDCCfg{
		issuer:     issuer,
		signingKey: signingKey,
		clients:    []config.OIDCClient{client},
	}

	db, mock := redismock.NewClientMock()
	rClient := rediscli.NewTestClient(db)

	d := &deps.Deps{
		Cfg:    cfg,
		Redis:  rClient,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	idpInstance := idp.NewNauthilusIdP(d)
	h := NewOIDCHandler(nil, d, idpInstance)

	t.Run("Token request with Basic Auth", func(t *testing.T) {
		code := "code123"
		oidcSession := &idp.OIDCSession{
			ClientID:    "test-client",
			UserID:      "user123",
			RedirectURI: "https://app.com/callback",
			Nonce:       "test-nonce",
		}
		sessionData, _ := json.Marshal(oidcSession)

		mock.ExpectGet("test:nauthilus:oidc:code:" + code).SetVal(string(sessionData))
		mock.ExpectDel("test:nauthilus:oidc:code:" + code).SetVal(1)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", code)

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verifiziere ID-Token Inhalt (optional, da wir IssueTokens bereits separat testen)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp["id_token"])

		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Token request with client_id in body and secret in Basic Auth (should fail)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", "any-code")
		form.Add("client_id", "test-client") // client_id im Body

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret") // secret im Header
		ctx.Request = req

		h.Token(ctx)

		// MUST NOT use more than one authentication method
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Token request with URL-encoded characters in Basic Auth", func(t *testing.T) {
		code := "code789"
		specialClientID := "client@test"
		specialSecret := "pass+word"
		oidcSession := &idp.OIDCSession{
			ClientID:    specialClientID,
			UserID:      "user123",
			RedirectURI: "https://app.com/callback",
		}
		sessionData, _ := json.Marshal(oidcSession)

		// Mock client with special characters
		cfg.clients = append(cfg.clients, config.OIDCClient{
			ClientID:     specialClientID,
			ClientSecret: specialSecret,
			RedirectURIs: []string{"https://app.com/callback"},
		})

		mock.ExpectGet("test:nauthilus:oidc:code:" + code).SetVal(string(sessionData))
		mock.ExpectDel("test:nauthilus:oidc:code:" + code).SetVal(1)

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", code)

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// URL-encode parts manually to simulate RFC 6749 Section 2.3.1
		authValue := url.QueryEscape(specialClientID) + ":" + url.QueryEscape(specialSecret)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(authValue)))
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Token request with both Header and Body (matching - should fail)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", "any-code")
		form.Add("client_id", "test-client")
		form.Add("client_secret", "test-secret")

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		ctx.Request = req

		h.Token(ctx)

		// MUST NOT use more than one authentication method
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Token request with 11 vs 6 chars mismatch (reproduce user log)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", "any-code")

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "secret") // 6 chars
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Token request with multiple methods (should fail)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", "any-code")
		form.Add("client_id", "test-client")
		form.Add("client_secret", "test-secret")

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test-client", "test-secret")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "invalid_client", resp["error"])
	})

	t.Run("Token request with enforced method (mismatch should fail)", func(t *testing.T) {
		// Update client to enforce basic auth
		cfg.clients[0].TokenEndpointAuthMethod = "client_secret_basic"

		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("grant_type", "authorization_code")
		form.Add("code", "any-code")
		form.Add("client_id", "test-client")
		form.Add("client_secret", "test-secret") // Post Body

		req, _ := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx.Request = req

		h.Token(ctx)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "invalid_client", resp["error"])
	})
}
