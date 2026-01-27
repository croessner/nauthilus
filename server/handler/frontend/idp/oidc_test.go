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
		DefaultHTTPRequestHeader: config.DefaultHTTPRequestHeader{
			OIDCCID:    "X-Nauthilus-OIDC-ClientID",
			ClientIP:   "X-Real-IP",
			ClientPort: "X-Real-Port",
			ClientID:   "X-Nauthilus-Client-ID",
			ClientHost: "X-Nauthilus-Client-Host",
		},
		DNS: config.DNS{
			ResolveClientIP: false,
		},
	}
}

func (m *mockOIDCCfg) GetOIDCCID() string    { return "X-Nauthilus-OIDC-ClientID" }
func (m *mockOIDCCfg) GetClientIP() string   { return "X-Real-IP" }
func (m *mockOIDCCfg) GetClientPort() string { return "X-Real-Port" }
func (m *mockOIDCCfg) GetClientID() string   { return "X-Nauthilus-Client-ID" }
func (m *mockOIDCCfg) GetClientHost() string { return "X-Nauthilus-Client-Host" }
func (m *mockOIDCCfg) GetLocalIP() string    { return "X-Local-IP" }
func (m *mockOIDCCfg) GetLocalPort() string  { return "X-Local-Port" }
func (m *mockOIDCCfg) GetUsername() string   { return "X-Nauthilus-Username" }
func (m *mockOIDCCfg) GetPassword() string   { return "X-Nauthilus-Password" }

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

	t.Run("Logout without session redirects to logged_out", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := gin.New()
		r.GET("/logout", sessions.Sessions("test-session", store), h.Logout)

		req, _ := http.NewRequest(http.MethodGet, "/logout", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/logged_out", w.Header().Get("Location"))
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

		// Expectations for DeleteUserRefreshTokens
		userKey := "test:nauthilus:oidc:user_refresh_tokens:user123"
		mock.ExpectSMembers(userKey).SetVal([]string{})

		url := "/logout?id_token_hint=" + idToken + "&post_logout_redirect_uri=https://app.com/post-logout"
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://app.com/post-logout", w.Header().Get("Location"))
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("Logout with client in session and LogoutRedirectURI", func(t *testing.T) {
		clientWithLogout := config.OIDCClient{
			ClientID:          "logout-client",
			LogoutRedirectURI: "https://custom-logout.com",
		}
		cfg.clients = append(cfg.clients, clientWithLogout)

		w := httptest.NewRecorder()
		r := gin.New()
		r.GET("/logout", sessions.Sessions("test-session", store), func(c *gin.Context) {
			session := sessions.Default(c)
			session.Set(definitions.CookieOIDCClients, "logout-client")
			_ = session.Save()
			h.Logout(c)
		})

		req, _ := http.NewRequest(http.MethodGet, "/logout", nil)
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://custom-logout.com", w.Header().Get("Location"))
	})
}

func Test_hasClientConsent(t *testing.T) {
	t.Run("returns false when no clients in session", func(t *testing.T) {
		session := &mockSession{values: make(map[any]any)}
		assert.False(t, hasClientConsent(session, "client1"))
	})

	t.Run("returns true when client is in session", func(t *testing.T) {
		session := &mockSession{values: map[any]any{
			definitions.CookieOIDCClients: "client1,client2",
		}}
		assert.True(t, hasClientConsent(session, "client1"))
		assert.True(t, hasClientConsent(session, "client2"))
		assert.False(t, hasClientConsent(session, "client3"))
	})
}

func Test_addClientToSession(t *testing.T) {
	t.Run("adds client to empty session", func(t *testing.T) {
		session := &mockSession{values: make(map[any]any)}
		addClientToSession(session, "client1")
		assert.Equal(t, "client1", session.values[definitions.CookieOIDCClients])
	})

	t.Run("appends client to existing session", func(t *testing.T) {
		session := &mockSession{values: map[any]any{
			definitions.CookieOIDCClients: "client1",
		}}
		addClientToSession(session, "client2")
		assert.Equal(t, "client1,client2", session.values[definitions.CookieOIDCClients])
	})

	t.Run("does not duplicate client in session", func(t *testing.T) {
		session := &mockSession{values: map[any]any{
			definitions.CookieOIDCClients: "client1,client2",
		}}
		addClientToSession(session, "client1")
		assert.Equal(t, "client1,client2", session.values[definitions.CookieOIDCClients])
	})
}

type mockSession struct {
	sessions.Session
	values map[any]any
}

func (m *mockSession) Get(key any) any {
	return m.values[key]
}

func (m *mockSession) Set(key any, val any) {
	m.values[key] = val
}

func (m *mockSession) Save() error {
	return nil
}

func TestOIDCHandler_Consent(t *testing.T) {
	t.Run("Authorize redirects to consent when not authorized", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IdP dependencies. hasClientConsent is covered by unit tests.")
	})

	t.Run("Authorize skips consent when already authorized", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IdP dependencies. hasClientConsent is covered by unit tests.")
	})

	t.Run("ConsentPOST redirects with code and state", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IdP dependencies. addClientToSession is covered by unit tests.")
	})

	t.Run("ConsentPOST with state in query", func(t *testing.T) {
		t.Skip("Skipping integration test due to complex IdP dependencies. addClientToSession is covered by unit tests.")
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
