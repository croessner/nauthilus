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
	"bytes"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	corelang "github.com/croessner/nauthilus/server/core/language"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
)

type mockLangManager struct {
	corelang.Manager
}

func (m *mockLangManager) GetBundle() *i18n.Bundle {
	return i18n.NewBundle(language.English)
}

func (m *mockLangManager) GetTags() []language.Tag {
	return []language.Tag{language.English}
}

func (m *mockLangManager) GetMatcher() language.Matcher {
	return language.NewMatcher([]language.Tag{language.English})
}

type mockFrontendCfg struct {
	config.FileSettings
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
	cfg := &mockFrontendCfg{}

	t.Run("Basic Session Data", func(t *testing.T) {
		r := gin.New()
		r.GET("/test", func(c *gin.Context) {
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount: "testuser",
			}}
			c.Set(definitions.CtxSecureDataKey, mgr)

			lm := &mockLangManager{}
			localizer := i18n.NewLocalizer(lm.GetBundle(), "de")
			c.Set(definitions.CtxLocalizedKey, localizer)
			c.Set(definitions.CtxCSPNonceKey, "nonce-123")

			data := BasePageData(c, cfg, lm)
			assert.Equal(t, "de", data["LanguageTag"])
			assert.Equal(t, "testuser", data["Username"])
			assert.Equal(t, "nonce-123", data["CSPNonce"])
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		req.AddCookie(&http.Cookie{Name: definitions.LanguageCookieName, Value: "de"})
		r.ServeHTTP(w, req)
	})

	idpClientNameTests := []struct {
		name         string
		cfg          *mockFrontendCfg
		sessionData  map[string]any
		expectedName string
	}{
		{
			name: "OIDC Client Name",
			cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IdP: &config.IdPSection{
						OIDC: config.OIDCConfig{
							Clients: []config.OIDCClient{
								{ClientID: "client-1", Name: "Client One"},
							},
						},
					},
				},
			},
			sessionData: map[string]any{
				definitions.SessionKeyIdPFlowType: definitions.ProtoOIDC,
				definitions.SessionKeyIdPClientID: "client-1",
			},
			expectedName: "Client One",
		},
		{
			name: "SAML Service Provider Name",
			cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IdP: &config.IdPSection{
						SAML2: config.SAML2Config{
							ServiceProviders: []config.SAML2ServiceProvider{
								{EntityID: "sp-1", Name: "Example SP"},
							},
						},
					},
				},
			},
			sessionData: map[string]any{
				definitions.SessionKeyIdPFlowType:     definitions.ProtoSAML,
				definitions.SessionKeyIdPSAMLEntityID: "sp-1",
			},
			expectedName: "Example SP",
		},
	}

	for _, tt := range idpClientNameTests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()

			r.GET("/test", func(c *gin.Context) {
				mgr := &mockCookieManager{data: tt.sessionData}
				c.Set(definitions.CtxSecureDataKey, mgr)

				lm := &mockLangManager{}
				localizer := i18n.NewLocalizer(lm.GetBundle(), "en")
				c.Set(definitions.CtxLocalizedKey, localizer)

				data := BasePageData(c, tt.cfg, lm)
				assert.Equal(t, tt.expectedName, data["IdPClientName"])
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/test", nil)
			r.ServeHTTP(w, req)
		})
	}
}

func TestURLParamsPreservation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &FrontendHandler{}

	t.Run("getLoginURL with params", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request, _ = http.NewRequest("GET", "/login?client_id=foo&return_to=bar", nil)
		ctx.Params = gin.Params{{Key: "languageTag", Value: "en"}}

		url := h.getLoginURL(ctx)
		assert.Equal(t, "/login/en?client_id=foo&return_to=bar", url)
	})

	t.Run("getLoginURL without lang with params", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request, _ = http.NewRequest("GET", "/login?client_id=foo", nil)

		url := h.getLoginURL(ctx)
		assert.Equal(t, "/login?client_id=foo", url)
	})

	t.Run("appendQueryString helper", func(t *testing.T) {
		assert.Equal(t, "/path?q=v", h.appendQueryString("/path", "q=v"))
		assert.Equal(t, "/path?a=b&q=v", h.appendQueryString("/path?a=b", "q=v"))
		assert.Equal(t, "/path", h.appendQueryString("/path", ""))
	})
}

func TestMFASelectTemplateRecommended(t *testing.T) {
	tmpl := loadMFASelectTemplate(t)

	data := map[string]any{
		"SelectMFA":            "Select",
		"ChooseMFADescription": "Choose",
		"SecurityKey":          "Security Key",
		"AuthenticatorApp":     "Authenticator App",
		"RecoveryCode":         "Recovery Code",
		"Recommended":          "Recommended",
		"OtherMethods":         "Other methods",
		"Or":                   "or",
		"Back":                 "Back",
		"HaveTOTP":             true,
		"HaveWebAuthn":         true,
		"HaveRecoveryCodes":    true,
		"RecommendedMethod":    "totp",
		"HasOtherMethods":      true,
	}

	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data)
	assert.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "autofocus")
	assert.Contains(t, output, "Other methods")
	assert.Contains(t, output, "/login/totp")
	assert.Contains(t, output, "/login/webauthn")
}

func TestMFASelectTemplateWithoutRecommendation(t *testing.T) {
	tmpl := loadMFASelectTemplate(t)

	data := map[string]any{
		"SelectMFA":            "Select",
		"ChooseMFADescription": "Choose",
		"SecurityKey":          "Security Key",
		"AuthenticatorApp":     "Authenticator App",
		"RecoveryCode":         "Recovery Code",
		"Recommended":          "Recommended",
		"OtherMethods":         "Other methods",
		"Or":                   "or",
		"Back":                 "Back",
		"HaveTOTP":             true,
		"HaveWebAuthn":         true,
		"HaveRecoveryCodes":    false,
		"RecommendedMethod":    "",
		"HasOtherMethods":      false,
	}

	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data)
	assert.NoError(t, err)

	output := buf.String()
	assert.NotContains(t, output, "<details")
	assert.NotContains(t, output, "autofocus")
	assert.Contains(t, output, "/login/totp")
	assert.Contains(t, output, "/login/webauthn")
}

func TestGetFlowClientIdentifiers(t *testing.T) {
	testCases := []struct {
		name              string
		sessionData       map[string]any
		expectedOIDCCID   string
		expectedSAMLEntID string
	}{
		{
			name: "OIDC flow returns client ID",
			sessionData: map[string]any{
				definitions.SessionKeyIdPFlowType: definitions.ProtoOIDC,
				definitions.SessionKeyIdPClientID: "oidc-client",
			},
			expectedOIDCCID: "oidc-client",
		},
		{
			name: "SAML flow returns entity ID",
			sessionData: map[string]any{
				definitions.SessionKeyIdPFlowType:     definitions.ProtoSAML,
				definitions.SessionKeyIdPSAMLEntityID: "sp-entity",
			},
			expectedSAMLEntID: "sp-entity",
		},
		{
			name: "Unknown flow returns empty identifiers",
			sessionData: map[string]any{
				definitions.SessionKeyIdPFlowType: "invalid",
			},
		},
	}

	h := &FrontendHandler{}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mgr := &mockCookieManager{data: tc.sessionData}

			oidcCID, samlEntityID := h.getFlowClientIdentifiers(mgr)

			assert.Equal(t, tc.expectedOIDCCID, oidcCID)
			assert.Equal(t, tc.expectedSAMLEntID, samlEntityID)
		})
	}

	t.Run("Nil manager returns empty identifiers", func(t *testing.T) {
		oidcCID, samlEntityID := h.getFlowClientIdentifiers(nil)

		assert.Empty(t, oidcCID)
		assert.Empty(t, samlEntityID)
	})
}

func TestGetRememberMeTTL(t *testing.T) {
	t.Run("Global setting overrides legacy client and service provider values", func(t *testing.T) {
		h := &FrontendHandler{
			deps: &deps.Deps{
				Cfg: &mockFrontendCfg{
					FileSettings: config.FileSettings{
						IdP: &config.IdPSection{
							RememberMeTTL: 2 * time.Hour,
							OIDC: config.OIDCConfig{
								Clients: []config.OIDCClient{
									{ClientID: "oidc-client", RememberMeTTL: 30 * time.Minute},
								},
							},
							SAML2: config.SAML2Config{
								ServiceProviders: []config.SAML2ServiceProvider{
									{EntityID: "sp-entity", RememberMeTTL: 45 * time.Minute},
								},
							},
						},
					},
				},
				Env:         config.NewTestEnvironmentConfig(),
				LangManager: &mockLangManager{},
				Logger:      slog.Default(),
			},
		}

		assert.Equal(t, 2*time.Hour, h.getRememberMeTTL("oidc-client", ""))
		assert.Equal(t, 2*time.Hour, h.getRememberMeTTL("", "sp-entity"))
		assert.Equal(t, 2*time.Hour, h.getRememberMeTTL("", ""))
		assert.True(t, h.shouldShowRememberMe("", ""))
	})

	t.Run("Legacy OIDC client value is used as fallback", func(t *testing.T) {
		h := &FrontendHandler{
			deps: &deps.Deps{
				Cfg: &mockFrontendCfg{
					FileSettings: config.FileSettings{
						IdP: &config.IdPSection{
							OIDC: config.OIDCConfig{
								Clients: []config.OIDCClient{
									{ClientID: "oidc-client", RememberMeTTL: 30 * time.Minute},
								},
							},
						},
					},
				},
				Env:         config.NewTestEnvironmentConfig(),
				LangManager: &mockLangManager{},
				Logger:      slog.Default(),
			},
		}

		assert.Equal(t, 30*time.Minute, h.getRememberMeTTL("oidc-client", ""))
		assert.True(t, h.shouldShowRememberMe("oidc-client", ""))
	})

	t.Run("Legacy SAML service provider value is used as fallback", func(t *testing.T) {
		h := &FrontendHandler{
			deps: &deps.Deps{
				Cfg: &mockFrontendCfg{
					FileSettings: config.FileSettings{
						IdP: &config.IdPSection{
							SAML2: config.SAML2Config{
								ServiceProviders: []config.SAML2ServiceProvider{
									{EntityID: "sp-entity", RememberMeTTL: time.Hour},
								},
							},
						},
					},
				},
				Env:         config.NewTestEnvironmentConfig(),
				LangManager: &mockLangManager{},
				Logger:      slog.Default(),
			},
		}

		assert.Equal(t, time.Hour, h.getRememberMeTTL("", "sp-entity"))
		assert.True(t, h.shouldShowRememberMe("", "sp-entity"))
	})

	t.Run("Unset values disable remember me", func(t *testing.T) {
		h := &FrontendHandler{
			deps: &deps.Deps{
				Cfg: &mockFrontendCfg{
					FileSettings: config.FileSettings{
						IdP: &config.IdPSection{},
					},
				},
				Env:         config.NewTestEnvironmentConfig(),
				LangManager: &mockLangManager{},
				Logger:      slog.Default(),
			},
		}

		assert.Equal(t, time.Duration(0), h.getRememberMeTTL("missing", ""))
		assert.False(t, h.shouldShowRememberMe("missing", ""))
	})
}

func TestIsMFAMethodSupported(t *testing.T) {
	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IdP: &config.IdPSection{
						OIDC: config.OIDCConfig{
							Clients: []config.OIDCClient{
								{
									ClientID:     "oidc-client",
									SupportedMFA: []string{definitions.MFAMethodWebAuthn},
								},
							},
						},
					},
				},
			},
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.Default(),
		},
	}

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIdPFlowType: definitions.ProtoOIDC,
		definitions.SessionKeyIdPClientID: "oidc-client",
	}}

	assert.True(t, h.isMFAMethodSupported(mgr, definitions.MFAMethodWebAuthn))
	assert.False(t, h.isMFAMethodSupported(mgr, definitions.MFAMethodTOTP))
}

func TestIsMFAMethodSupported_DefaultsToAllWhenUnset(t *testing.T) {
	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IdP: &config.IdPSection{
						OIDC: config.OIDCConfig{
							Clients: []config.OIDCClient{
								{
									ClientID: "oidc-client",
								},
							},
						},
					},
				},
			},
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.Default(),
		},
	}

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIdPFlowType: definitions.ProtoOIDC,
		definitions.SessionKeyIdPClientID: "oidc-client",
	}}

	assert.True(t, h.isMFAMethodSupported(mgr, definitions.MFAMethodWebAuthn))
	assert.True(t, h.isMFAMethodSupported(mgr, definitions.MFAMethodTOTP))
	assert.True(t, h.isMFAMethodSupported(mgr, definitions.MFAMethodRecoveryCodes))
}

func TestCheckRequireMFARegistrationAndRedirectClearsStaleSessionState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/login/mfa", nil)

	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IdP: &config.IdPSection{
						OIDC: config.OIDCConfig{
							Clients: []config.OIDCClient{{
								ClientID:     "different-client",
								RequireMFA:   []string{definitions.MFAMethodRecoveryCodes},
								GrantTypes:   []string{definitions.OIDCFlowAuthorizationCode},
								RedirectURIs: []string{"https://example.invalid/callback"},
							}},
						},
					},
				},
			},
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.Default(),
		},
	}

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIdPFlowID:         "flow-require-mfa",
		definitions.SessionKeyRequireMFAFlow:    true,
		definitions.SessionKeyRequireMFAPending: definitions.MFAMethodRecoveryCodes,
		definitions.SessionKeyIdPFlowType:       definitions.ProtoOIDC,
		definitions.SessionKeyIdPClientID:       "stale-client",
		definitions.SessionKeyAccount:           "testuser",
	}}

	redirected := h.checkRequireMFARegistrationAndRedirect(ctx, mgr)

	assert.False(t, redirected)
	assert.False(t, mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyRequireMFAPending, ""))
	assert.Equal(t, "flow-require-mfa", mgr.GetString(definitions.SessionKeyIdPFlowID, ""))
	assert.Equal(t, definitions.ProtoOIDC, mgr.GetString(definitions.SessionKeyIdPFlowType, ""))
	assert.Empty(t, recorder.Header().Get("Location"))
	assert.Equal(t, http.StatusOK, recorder.Code)
}

func TestHasRecoveryCodesForRequireMFASessionSavedFlag(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/mfa/recovery/register", nil)

	h := &FrontendHandler{}
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyRecoveryCodesSaved: true,
	}}

	user := backend.NewUser("test-user", "", "uid-123")

	assert.True(t, h.hasRecoveryCodesForRequireMFA(ctx, mgr, user))
}

func TestHasRecoveryCodesForRequireMFANoRecoveryData(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/mfa/recovery/register", nil)

	h := &FrontendHandler{}
	mgr := &mockCookieManager{data: map[string]any{}}

	user := backend.NewUser("test-user", "", "uid-123")

	assert.False(t, h.hasRecoveryCodesForRequireMFA(ctx, mgr, user))
}

func loadMFASelectTemplate(t *testing.T) *template.Template {
	t.Helper()

	path := filepath.Join("..", "..", "..", "..", "static", "templates", "idp_mfa_select.html")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read template: %v", err)
	}

	tmpl := template.New("idp_mfa_select.html")
	_, err = tmpl.Parse("{{ define \"idp_header.html\" }}header{{ end }}{{ define \"idp_footer.html\" }}footer{{ end }}")
	if err != nil {
		t.Fatalf("failed to parse base templates: %v", err)
	}

	_, err = tmpl.Parse(string(content))
	if err != nil {
		t.Fatalf("failed to parse select template: %v", err)
	}

	return tmpl
}

func TestRegisterWebAuthnAllowsExistingSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.SetHTMLTemplate(template.Must(template.New("idp_webauthn_register.html").Parse("ok")))

	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg:         &mockFrontendCfg{},
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.Default(),
		},
	}

	r.GET("/mfa/webauthn/register", func(c *gin.Context) {
		localizer := i18n.NewLocalizer((&mockLangManager{}).GetBundle(), "en")
		c.Set(definitions.CtxLocalizedKey, localizer)

		mgr := &mockCookieManager{data: map[string]any{
			definitions.SessionKeyUniqueUserID: "uid-123",
			definitions.SessionKeyAccount:      "testuser",
		}}
		c.Set(definitions.CtxSecureDataKey, mgr)

		h.RegisterWebAuthn(c)
	})

	resp := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/mfa/webauthn/register", nil)
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestRegisterWebAuthnRedirectsWithoutSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.SetHTMLTemplate(template.Must(template.New("idp_webauthn_register.html").Parse("ok")))

	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg:         &mockFrontendCfg{},
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.Default(),
		},
	}

	r.GET("/mfa/webauthn/register", func(c *gin.Context) {
		localizer := i18n.NewLocalizer((&mockLangManager{}).GetBundle(), "en")
		c.Set(definitions.CtxLocalizedKey, localizer)

		// No cookie manager set - simulates no session
		h.RegisterWebAuthn(c)
	})

	resp := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/mfa/webauthn/register", nil)
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusFound, resp.Code)
	assert.Equal(t, "/login", resp.Header().Get("Location"))
}

func TestLoggedOutRoute_DoesNotSetSecureDataCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())

	r := gin.New()
	r.SetHTMLTemplate(template.Must(template.New("idp_logged_out.html").Parse("ok")))

	d := &deps.Deps{
		Cfg:         &mockFrontendCfg{},
		Env:         config.NewTestEnvironmentConfig(),
		LangManager: &mockLangManager{},
		Logger:      slog.Default(),
	}

	h := NewFrontendHandler(d)
	h.Register(r)

	resp := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/logged_out/en", nil)
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)

	seenLanguageCookie := false

	for _, c := range resp.Result().Cookies() {
		assert.NotEqual(t, definitions.SecureDataCookieName, c.Name)
		if c.Name == definitions.LanguageCookieName {
			seenLanguageCookie = true
			assert.Equal(t, "en", c.Value)
			assert.Greater(t, c.MaxAge, 0)
		}
	}

	assert.True(t, seenLanguageCookie)
}
