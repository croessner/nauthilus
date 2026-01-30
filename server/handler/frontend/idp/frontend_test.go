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

	"github.com/croessner/nauthilus/server/config"
	corelang "github.com/croessner/nauthilus/server/core/language"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
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
	store := cookie.NewStore([]byte("secret"))
	cfg := &mockFrontendCfg{}

	t.Run("Basic Session Data", func(t *testing.T) {
		r := gin.New()
		r.Use(sessions.Sessions("test-session", store))
		r.GET("/test", func(c *gin.Context) {
			session := sessions.Default(c)
			session.Set(definitions.CookieAccount, "testuser")
			session.Set(definitions.CookieLang, "de")
			session.Save()

			lm := &mockLangManager{}
			localizer := i18n.NewLocalizer(lm.GetBundle(), "de")
			c.Set(definitions.CtxLocalizedKey, localizer)

			data := BasePageData(c, cfg, lm)
			assert.Equal(t, "de", data["LanguageTag"])
			assert.Equal(t, "testuser", data["Username"])
			c.Status(http.StatusOK)
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)
	})
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

	t.Run("getMFAURL with params", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request, _ = http.NewRequest("GET", "/login/en?client_id=foo", nil)
		ctx.Params = gin.Params{{Key: "languageTag", Value: "en"}}

		url := h.getMFAURL(ctx, "webauthn")
		assert.Equal(t, "/login/webauthn/en?client_id=foo", url)
	})

	t.Run("getMFAURL for begin with params", func(t *testing.T) {
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request, _ = http.NewRequest("GET", "/login/webauthn/en?client_id=foo", nil)
		ctx.Params = gin.Params{{Key: "languageTag", Value: "en"}}

		url := h.getMFAURL(ctx, "webauthn/begin")
		assert.Equal(t, "/login/webauthn/begin/en?client_id=foo", url)
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
		"QueryString":          "?return_to=foo",
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
	assert.Contains(t, output, "/login/totp?return_to=foo")
	assert.Contains(t, output, "/login/webauthn?return_to=foo")
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
		"QueryString":          "?return_to=foo",
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
	assert.Contains(t, output, "/login/totp?return_to=foo")
	assert.Contains(t, output, "/login/webauthn?return_to=foo")
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
	store := cookie.NewStore([]byte("secret"))

	r := gin.New()
	r.Use(sessions.Sessions("test-session", store))
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

		session := sessions.Default(c)
		session.Set(definitions.CookieUniqueUserID, "uid-123")
		session.Set(definitions.CookieAccount, "testuser")
		session.Set(definitions.CookieLang, "en")
		_ = session.Save()

		h.RegisterWebAuthn(c)
	})

	resp := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/mfa/webauthn/register", nil)
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestRegisterWebAuthnRedirectsWithoutSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := cookie.NewStore([]byte("secret"))

	r := gin.New()
	r.Use(sessions.Sessions("test-session", store))
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

		h.RegisterWebAuthn(c)
	})

	resp := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/mfa/webauthn/register", nil)
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusFound, resp.Code)
	assert.Equal(t, "/login", resp.Header().Get("Location"))
}
