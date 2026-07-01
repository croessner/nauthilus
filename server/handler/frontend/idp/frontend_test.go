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
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	corelang "github.com/croessner/nauthilus/v3/server/core/language"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	flowdomain "github.com/croessner/nauthilus/v3/server/idp/flow"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
)

const (
	frontendRecoveryRegisterPath = "/mfa/recovery/register"
	frontendTOTPRegisterPath     = "/mfa/totp/register"
	frontendTestAccount          = "testuser"
	frontendTestDisplayName      = "Test User"
	frontendTestUniqueUserID     = "uid-123"
	frontendTestUser             = "test-user"
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

func TestParseSubmittedMasterUserFallsBackToCanonicalizedDefaultFormat(t *testing.T) {
	handler := &FrontendHandler{}
	targetUser := &backend.User{Name: "target@example.test"}

	target, master, ok := handler.parseSubmittedMasterUser("target@example.test*master@example.test", targetUser)

	assert.True(t, ok)
	assert.Equal(t, "target@example.test", target)
	assert.Equal(t, "master@example.test", master)
}

func TestParseSubmittedMasterUserRejectsUncanonicalizedDefaultFormat(t *testing.T) {
	handler := &FrontendHandler{}
	targetUser := &backend.User{Name: "someone@example.test"}

	_, _, ok := handler.parseSubmittedMasterUser("target@example.test*master@example.test", targetUser)

	assert.False(t, ok)
}

func TestBasePageData(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &mockFrontendCfg{}

	t.Run("Basic Session Data", func(t *testing.T) {
		assertBasePageBasicSessionData(t, cfg)
	})

	t.Run("Includes legal links from IDP config", func(t *testing.T) {
		assertBasePageLegalLinks(t)
	})

	for _, tt := range basePageIDPClientNameTests() {
		t.Run(tt.name, func(t *testing.T) {
			assertBasePageIDPClientName(t, tt.cfg, tt.sessionData, tt.expectedName)
		})
	}
}

type basePageIDPClientNameTest struct {
	name         string
	cfg          *mockFrontendCfg
	sessionData  map[string]any
	expectedName string
}

// basePageIDPClientNameTests returns OIDC and SAML display-name cases.
func basePageIDPClientNameTests() []basePageIDPClientNameTest {
	return []basePageIDPClientNameTest{
		{
			name: "OIDC Client Name",
			cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IDP: &config.IDPSection{
						OIDC: config.OIDCConfig{
							Clients: []config.OIDCClient{
								{ClientID: "client-1", Name: "Client One"},
							},
						},
					},
				},
			},
			sessionData: map[string]any{
				definitions.SessionKeyIDPFlowType: definitions.ProtoOIDC,
				definitions.SessionKeyIDPClientID: "client-1",
			},
			expectedName: "Client One",
		},
		{
			name: "SAML Service Provider Name",
			cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IDP: &config.IDPSection{
						SAML2: config.SAML2Config{
							ServiceProviders: []config.SAML2ServiceProvider{
								{EntityID: "sp-1", Name: "Example SP"},
							},
						},
					},
				},
			},
			sessionData: map[string]any{
				definitions.SessionKeyIDPFlowType:     definitions.ProtoSAML,
				definitions.SessionKeyIDPSAMLEntityID: "sp-1",
			},
			expectedName: "Example SP",
		},
	}
}

// assertBasePageBasicSessionData verifies common session-backed template values.
func assertBasePageBasicSessionData(t *testing.T, cfg *mockFrontendCfg) {
	t.Helper()

	sessionData := map[string]any{definitions.SessionKeyAccount: "testuser"}
	cookieLang := "de"
	runBasePageDataRequest(t, cfg, sessionData, cookieLang, func(data gin.H) {
		assert.Equal(t, "de", data["LanguageTag"])
		assert.Equal(t, "testuser", data["Username"])
		assert.Equal(t, "nonce-123", data["CSPNonce"])
		assert.Equal(t, "Logout", data["Logout"])
	})
}

// assertBasePageLegalLinks verifies legal link URLs and labels.
func assertBasePageLegalLinks(t *testing.T) {
	t.Helper()

	cfgWithLegalLinks := &mockFrontendCfg{
		FileSettings: config.FileSettings{
			IDP: &config.IDPSection{
				TermsOfServiceURL:    "https://example.com/legal",
				PrivacyPolicyURL:     "https://example.com/privacy",
				PasswordForgottenURL: "https://example.com/forgot",
			},
		},
	}

	runBasePageDataRequest(t, cfgWithLegalLinks, nil, "", func(data gin.H) {
		assert.Equal(t, "https://example.com/legal", data["TermsOfServiceURL"])
		assert.Equal(t, "https://example.com/privacy", data["PrivacyPolicyURL"])
		assert.Equal(t, "https://example.com/forgot", data["PasswordForgottenURL"])
		assert.Equal(t, "Legal notice", data["LegalNoticeLabel"])
		assert.Equal(t, "Privacy policy", data["PrivacyPolicyLabel"])
		assert.Equal(t, "Forgot password?", data["PasswordForgottenLabel"])
	})
}

// assertBasePageIDPClientName verifies OIDC and SAML client-name resolution.
func assertBasePageIDPClientName(
	t *testing.T,
	cfg *mockFrontendCfg,
	sessionData map[string]any,
	expectedName string,
) {
	t.Helper()

	runBasePageDataRequest(t, cfg, sessionData, "", func(data gin.H) {
		assert.Equal(t, expectedName, data["IDPClientName"])
	})
}

// runBasePageDataRequest executes BasePageData inside a Gin request context.
func runBasePageDataRequest(
	t *testing.T,
	cfg *mockFrontendCfg,
	sessionData map[string]any,
	cookieLang string,
	assertData func(gin.H),
) {
	t.Helper()

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		lm := &mockLangManager{}
		localizer := i18n.NewLocalizer(lm.GetBundle(), "en")
		c.Set(definitions.CtxLocalizedKey, localizer)
		c.Set(definitions.CtxCSPNonceKey, "nonce-123")

		if sessionData != nil {
			c.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: sessionData})
		}

		assertData(BasePageData(c, cfg, lm))
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()

	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	if cookieLang != "" {
		req.AddCookie(&http.Cookie{Name: definitions.LanguageCookieName, Value: cookieLang})
	}

	r.ServeHTTP(w, req)
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
	output := renderMFASelectTemplate(t, map[string]any{
		"HaveRecoveryCodes": true,
		"RecommendedMethod": "totp",
		"HasOtherMethods":   true,
	})

	assert.Contains(t, output, "autofocus")
	assert.Contains(t, output, "Other methods")
	assert.Contains(t, output, "/login/totp")
	assert.Contains(t, output, "/login/webauthn")
}

func TestMFASelectTemplateWithoutRecommendation(t *testing.T) {
	output := renderMFASelectTemplate(t, nil)

	assert.NotContains(t, output, "<details")
	assert.NotContains(t, output, "autofocus")
	assert.Contains(t, output, "/login/totp")
	assert.Contains(t, output, "/login/webauthn")
}

func TestIDPLoginTemplateRendersForgotPasswordLinkWithURL(t *testing.T) {
	tmpl := loadIDPLoginTemplate(t)

	passwordForgotten := "https://example.com/forgot"

	output := renderIDPLoginTemplate(t, tmpl, passwordForgotten)

	assert.Contains(t, output, "href=\""+passwordForgotten+"\"")
	assert.Contains(t, output, "label-text idp-forgot-password-link text-sm")
	assert.Contains(t, output, ">Forgot password?</a>")
	assert.NotContains(t, output, ">Legal notice</a>")
	assert.NotContains(t, output, ">Privacy policy</a>")
	assert.Contains(t, output, "rel=\"noopener noreferrer\"")
}

func TestIDPLoginTemplateHidesLinksWithoutURLs(t *testing.T) {
	tmpl := loadIDPLoginTemplate(t)

	output := renderIDPLoginTemplate(t, tmpl, "")

	assert.NotContains(t, output, "Forgot password?</a>")
	assert.NotContains(t, output, ">Legal notice</a>")
	assert.NotContains(t, output, ">Privacy policy</a>")
}

func TestIDPFooterTemplateRendersLinksWithURLs(t *testing.T) {
	tmpl := loadIDPFooterTemplate(t)

	output := renderIDPFooterTemplate(t, tmpl, "https://example.com/legal", "https://example.com/privacy")

	assert.Contains(t, output, "href=\"https://example.com/legal\"")
	assert.Contains(t, output, "href=\"https://example.com/privacy\"")
	assert.Contains(t, output, ">Legal notice</a>")
	assert.Contains(t, output, ">Privacy policy</a>")
}

func TestIDPFooterTemplateHidesLinksWithoutURLs(t *testing.T) {
	tmpl := loadIDPFooterTemplate(t)

	output := renderIDPFooterTemplate(t, tmpl, "", "")

	assert.NotContains(t, output, ">Legal notice</a>")
	assert.NotContains(t, output, ">Privacy policy</a>")
}

func TestIDPUISubmitDisableDefersNativeFormHandling(t *testing.T) {
	script := loadIDPUIScript(t)

	assert.Contains(t, script, "function deferNativeFormSubmitDisable(form, submitter)")
	assert.Contains(t, script, "window.setTimeout(() => {")
	assert.Contains(t, script, "deferNativeFormSubmitDisable(form, submitter);")
}

func TestIDPUIRecoveryCodesDownloadUsesPDF(t *testing.T) {
	script := loadIDPUIScript(t)

	assert.Contains(t, script, "function buildRecoveryCodesPdfBlob(codes)")
	assert.Contains(t, script, "application/pdf")
	assert.Contains(t, script, "recovery-codes.pdf")
	assert.NotContains(t, script, "buildRecoveryCodesPngDataURL")
	assert.NotContains(t, script, "toDataURL('image/png')")
	assert.NotContains(t, script, "recovery-codes.png")
}

func TestIDPUIRecoveryDownloadEnablesVisualTargetState(t *testing.T) {
	script := loadIDPUIScript(t)
	modal := loadStaticTemplate(t, "idp_recovery_codes_modal.html")

	assert.Contains(t, script, "function enableRecoveryTarget(selector)")
	assert.Contains(t, script, "target.classList.remove('btn-disabled')")
	assert.Contains(t, script, "target.classList.add(...enabledClasses.split")
	assert.Contains(t, script, "target.focus()")
	assert.Contains(t, script, "target.removeAttribute('aria-disabled')")
	assert.Contains(t, script, "markRecoveryDownloadComplete(trigger)")
	assert.Contains(t, modal, `data-enable-target="#recovery-modal-close"`)
	assert.Contains(t, modal, `data-enable-class="btn-primary"`)
	assert.Contains(t, modal, `data-focus-on-enable="1"`)
	assert.Contains(t, modal, `id="recovery-modal-close"`)
}

func TestIDPUIRecoveryCodesDistinguishesDigitsVisually(t *testing.T) {
	script := loadIDPUIScript(t)

	assert.Contains(t, script, "function decorateRecoveryCodes(root)")
	assert.Contains(t, script, "span.className = 'text-info font-bold'")
	assert.Contains(t, script, "function appendRecoveryCodePdfText(content, code, x, y)")
	assert.Contains(t, script, "0.05 0.38 0.85 rg")
	assert.Contains(t, script, "decorateRecoveryCodes(document)")
}

func renderIDPLoginTemplate(t *testing.T, tmpl *template.Template, passwordForgottenURL string) string {
	t.Helper()

	data := map[string]any{
		"Title":                  "Login",
		"PostLoginEndpoint":      "/login",
		"CSRFToken":              "dev-token",
		"UsernameLabel":          "Username",
		"UsernamePlaceholder":    "name",
		"PasswordLabel":          "Password",
		"PasswordPlaceholder":    "pass",
		"Submit":                 "Submit",
		"RememberMeLabel":        "Remember me",
		"PasswordForgottenURL":   passwordForgottenURL,
		"PasswordForgottenLabel": "Forgot password?",
	}

	var buf bytes.Buffer

	err := tmpl.Execute(&buf, data)
	assert.NoError(t, err)

	return buf.String()
}

// renderMFASelectTemplate renders the MFA selection template with stable baseline labels.
func renderMFASelectTemplate(t *testing.T, overrides map[string]any) string {
	t.Helper()

	tmpl := loadMFASelectTemplate(t)

	data := mfaSelectTemplateData()
	for key, value := range overrides {
		data[key] = value
	}

	var buf bytes.Buffer

	err := tmpl.Execute(&buf, data)
	assert.NoError(t, err)

	return buf.String()
}

// mfaSelectTemplateData returns the default template data shared by MFA selection tests.
func mfaSelectTemplateData() map[string]any {
	return map[string]any{
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
}

func renderIDPFooterTemplate(t *testing.T, tmpl *template.Template, termsOfServiceURL, privacyPolicyURL string) string {
	t.Helper()

	data := map[string]any{
		"TermsOfServiceURL":  termsOfServiceURL,
		"PrivacyPolicyURL":   privacyPolicyURL,
		"LegalNoticeLabel":   "Legal notice",
		"PrivacyPolicyLabel": "Privacy policy",
	}

	var buf bytes.Buffer

	err := tmpl.Execute(&buf, data)
	assert.NoError(t, err)

	return buf.String()
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
				definitions.SessionKeyIDPFlowType: definitions.ProtoOIDC,
				definitions.SessionKeyIDPClientID: "oidc-client",
			},
			expectedOIDCCID: "oidc-client",
		},
		{
			name: "SAML flow returns entity ID",
			sessionData: map[string]any{
				definitions.SessionKeyIDPFlowType:     definitions.ProtoSAML,
				definitions.SessionKeyIDPSAMLEntityID: "sp-entity",
			},
			expectedSAMLEntID: "sp-entity",
		},
		{
			name: "Unknown flow returns empty identifiers",
			sessionData: map[string]any{
				definitions.SessionKeyIDPFlowType: "invalid",
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
	cases := []struct {
		name         string
		idpConfig    *config.IDPSection
		expectations []rememberMeTTLExpectation
	}{
		{
			name:      "Global setting overrides legacy client and service provider values",
			idpConfig: globalRememberMeIDPConfig(),
			expectations: []rememberMeTTLExpectation{
				{oidcClientID: "oidc-client", ttl: 2 * time.Hour, show: true},
				{samlEntityID: "sp-entity", ttl: 2 * time.Hour, show: true},
				{ttl: 2 * time.Hour, show: true},
			},
		},
		{
			name:      "Legacy OIDC client value is used as fallback",
			idpConfig: legacyOIDCRememberMeIDPConfig(),
			expectations: []rememberMeTTLExpectation{
				{oidcClientID: "oidc-client", ttl: 30 * time.Minute, show: true},
			},
		},
		{
			name:      "Legacy SAML service provider value is used as fallback",
			idpConfig: legacySAMLRememberMeIDPConfig(),
			expectations: []rememberMeTTLExpectation{
				{samlEntityID: "sp-entity", ttl: time.Hour, show: true},
			},
		},
		{
			name:      "Unset values disable remember me",
			idpConfig: &config.IDPSection{},
			expectations: []rememberMeTTLExpectation{
				{oidcClientID: "missing", ttl: 0, show: false},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assertRememberMeTTLExpectations(t, newRememberMeTTLHandler(tt.idpConfig), tt.expectations)
		})
	}
}

type rememberMeTTLExpectation struct {
	oidcClientID string
	samlEntityID string
	ttl          time.Duration
	show         bool
}

// globalRememberMeIDPConfig returns an IDP config with a global remember-me TTL.
func globalRememberMeIDPConfig() *config.IDPSection {
	return &config.IDPSection{
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
	}
}

// legacyOIDCRememberMeIDPConfig returns an IDP config with a legacy OIDC TTL.
func legacyOIDCRememberMeIDPConfig() *config.IDPSection {
	return &config.IDPSection{
		OIDC: config.OIDCConfig{
			Clients: []config.OIDCClient{
				{ClientID: "oidc-client", RememberMeTTL: 30 * time.Minute},
			},
		},
	}
}

// legacySAMLRememberMeIDPConfig returns an IDP config with a legacy SAML TTL.
func legacySAMLRememberMeIDPConfig() *config.IDPSection {
	return &config.IDPSection{
		SAML2: config.SAML2Config{
			ServiceProviders: []config.SAML2ServiceProvider{
				{EntityID: "sp-entity", RememberMeTTL: time.Hour},
			},
		},
	}
}

// newRememberMeTTLHandler creates a frontend handler for remember-me TTL tests.
func newRememberMeTTLHandler(idpConfig *config.IDPSection) *FrontendHandler {
	return &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{IDP: idpConfig},
			},
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.Default(),
		},
	}
}

// assertRememberMeTTLExpectations verifies TTL and visibility for each lookup.
func assertRememberMeTTLExpectations(
	t *testing.T,
	handler *FrontendHandler,
	expectations []rememberMeTTLExpectation,
) {
	t.Helper()

	for _, expectation := range expectations {
		assert.Equal(t, expectation.ttl, handler.getRememberMeTTL(expectation.oidcClientID, expectation.samlEntityID))
		assert.Equal(t, expectation.show, handler.shouldShowRememberMe(expectation.oidcClientID, expectation.samlEntityID))
	}
}

func TestIsMFAMethodSupported(t *testing.T) {
	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IDP: &config.IDPSection{
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
		definitions.SessionKeyIDPFlowType: definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID: "oidc-client",
	}}

	assert.True(t, h.isMFAMethodSupported(mgr, definitions.MFAMethodWebAuthn))
	assert.False(t, h.isMFAMethodSupported(mgr, definitions.MFAMethodTOTP))
}

func TestIsMFAMethodSupported_DefaultsToAllWhenUnset(t *testing.T) {
	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IDP: &config.IDPSection{
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
		definitions.SessionKeyIDPFlowType: definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID: "oidc-client",
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

	h := newOIDCRequireMFATestHandler("different-client", []string{definitions.MFAMethodRecoveryCodes})

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyIDPFlowID:         "flow-require-mfa",
		definitions.SessionKeyRequireMFAFlow:    true,
		definitions.SessionKeyRequireMFAPending: definitions.MFAMethodRecoveryCodes,
		definitions.SessionKeyIDPFlowType:       definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID:       "stale-client",
		definitions.SessionKeyAccount:           "testuser",
	}}

	redirected := h.checkRequireMFARegistrationAndRedirect(ctx, mgr)

	assert.False(t, redirected)
	assert.False(t, mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyRequireMFAPending, ""))
	assert.Equal(t, "flow-require-mfa", mgr.GetString(definitions.SessionKeyIDPFlowID, ""))
	assert.Equal(t, definitions.ProtoOIDC, mgr.GetString(definitions.SessionKeyIDPFlowType, ""))
	assert.Empty(t, recorder.Header().Get("Location"))
	assert.Equal(t, http.StatusOK, recorder.Code)
}

func TestExistingSessionRequireMFAResumeRedirectsToStepUp(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/login/en", nil)
	ctx.Params = gin.Params{{Key: "languageTag", Value: "en"}}

	h := newOIDCRequireMFATestHandler("oidc-client", []string{definitions.MFAMethodTOTP})
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:      "alice",
		definitions.SessionKeyUniqueUserID: "alice-id",
		definitions.SessionKeyDisplayName:  "Alice Example",
		definitions.SessionKeySubject:      "alice-id",
		definitions.SessionKeyIDPFlowType:  definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID:  "oidc-client",
	}}

	redirected := h.redirectExistingSessionMFAAssurance(ctx, mgr)

	assert.True(t, redirected)
	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.Equal(t, "/login/mfa/en", recorder.Header().Get("Location"))
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyUsername, ""))
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyMFAAccount, ""))
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyMFAFactorAccount, ""))
	assert.True(t, mgr.HasKey(definitions.SessionKeyAuthResult))
}

// newOIDCRequireMFATestHandler builds a frontend handler with one require-MFA OIDC client.
func newOIDCRequireMFATestHandler(clientID string, requireMFA []string) *FrontendHandler {
	return &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IDP: &config.IDPSection{
						OIDC: config.OIDCConfig{
							Clients: []config.OIDCClient{{
								ClientID:     clientID,
								RequireMFA:   requireMFA,
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
}

func TestLoginWebAuthnRebuildsExistingSessionRequireMFAStepUp(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					IDP: &config.IDPSection{
						OIDC: config.OIDCConfig{
							Clients: []config.OIDCClient{{
								ClientID:   "oidc-client",
								RequireMFA: []string{definitions.MFAMethodWebAuthn},
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
		definitions.SessionKeyAccount:      "alice",
		definitions.SessionKeyUniqueUserID: "alice-id",
		definitions.SessionKeyDisplayName:  "Alice Example",
		definitions.SessionKeySubject:      "alice-id",
		definitions.SessionKeyIDPFlowType:  definitions.ProtoOIDC,
		definitions.SessionKeyIDPClientID:  "oidc-client",
	}}

	router := gin.New()
	router.SetHTMLTemplate(template.Must(template.New("webauthn-step-up").Parse(`
{{ define "idp_webauthn_verify.html" }}webauthn step-up{{ end }}
`)))
	router.GET("/login/webauthn/en", func(ctx *gin.Context) {
		ctx.Set(definitions.CtxLocalizedKey, i18n.NewLocalizer((&mockLangManager{}).GetBundle(), "en"))
		ctx.Set(definitions.CtxSecureDataKey, mgr)
		ctx.Params = gin.Params{{Key: "languageTag", Value: "en"}}
		h.LoginWebAuthn(ctx)
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/login/webauthn/en", nil)

	router.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyUsername, ""))
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyMFAAccount, ""))
	assert.True(t, mgr.HasKey(definitions.SessionKeyAuthResult))
	assert.Contains(t, recorder.Body.String(), "webauthn step-up")
}

func TestHasCompletedMethodForRequireMFA(t *testing.T) {
	testCases := []struct {
		name  string
		path  string
		data  map[string]any
		check func(*FrontendHandler, *gin.Context, *mockCookieManager, *backend.User) bool
		want  bool
	}{
		{
			name: "recovery codes session saved flag",
			path: frontendRecoveryRegisterPath,
			data: map[string]any{
				definitions.SessionKeyRecoveryCodesSaved: true,
			},
			check: func(h *FrontendHandler, ctx *gin.Context, mgr *mockCookieManager, user *backend.User) bool {
				return h.hasRecoveryCodesForRequireMFA(ctx, mgr, user)
			},
			want: true,
		},
		{
			name: "recovery codes no data",
			path: frontendRecoveryRegisterPath,
			data: map[string]any{},
			check: func(h *FrontendHandler, ctx *gin.Context, mgr *mockCookieManager, user *backend.User) bool {
				return h.hasRecoveryCodesForRequireMFA(ctx, mgr, user)
			},
			want: false,
		},
		{
			name: "TOTP session flag",
			path: frontendTOTPRegisterPath,
			data: map[string]any{
				definitions.SessionKeyHaveTOTP: true,
			},
			check: func(h *FrontendHandler, ctx *gin.Context, mgr *mockCookieManager, user *backend.User) bool {
				return h.hasTOTPForRequireMFA(ctx, mgr, user)
			},
			want: true,
		},
		{
			name: "TOTP no session or attribute data",
			path: frontendTOTPRegisterPath,
			data: map[string]any{},
			check: func(h *FrontendHandler, ctx *gin.Context, mgr *mockCookieManager, user *backend.User) bool {
				return h.hasTOTPForRequireMFA(ctx, mgr, user)
			},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newFrontendTestContext(tc.path)
			h := &FrontendHandler{}
			mgr := &mockCookieManager{data: tc.data}

			assert.Equal(t, tc.want, tc.check(h, ctx, mgr, newFrontendTestUser()))
		})
	}
}

func TestMFASelfServiceTOTPDeleteRejectsMissingStepUp(t *testing.T) {
	handler, provider := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodDelete, "/mfa/totp", map[string]any{
		definitions.SessionKeyAccount:     "alice",
		definitions.SessionKeyUserBackend: uint8(definitions.BackendLDAP),
	}, nil)

	handler.DeleteTOTP(ctx)

	assertMFASelfServiceStepUpRejected(t, recorder, provider.deleteTOTPCalls)
}

func TestMFASelfServiceTOTPDeleteRejectsStaleStepUp(t *testing.T) {
	handler, provider := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodDelete, "/mfa/totp", map[string]any{
		definitions.SessionKeyAccount:        "alice",
		definitions.SessionKeyUserBackend:    uint8(definitions.BackendLDAP),
		definitions.SessionKeyMFACompleted:   true,
		definitions.SessionKeyMFAMethod:      definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceAt: time.Now().Add(-25 * time.Hour).Unix(),
	}, nil)

	handler.DeleteTOTP(ctx)

	assertMFASelfServiceStepUpRejected(t, recorder, provider.deleteTOTPCalls)
}

func TestMFASelfServiceTOTPDeletePermitsFreshStepUp(t *testing.T) {
	handler, provider := newMFASelfServiceTestHandler()
	ctx, _ := newMFASelfServiceContext(http.MethodDelete, "/mfa/totp", map[string]any{
		definitions.SessionKeyAccount:        "alice",
		definitions.SessionKeyUserBackend:    uint8(definitions.BackendLDAP),
		definitions.SessionKeyMFACompleted:   true,
		definitions.SessionKeyMFAMethod:      definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceAt: time.Now().Unix(),
	}, nil)

	handler.DeleteTOTP(ctx)

	assert.Equal(t, 1, provider.deleteTOTPCalls)
}

func TestMFASelfServiceWebAuthnDeleteRejectsMissingStepUp(t *testing.T) {
	handler, _ := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodDelete, "/mfa/webauthn", map[string]any{
		definitions.SessionKeyAccount:      "alice",
		definitions.SessionKeyUniqueUserID: "uid-123",
	}, nil)

	handler.DeleteWebAuthn(ctx)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "Recent MFA verification required")
}

func TestMFASelfServiceRecoveryRegenerationRejectsMissingStepUp(t *testing.T) {
	handler, provider := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodPost, "/mfa/recovery/generate", map[string]any{
		definitions.SessionKeyAccount:     "alice",
		definitions.SessionKeyUserBackend: uint8(definitions.BackendLDAP),
	}, nil)

	handler.PostGenerateRecoveryCodes(ctx)

	assertMFASelfServiceStepUpRejected(t, recorder, provider.generateRecoveryCalls)
}

func assertMFASelfServiceStepUpRejected(t *testing.T, recorder *httptest.ResponseRecorder, mutationCalls int) {
	t.Helper()

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Zero(t, mutationCalls)
	assert.Contains(t, recorder.Body.String(), "Recent MFA verification required")
}

type mfaSelfServiceProvider struct {
	deleteTOTPCalls       int
	generateRecoveryCalls int
}

func (p *mfaSelfServiceProvider) GenerateTOTPSecret(_ *gin.Context, _ string) (string, string, error) {
	return "", "", errors.New("unexpected GenerateTOTPSecret call")
}

func (p *mfaSelfServiceProvider) VerifyAndSaveTOTP(_ *gin.Context, _ string, _ string, _ string, _ uint8) error {
	return errors.New("unexpected VerifyAndSaveTOTP call")
}

func (p *mfaSelfServiceProvider) VerifyTOTP(_ *gin.Context, _ string, _ string, _ uint8) (bool, error) {
	return false, errors.New("unexpected VerifyTOTP call")
}

func (p *mfaSelfServiceProvider) DeleteTOTP(_ *gin.Context, _ string, _ uint8) error {
	p.deleteTOTPCalls++

	return nil
}

func (p *mfaSelfServiceProvider) GenerateRecoveryCodes(_ *gin.Context, _ string, _ uint8) ([]string, error) {
	p.generateRecoveryCalls++

	return []string{"recovery-one", "recovery-two"}, nil
}

func (p *mfaSelfServiceProvider) SaveRecoveryCodes(_ *gin.Context, _ string, _ []string, _ uint8) error {
	return errors.New("unexpected SaveRecoveryCodes call")
}

func (p *mfaSelfServiceProvider) UseRecoveryCode(_ *gin.Context, _ string, _ string, _ uint8) (bool, error) {
	return false, errors.New("unexpected UseRecoveryCode call")
}

func (p *mfaSelfServiceProvider) DeleteWebAuthnCredential(_ *gin.Context, _ string, _ string, _ uint8) error {
	return errors.New("unexpected DeleteWebAuthnCredential call")
}

func newMFASelfServiceTestHandler() (*FrontendHandler, *mfaSelfServiceProvider) {
	provider := &mfaSelfServiceProvider{}
	handler := &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{
				FileSettings: config.FileSettings{
					Server: &config.ServerSection{
						Redis: config.Redis{Prefix: "test:"},
						Timeouts: config.Timeouts{
							RedisRead:  time.Second,
							RedisWrite: time.Second,
						},
					},
					IDP: &config.IDPSection{},
				},
			},
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.Default(),
		},
		mfa:    provider,
		tracer: monittrace.New("test/frontend"),
	}

	return handler, provider
}

func newMFASelfServiceContext(method string, path string, sessionData map[string]any, body *bytes.Reader) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)

	if sessionData == nil {
		sessionData = make(map[string]any)
	}

	if body == nil {
		body = bytes.NewReader(nil)
	}

	recorder := httptest.NewRecorder()
	ctx, engine := gin.CreateTestContext(recorder)
	engine.SetHTMLTemplate(template.Must(template.New("mfa-self-service").Parse(`
{{ define "idp_error_modal.html" }}{{ .Message }}{{ end }}
{{ define "idp_recovery_codes_modal.html" }}{{ range .Codes }}{{ . }} {{ end }}{{ end }}
`)))

	ctx.Request = httptest.NewRequest(method, path, body)
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: sessionData})
	ctx.Set(definitions.CtxGUIDKey, "test-guid")
	ctx.Set(definitions.CtxLocalizedKey, i18n.NewLocalizer((&mockLangManager{}).GetBundle(), "en"))

	return ctx, recorder
}

func newFrontendTestContext(path string) *gin.Context {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil)

	return ctx
}

func newFrontendTestUser() *backend.User {
	return backend.NewUser(frontendTestUser, "", frontendTestUniqueUserID)
}

func TestLoginMFAViewsDoNotExpose2FAHomeMenuBeforeMFACompletion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := newLoginMFAViewHandler()
	tmpl := loginMFATestTemplate()
	testCases := loginMFAViewCases(h)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assertLoginMFAViewHidesHomeMenu(t, tmpl, tc.path, tc.handler)
		})
	}
}

type loginMFAViewCase struct {
	handler gin.HandlerFunc
	name    string
	path    string
}

// newLoginMFAViewHandler creates a frontend handler for MFA login view tests.
func newLoginMFAViewHandler() *FrontendHandler {
	return &FrontendHandler{
		deps: &deps.Deps{
			Cfg:         &mockFrontendCfg{},
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.Default(),
		},
	}
}

// loginMFATestTemplate returns minimal templates that would expose Username when present.
func loginMFATestTemplate() *template.Template {
	return template.Must(template.New("mfa-login-templates").Parse(`
{{ define "idp_webauthn_verify.html" }}{{ if .Username }}2FA Verwaltung{{ end }}{{ end }}
{{ define "idp_totp_verify.html" }}{{ if .Username }}2FA Verwaltung{{ end }}{{ end }}
{{ define "idp_recovery_login.html" }}{{ if .Username }}2FA Verwaltung{{ end }}{{ end }}
`))
}

// loginMFAViewCases returns the MFA login views that must hide self-service navigation.
func loginMFAViewCases(h *FrontendHandler) []loginMFAViewCase {
	return []loginMFAViewCase{
		{
			name:    "WebAuthn verify page",
			path:    "/login/webauthn/de",
			handler: h.LoginWebAuthn,
		},
		{
			name:    "TOTP verify page",
			path:    "/login/totp/de",
			handler: h.LoginTOTP,
		},
		{
			name:    "Recovery verify page",
			path:    "/login/recovery/de",
			handler: h.LoginRecovery,
		},
	}
}

// assertLoginMFAViewHidesHomeMenu verifies that pending MFA pages omit the 2FA home link.
func assertLoginMFAViewHidesHomeMenu(
	t *testing.T,
	tmpl *template.Template,
	path string,
	handler gin.HandlerFunc,
) {
	t.Helper()

	r := gin.New()
	r.SetHTMLTemplate(tmpl)
	r.Use(loginMFAViewSessionMiddleware())
	r.GET(path, handler)

	resp := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, path, nil)

	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.NotContains(t, resp.Body.String(), "2FA Verwaltung")
}

// loginMFAViewSessionMiddleware installs localized and secure-session state for view tests.
func loginMFAViewSessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		localizer := i18n.NewLocalizer((&mockLangManager{}).GetBundle(), "de")
		c.Set(definitions.CtxLocalizedKey, localizer)
		c.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
			definitions.SessionKeyUsername: "alice",
		}})
		c.Next()
	}
}

func TestDelayedResponseFirstFactorLatchSurvivesTOTPCompletion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyUsername: "alice",
	}}
	cookie.SetAuthResult(mgr, "alice", definitions.AuthResultFail)

	h := &FrontendHandler{
		deps: &deps.Deps{
			Cfg:         &mockFrontendCfg{},
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.Default(),
		},
	}

	tmpl := template.Must(template.New("login-template").Parse(`
{{ define "idp_login.html" }}{{ if .HaveError }}latched failure{{ end }}{{ end }}
`))

	r := gin.New()
	r.SetHTMLTemplate(tmpl)
	r.POST("/login/totp", func(c *gin.Context) {
		localizer := i18n.NewLocalizer((&mockLangManager{}).GetBundle(), "en")
		c.Set(definitions.CtxLocalizedKey, localizer)
		c.Set(definitions.CtxSecureDataKey, mgr)

		handled := h.handleDelayedResponseFailure(c, &mfaSessionState{
			mgr:      mgr,
			username: "alice",
		}, definitions.MFAMethodTOTP)

		assert.True(t, handled)
	})

	resp := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/login/totp", nil)

	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Contains(t, resp.Body.String(), "latched failure")
}

func loadMFASelectTemplate(t *testing.T) *template.Template {
	t.Helper()

	return loadIDPChromeTemplate(t, "idp_mfa_select.html")
}

func loadIDPLoginTemplate(t *testing.T) *template.Template {
	t.Helper()

	return loadIDPChromeTemplate(t, "idp_login.html")
}

// loadIDPChromeTemplate loads templates that depend on shared IDP header and footer definitions.
func loadIDPChromeTemplate(t *testing.T, name string) *template.Template {
	t.Helper()

	tmpl := template.New(name)

	_, err := tmpl.Parse("{{ define \"idp_header.html\" }}header{{ end }}{{ define \"idp_footer.html\" }}footer{{ end }}")
	if err != nil {
		t.Fatalf("failed to parse base templates: %v", err)
	}

	_, err = tmpl.Parse(loadStaticTemplate(t, name))
	if err != nil {
		t.Fatalf("failed to parse template %s: %v", name, err)
	}

	return tmpl
}

func loadIDPFooterTemplate(t *testing.T) *template.Template {
	t.Helper()

	path := filepath.Join("..", "..", "..", "..", "static", "templates", "idp_footer.html")

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read template: %v", err)
	}

	tmpl := template.New("idp_footer.html")

	_, err = tmpl.Parse(string(content))
	if err != nil {
		t.Fatalf("failed to parse footer template: %v", err)
	}

	return tmpl
}

func loadIDPUIScript(t *testing.T) string {
	t.Helper()

	path := filepath.Join("..", "..", "..", "..", "static", "js", "idp_ui.js")

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read script: %v", err)
	}

	return string(content)
}

func loadStaticTemplate(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join("..", "..", "..", "..", "static", "templates", name)

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read template %s: %v", name, err)
	}

	return string(content)
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
			definitions.SessionKeyUniqueUserID: frontendTestUniqueUserID,
			definitions.SessionKeyAccount:      frontendTestAccount,
		}}
		c.Set(definitions.CtxSecureDataKey, mgr)

		h.RegisterWebAuthn(c)
	})

	resp := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/mfa/webauthn/register", nil)
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)
}

func TestRestoreRequireMFAIdentityContextFromFlowState(t *testing.T) {
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyUniqueUserID: "uid-before",
	}}
	state := &flowdomain.State{
		Type: flowdomain.FlowTypeRequireMFA,
		Metadata: map[string]string{
			flowdomain.FlowMetadataAccount:      frontendTestAccount,
			flowdomain.FlowMetadataUniqueUserID: "uid-before",
			flowdomain.FlowMetadataDisplayName:  frontendTestDisplayName,
		},
	}

	restoreRequireMFAIdentityContext(mgr, state)

	assert.Equal(t, frontendTestAccount, mgr.GetString(definitions.SessionKeyAccount, ""))
	assert.Equal(t, "uid-before", mgr.GetString(definitions.SessionKeyUniqueUserID, ""))
	assert.Equal(t, frontendTestDisplayName, mgr.GetString(definitions.SessionKeyDisplayName, ""))
}

func TestRequiredMFAFlowIDsAreIsolatedPerParentFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := &FrontendHandler{
		deps: &deps.Deps{
			Cfg: &mockFrontendCfg{},
		},
	}
	flowIDs := make(map[string]string)

	for _, tc := range []struct {
		name     string
		parentID string
		account  string
		userID   string
	}{
		{name: "alice", parentID: "parent-flow-alice", account: "alice", userID: "uid-alice"},
		{name: "bob", parentID: "parent-flow-bob", account: "bob", userID: "uid-bob"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodGet, "/login", nil)
			mgr := &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount:           tc.account,
				definitions.SessionKeyIDPFlowID:         tc.parentID,
				definitions.SessionKeyProtocol:          definitions.ProtoOIDC,
				definitions.SessionKeyRequireMFAPending: definitions.MFAMethodTOTP,
				definitions.SessionKeyUniqueUserID:      tc.userID,
			}}
			user := &backend.User{
				ID:   tc.userID,
				Name: tc.account,
			}

			redirectURI, redirected := handler.startRequireMFARegistrationFlow(ctx, mgr, user, definitions.ProtoOIDC, []string{definitions.MFAMethodTOTP})
			flowID := mgr.GetString(definitions.SessionKeyIDPFlowID, "")

			assert.True(t, redirected)
			assert.NotEmpty(t, redirectURI)
			assert.NotEmpty(t, flowID)
			assert.NotEqual(t, flowdomain.FlowIDRequireMFA, flowID)
			assert.Equal(t, tc.parentID, mgr.GetString(definitions.SessionKeyRequireMFAParentFlowID, ""))

			flowIDs[tc.name] = flowID
		})
	}

	assert.NotEqual(t, flowIDs["alice"], flowIDs["bob"])
}

func TestRequiredMFAResumeRejectsMismatchedIdentityMetadata(t *testing.T) {
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount: "alice",
	}}
	state := &flowdomain.State{
		Type: flowdomain.FlowTypeRequireMFA,
		Metadata: map[string]string{
			flowdomain.FlowMetadataAccount:      "bob",
			flowdomain.FlowMetadataUniqueUserID: "uid-bob",
			flowdomain.FlowMetadataDisplayName:  "Bob Example",
		},
	}

	restoreRequireMFAIdentityContext(mgr, state)

	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyAccount, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyUniqueUserID, ""))
	assert.Empty(t, mgr.GetString(definitions.SessionKeyDisplayName, ""))
}

func TestRequireMFAFlowIDRequiresParentReference(t *testing.T) {
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyRequireMFAFlow: true,
	}}

	assert.Empty(t, requireMFAFlowIDFromSession(mgr))
}

func TestRequireMFAFlowIDDerivesFromParentReference(t *testing.T) {
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyRequireMFAFlow:         true,
		definitions.SessionKeyRequireMFAParentFlowID: "parent-flow",
	}}

	assert.Equal(t, flowdomain.NewRequireMFAFlowID("parent-flow"), requireMFAFlowIDFromSession(mgr))
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
