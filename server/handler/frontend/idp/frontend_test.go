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
	"github.com/croessner/nauthilus/v3/server/frontend"
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

type mockMultiLangManager struct {
	corelang.Manager
}

func (m *mockMultiLangManager) GetBundle() *i18n.Bundle {
	return i18n.NewBundle(language.English)
}

func (m *mockMultiLangManager) GetTags() []language.Tag {
	return []language.Tag{language.English, language.German}
}

func (m *mockMultiLangManager) GetMatcher() language.Matcher {
	return language.NewMatcher(m.GetTags())
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

	t.Run("Language switch keeps MFA route", func(t *testing.T) {
		assertBasePageLanguageSwitchKeepsMFAPath(t, cfg)
	})

	for _, tt := range basePageIDPClientNameTests() {
		t.Run(tt.name, func(t *testing.T) {
			assertBasePageIDPClientName(t, tt.cfg, tt.sessionData, tt.expectedName)
		})
	}
}

// assertBasePageLanguageSwitchKeepsMFAPath verifies language menu links keep
// the current MFA route while replacing only the language suffix.
func assertBasePageLanguageSwitchKeepsMFAPath(t *testing.T, cfg *mockFrontendCfg) {
	t.Helper()

	r := gin.New()
	r.GET("/login/mfa/:languageTag", func(c *gin.Context) {
		lm := &mockMultiLangManager{}
		c.Set(definitions.CtxLocalizedKey, i18n.NewLocalizer(lm.GetBundle(), "de"))
		c.Params = gin.Params{{Key: "languageTag", Value: "de"}}

		data := BasePageData(c, cfg, lm)
		passive, ok := data["LanguagePassive"].([]frontend.Language)
		assert.True(t, ok)
		assert.Len(t, passive, 1)
		assert.Equal(t, "/login/mfa/en?", passive[0].LanguageLink)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/login/mfa/de", nil)

	r.ServeHTTP(w, req)
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

func TestTwoFAHomeTemplateUsesLocalizedMFASelfServiceEndpoints(t *testing.T) {
	tmpl := template.Must(template.New("idp_2fa_home.html").Funcs(template.FuncMap{
		"int": func(value any) int {
			if converted, ok := value.(int); ok {
				return converted
			}

			return 0
		},
	}).Parse(`{{ define "idp_header.html" }}header{{ end }}{{ define "idp_footer.html" }}footer{{ end }}`))
	tmpl = template.Must(tmpl.Parse(loadStaticTemplate(t, "idp_2fa_home.html")))
	data := twoFAHomeTemplateData()
	data["TOTPDeleteEndpoint"] = definitions.MFARoot + "/totp/de"
	data["TOTPRegisterEndpoint"] = definitions.MFARoot + "/totp/register/de"
	data["WebAuthnDevicesEndpoint"] = definitions.MFARoot + "/webauthn/devices/de"
	data["WebAuthnRegisterEndpoint"] = definitions.MFARoot + "/webauthn/register/de"
	data["RecoveryGenerateEndpoint"] = definitions.MFARoot + "/recovery/generate/de"

	var output bytes.Buffer
	assert.NoError(t, tmpl.Execute(&output, data))

	assert.Contains(t, output.String(), `hx-delete="/mfa/totp/de"`)
	assert.Contains(t, output.String(), `href="/mfa/webauthn/devices/de"`)
	assert.Contains(t, output.String(), `hx-post="/mfa/recovery/generate/de"`)
	assert.NotContains(t, output.String(), `hx-delete="/mfa/totp"`)
	assert.NotContains(t, output.String(), `href="/mfa/webauthn/devices"`)
	assert.NotContains(t, output.String(), `hx-post="/mfa/recovery/generate"`)
}

func TestWebAuthnDevicesTemplateUsesLocalizedMFASelfServiceEndpoints(t *testing.T) {
	tmpl := template.Must(template.New("idp_2fa_webauthn_devices.html").
		Parse(`{{ define "idp_header.html" }}header{{ end }}{{ define "idp_footer.html" }}footer{{ end }}`))
	tmpl = template.Must(tmpl.Parse(loadStaticTemplate(t, "idp_2fa_webauthn_devices.html")))
	data := webAuthnDevicesTemplateData()

	var output bytes.Buffer
	assert.NoError(t, tmpl.Execute(&output, data))

	assert.Contains(t, output.String(), `href="/mfa/register/home/de"`)
	assert.Contains(t, output.String(), `hx-post="/mfa/webauthn/device/Y3JlZC0x/name/de"`)
	assert.Contains(t, output.String(), `hx-delete="/mfa/webauthn/device/Y3JlZC0x/de"`)
	assert.Contains(t, output.String(), `href="/mfa/webauthn/register/de"`)
	assert.NotContains(t, output.String(), `href="/mfa/register/home"`)
	assert.NotContains(t, output.String(), `hx-post="/mfa/webauthn/device/Y3JlZC0x/name"`)
	assert.NotContains(t, output.String(), `hx-delete="/mfa/webauthn/device/Y3JlZC0x"`)
	assert.NotContains(t, output.String(), `href="/mfa/webauthn/register"`)
}

func TestMFARegistrationTemplatesUseLocalizedSelfServiceEndpoints(t *testing.T) {
	for _, tc := range mfaRegistrationTemplateEndpointTests() {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := template.Must(template.New(tc.templateName).Funcs(template.FuncMap{
				"cspNonce": func(any) string {
					return "nonce"
				},
			}).
				Parse(`{{ define "idp_header.html" }}header{{ end }}{{ define "idp_footer.html" }}footer{{ end }}`))
			tmpl = template.Must(tmpl.Parse(loadStaticTemplate(t, tc.templateName)))

			var output bytes.Buffer
			assert.NoError(t, tmpl.Execute(&output, tc.data))

			for _, want := range tc.want {
				assert.Contains(t, output.String(), want)
			}

			for _, notWant := range tc.notWant {
				assert.NotContains(t, output.String(), notWant)
			}
		})
	}
}

func TestRegisterWebAuthnPageUsesFlowAwareNextEndpoint(t *testing.T) {
	testCases := []struct {
		name         string
		languageTag  string
		requireFlow  bool
		expectedNext string
	}{
		{
			name:         "required MFA flow localized",
			languageTag:  "de",
			requireFlow:  true,
			expectedNext: definitions.MFARoot + "/register/continue/de",
		},
		{
			name:         "required MFA flow default language",
			requireFlow:  true,
			expectedNext: definitions.MFARoot + "/register/continue",
		},
		{
			name:         "self-service localized",
			languageTag:  "de",
			expectedNext: definitions.MFARoot + "/register/home/de",
		},
		{
			name:         "self-service default language",
			expectedNext: definitions.MFARoot + "/register/home",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			output := renderRegisterWebAuthnPage(t, tc.languageTag, tc.requireFlow)

			assert.Contains(t, output, `data-webauthn-next-url="`+tc.expectedNext+`"`)
		})
	}
}

// renderRegisterWebAuthnPage renders the real WebAuthn registration handler
// with a minimal authenticated session.
func renderRegisterWebAuthnPage(t *testing.T, languageTag string, requireFlow bool) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, engine := gin.CreateTestContext(recorder)
	engine.SetHTMLTemplate(loadIDPChromeTemplate(t, "idp_webauthn_register.html"))

	path := definitions.MFARoot + "/webauthn/register"
	if languageTag != "" {
		path += "/" + languageTag
		ctx.Params = gin.Params{{Key: "languageTag", Value: languageTag}}
	}

	ctx.Request = httptest.NewRequest(http.MethodGet, path, nil)
	ctx.Set(definitions.CtxLocalizedKey, i18n.NewLocalizer((&mockLangManager{}).GetBundle(), "en"))
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
		definitions.SessionKeyAccount:        frontendTestAccount,
		definitions.SessionKeyUniqueUserID:   frontendTestUniqueUserID,
		definitions.SessionKeyRequireMFAFlow: requireFlow,
	}})

	handler := &FrontendHandler{
		deps: &deps.Deps{
			Cfg:         &mockFrontendCfg{},
			Env:         config.NewTestEnvironmentConfig(),
			LangManager: &mockLangManager{},
			Logger:      slog.Default(),
		},
	}

	handler.RegisterWebAuthn(ctx)

	assert.Equal(t, http.StatusOK, recorder.Code)

	return recorder.Body.String()
}

type registrationTemplateEndpointTest struct {
	name         string
	templateName string
	data         map[string]any
	want         []string
	notWant      []string
}

// mfaRegistrationTemplateEndpointTests returns localized endpoint assertions
// for MFA registration and recovery-code templates.
func mfaRegistrationTemplateEndpointTests() []registrationTemplateEndpointTest {
	return []registrationTemplateEndpointTest{
		totpRegistrationTemplateEndpointTest(),
		webAuthnRegistrationTemplateEndpointTest(),
		recoveryRegistrationTemplateEndpointTest(),
		recoveryGeneratedModalTemplateEndpointTest(),
	}
}

// totpRegistrationTemplateEndpointTest covers localized TOTP registration URLs.
func totpRegistrationTemplateEndpointTest() registrationTemplateEndpointTest {
	return registrationTemplateEndpointTest{
		name:         "TOTP register",
		templateName: "idp_totp_register.html",
		data:         totpRegisterTemplateData(),
		want:         []string{`hx-post="/mfa/totp/register/de"`, `href="/mfa/register/cancel/de"`},
		notWant:      []string{`hx-post="/mfa/totp/register"`, `href="/mfa/register/cancel"`},
	}
}

// webAuthnRegistrationTemplateEndpointTest covers localized WebAuthn registration URLs.
func webAuthnRegistrationTemplateEndpointTest() registrationTemplateEndpointTest {
	return registrationTemplateEndpointTest{
		name:         "WebAuthn register",
		templateName: "idp_webauthn_register.html",
		data:         webAuthnRegisterTemplateData(),
		want: []string{
			`data-webauthn-begin="/mfa/webauthn/register/begin/de"`,
			`data-webauthn-finish="/mfa/webauthn/register/finish/de"`,
			`data-webauthn-next-url="/mfa/register/continue/de"`,
			`href="/mfa/register/cancel/de"`,
		},
		notWant: []string{
			`data-webauthn-begin="/mfa/webauthn/register/begin"`,
			`data-webauthn-finish="/mfa/webauthn/register/finish"`,
			`data-webauthn-next-url="/mfa/register/continue"`,
			`href="/mfa/register/cancel"`,
		},
	}
}

// recoveryRegistrationTemplateEndpointTest covers localized recovery registration URLs.
func recoveryRegistrationTemplateEndpointTest() registrationTemplateEndpointTest {
	return registrationTemplateEndpointTest{
		name:         "Recovery register",
		templateName: "idp_recovery_codes_register.html",
		data:         recoveryCodesRegisterTemplateData(),
		want: []string{
			`data-save-url="/mfa/recovery/register/save/de"`,
			`action="/mfa/recovery/register/de"`,
			`href="/mfa/register/cancel/de"`,
		},
		notWant: []string{
			`data-save-url="/mfa/recovery/register/save"`,
			`action="/mfa/recovery/register"`,
			`href="/mfa/register/cancel"`,
		},
	}
}

// recoveryGeneratedModalTemplateEndpointTest covers localized generated-code modal URLs.
func recoveryGeneratedModalTemplateEndpointTest() registrationTemplateEndpointTest {
	return registrationTemplateEndpointTest{
		name:         "Recovery generated modal",
		templateName: "idp_recovery_codes_modal.html",
		data:         recoveryCodesModalTemplateData(),
		want:         []string{`hx-get="/mfa/register/home/de"`},
		notWant:      []string{`hx-get="/mfa/register/home"`},
	}
}

func TestMFASelectTemplateUsesLocalizedChallengeEndpoints(t *testing.T) {
	output := renderMFASelectTemplate(t, map[string]any{
		"HaveRecoveryCodes":     true,
		"TOTPLoginEndpoint":     "/login/totp/de",
		"WebAuthnLoginEndpoint": "/login/webauthn/de",
		"RecoveryLoginEndpoint": "/login/recovery/de",
	})

	assert.Contains(t, output, `href="/login/totp/de"`)
	assert.Contains(t, output, `href="/login/webauthn/de"`)
	assert.Contains(t, output, `href="/login/recovery/de"`)
	assert.NotContains(t, output, `href="/login/totp"`)
	assert.NotContains(t, output, `href="/login/webauthn"`)
	assert.NotContains(t, output, `href="/login/recovery"`)
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

// twoFAHomeTemplateData returns default labels and state for the self-service
// home template tests.
func twoFAHomeTemplateData() map[string]any {
	return map[string]any{
		"HXRequest":                    true,
		"Title":                        "2FA Self-Service",
		"AuthenticatorAppTOTP":         "Authenticator App (TOTP)",
		"TOTPDescription":              "Use an app.",
		"SecurityKeyWebAuthn":          "Security Key (WebAuthn)",
		"WebAuthnDescription":          "Use a security key.",
		"RegisterTOTP":                 "Register TOTP",
		"RegisterWebAuthn":             "Register WebAuthn",
		"Deactivate":                   "Deactivate",
		"DeactivateTOTPConfirm":        "Deactivate TOTP?",
		"DeactivateWebAuthnConfirm":    "Deactivate WebAuthn?",
		"RecoveryCodes":                "Recovery Codes",
		"RecoveryCodesDescription":     "Backup codes.",
		"RecoveryCodesLeft":            "You have %d recovery codes left.",
		"GenerateNewRecoveryCodes":     "Generate new recovery codes",
		"GenerateRecoveryCodesConfirm": "Generate new recovery codes?",
		"HaveTOTP":                     true,
		"HaveRecoveryCodes":            true,
		"NumRecoveryCodes":             3,
		"HaveWebAuthn":                 true,
		"CSRFToken":                    "csrf-token",
		"TOTPDeleteEndpoint":           definitions.MFARoot + "/totp",
		"TOTPRegisterEndpoint":         definitions.MFARoot + "/totp/register",
		"WebAuthnDevicesEndpoint":      definitions.MFARoot + "/webauthn/devices",
		"WebAuthnRegisterEndpoint":     definitions.MFARoot + "/webauthn/register",
		"RecoveryGenerateEndpoint":     definitions.MFARoot + "/recovery/generate",
	}
}

// webAuthnDevicesTemplateData returns labels, endpoints, and one device row for
// the WebAuthn devices template tests.
func webAuthnDevicesTemplateData() map[string]any {
	return map[string]any{
		"Title":             "Security Keys",
		"BackTo2FA":         "Back",
		"BackTo2FAEndpoint": definitions.MFARoot + "/register/home/de",
		"RegisteredDevices": "Registered devices",
		"DeviceID":          "Device ID",
		"LastUsed":          "Last used",
		"UnnamedDevice":     "Unnamed device",
		"Save":              "Save",
		"Delete":            "Delete",
		"DeleteConfirm":     "Delete?",
		"AddDevice":         "Add",
		"AddDeviceEndpoint": definitions.MFARoot + "/webauthn/register/de",
		"CSRFToken":         "csrf-token",
		"Devices": []map[string]string{
			{
				"ID":             "Y3JlZC0x",
				"Name":           "Device",
				"LastUsed":       "Never",
				"NameEndpoint":   definitions.MFARoot + "/webauthn/device/Y3JlZC0x/name/de",
				"DeleteEndpoint": definitions.MFARoot + "/webauthn/device/Y3JlZC0x/de",
			},
		},
	}
}

// totpRegisterTemplateData returns default labels and endpoints for TOTP
// registration template tests.
func totpRegisterTemplateData() map[string]any {
	return map[string]any{
		"Title":                "Register TOTP",
		"RequireMFAFlow":       true,
		"RequireMFAMessage":    "Required",
		"TOTPMessage":          "Scan",
		"QRCode":               "otpauth://totp/test",
		"Secret":               "secret",
		"Code":                 "Code",
		"Submit":               "Submit",
		"Cancel":               "Cancel",
		"CSRFToken":            "csrf-token",
		"PostTOTPRegisterPath": definitions.MFARoot + "/totp/register/de",
		"CancelMFAEndpoint":    definitions.MFARoot + "/register/cancel/de",
	}
}

// webAuthnRegisterTemplateData returns default labels and endpoints for
// WebAuthn registration template tests.
func webAuthnRegisterTemplateData() map[string]any {
	return map[string]any{
		"Title":                    "Register WebAuthn",
		"RequireMFAFlow":           true,
		"RequireMFAMessage":        "Required",
		"WebAuthnMessage":          "Use key",
		"DeviceNameLabel":          "Device",
		"DeviceNamePlaceholder":    "Device name",
		"Submit":                   "Submit",
		"Cancel":                   "Cancel",
		"CSRFToken":                "csrf-token",
		"WebAuthnBeginEndpoint":    definitions.MFARoot + "/webauthn/register/begin/de",
		"WebAuthnFinishEndpoint":   definitions.MFARoot + "/webauthn/register/finish/de",
		"WebAuthnNextEndpoint":     definitions.MFARoot + "/register/continue/de",
		"CancelMFAEndpoint":        definitions.MFARoot + "/register/cancel/de",
		"JSInteractWithKey":        "Touch key",
		"JSCompletingRegistration": "Completing",
		"JSDeviceNameRequired":     "Required",
		"JSUnknownError":           "Unknown",
	}
}

// recoveryCodesRegisterTemplateData returns default labels and endpoints for
// recovery-code registration template tests.
func recoveryCodesRegisterTemplateData() map[string]any {
	data := recoveryCodesModalTemplateData()
	data["Title"] = "Recovery Codes"
	data["RequireMFAFlow"] = true
	data["RequireMFAMessage"] = "Required"
	data["Continue"] = "Continue"
	data["CSRFToken"] = "csrf-token"
	data["SaveRecoveryCodesEndpoint"] = definitions.MFARoot + "/recovery/register/save/de"
	data["PostRecoveryRegisterEndpoint"] = definitions.MFARoot + "/recovery/register/de"
	data["CancelMFAEndpoint"] = definitions.MFARoot + "/register/cancel/de"

	return data
}

// recoveryCodesModalTemplateData returns labels and endpoints for generated
// recovery-code modal template tests.
func recoveryCodesModalTemplateData() map[string]any {
	return map[string]any{
		"HXRequest":            true,
		"NewRecoveryCodes":     "New recovery codes",
		"BackupTheseCodes":     "Backup",
		"ShownOnlyOnce":        "Once",
		"Copy":                 "Copy",
		"Download":             "Download",
		"Downloaded":           "Downloaded",
		"CopiedToClipboard":    "Copied",
		"Close":                "Close",
		"Codes":                []string{"AAAA-BBBB", "CCCC-DDDD"},
		"RecoveryHomeEndpoint": definitions.MFARoot + "/register/home/de",
	}
}

// mfaSelectTemplateData returns the default template data shared by MFA selection tests.
func mfaSelectTemplateData() map[string]any {
	return map[string]any{
		"SelectMFA":             "Select",
		"ChooseMFADescription":  "Choose",
		"SecurityKey":           "Security Key",
		"AuthenticatorApp":      "Authenticator App",
		"RecoveryCode":          "Recovery Code",
		"Recommended":           "Recommended",
		"OtherMethods":          "Other methods",
		"Or":                    "or",
		"Back":                  "Back",
		"HaveTOTP":              true,
		"HaveWebAuthn":          true,
		"HaveRecoveryCodes":     false,
		"RecommendedMethod":     "",
		"HasOtherMethods":       false,
		"TOTPLoginEndpoint":     "/login/totp",
		"WebAuthnLoginEndpoint": "/login/webauthn",
		"RecoveryLoginEndpoint": "/login/recovery",
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

	assertMFASelfServiceStepUpRedirect(t, ctx, recorder, provider.deleteTOTPCalls, "totp_delete", definitions.MFARoot+"/register/home")
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

	assertMFASelfServiceStepUpRedirect(t, ctx, recorder, provider.deleteTOTPCalls, "totp_delete", definitions.MFARoot+"/register/home")
}

func TestMFASelfServiceTOTPDeletePermitsFreshStepUp(t *testing.T) {
	handler, provider := newMFASelfServiceTestHandler()
	ctx, _ := newMFASelfServiceContext(http.MethodDelete, "/mfa/totp", map[string]any{
		definitions.SessionKeyAccount:           "alice",
		definitions.SessionKeyUserBackend:       uint8(definitions.BackendLDAP),
		definitions.SessionKeyMFACompleted:      true,
		definitions.SessionKeyMFAMethod:         definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceAt:    time.Now().Unix(),
		definitions.SessionKeyMFAAssuranceScope: definitions.ProtoIDP,
	}, nil)

	handler.DeleteTOTP(ctx)

	assert.Equal(t, 1, provider.deleteTOTPCalls)
}

func TestMFASelfServiceTOTPDeleteRejectsFreshOIDCAssurance(t *testing.T) {
	handler, provider := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodDelete, "/mfa/totp", map[string]any{
		definitions.SessionKeyAccount:           "alice",
		definitions.SessionKeyUserBackend:       uint8(definitions.BackendLDAP),
		definitions.SessionKeyMFACompleted:      true,
		definitions.SessionKeyMFAMethod:         definitions.MFAMethodTOTP,
		definitions.SessionKeyMFAAssuranceAt:    time.Now().Unix(),
		definitions.SessionKeyMFAAssuranceScope: oidcMFAAssuranceScope("mail-client"),
	}, nil)

	handler.DeleteTOTP(ctx)

	assertMFASelfServiceStepUpRedirect(t, ctx, recorder, provider.deleteTOTPCalls, "totp_delete", definitions.MFARoot+"/register/home")
}

func TestMFASelfServiceWebAuthnDeleteRejectsMissingStepUp(t *testing.T) {
	handler, _ := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodDelete, "/mfa/webauthn", map[string]any{
		definitions.SessionKeyAccount:      "alice",
		definitions.SessionKeyUniqueUserID: "uid-123",
	}, nil)

	handler.DeleteWebAuthn(ctx)

	assertMFASelfServiceStepUpRedirect(t, ctx, recorder, 0, "webauthn_delete", definitions.MFARoot+"/register/home")
}

func TestMFASelfServiceRecoveryRegenerationRejectsMissingStepUp(t *testing.T) {
	handler, provider := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodPost, "/mfa/recovery/generate", map[string]any{
		definitions.SessionKeyAccount:     "alice",
		definitions.SessionKeyUserBackend: uint8(definitions.BackendLDAP),
	}, nil)

	handler.PostGenerateRecoveryCodes(ctx)

	assertMFASelfServiceStepUpRedirect(t, ctx, recorder, provider.generateRecoveryCalls, "recovery_generate", definitions.MFARoot+"/register/home")
}

func TestMFASelfServiceWebAuthnDeviceDeleteRejectsMissingStepUp(t *testing.T) {
	handler, _ := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodDelete, "/mfa/webauthn/device/Y3JlZC0x", map[string]any{
		definitions.SessionKeyAccount:      "alice",
		definitions.SessionKeyUniqueUserID: "uid-123",
	}, nil)
	ctx.Params = gin.Params{{Key: "id", Value: "Y3JlZC0x"}}

	handler.DeleteWebAuthnDevice(ctx)

	assertMFASelfServiceStepUpRedirect(t, ctx, recorder, 0, "webauthn_device_delete", definitions.MFARoot+"/webauthn/devices")
}

func TestMFASelfServiceStepUpIgnoresUntrustedReturnTargets(t *testing.T) {
	handler, provider := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodPost, "/mfa/recovery/generate?return=https://evil.example/", map[string]any{
		definitions.SessionKeyAccount:     "alice",
		definitions.SessionKeyUserBackend: uint8(definitions.BackendLDAP),
	}, nil)
	ctx.Request.Header.Set("Referer", "https://evil.example/mfa/register/home")

	handler.PostGenerateRecoveryCodes(ctx)

	assertMFASelfServiceStepUpRedirect(t, ctx, recorder, provider.generateRecoveryCalls, "recovery_generate", definitions.MFARoot+"/register/home")
	mgr := mfaSelfServiceTestManager(t, ctx)
	assert.NotContains(t, mgr.GetString("mfa_self_service_step_up_return", ""), "evil.example")
}

func TestMFASelfServiceStepUpUsesHXRedirectForHTMX(t *testing.T) {
	handler, provider := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodPost, "/mfa/recovery/generate", map[string]any{
		definitions.SessionKeyAccount:     "alice",
		definitions.SessionKeyUserBackend: uint8(definitions.BackendLDAP),
	}, nil)
	ctx.Request.Header.Set("HX-Request", "true")

	handler.PostGenerateRecoveryCodes(ctx)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, frontendMFASelectPath, recorder.Header().Get("HX-Redirect"))
	assert.Zero(t, provider.generateRecoveryCalls)
}

func TestMFASelfServiceLocalizedStepUpUsesLocalizedHXRedirectForHTMX(t *testing.T) {
	for _, tc := range localizedSelfServiceStepUpTests() {
		t.Run(tc.name, func(t *testing.T) {
			handler, _ := newMFASelfServiceTestHandler()
			ctx, recorder := newMFASelfServiceContext(tc.method, tc.path, map[string]any{
				definitions.SessionKeyAccount:      "alice",
				definitions.SessionKeyUserBackend:  uint8(definitions.BackendLDAP),
				definitions.SessionKeyUniqueUserID: "uid-123",
			}, nil)
			ctx.Params = tc.params
			ctx.Request.Header.Set("HX-Request", "true")

			tc.handle(handler, ctx)

			assert.Equal(t, http.StatusOK, recorder.Code)
			assert.Equal(t, frontendMFASelectPath+"/de", recorder.Header().Get("HX-Redirect"))

			mgr := mfaSelfServiceTestManager(t, ctx)
			assert.Equal(t, tc.wantAction, mgr.GetString("mfa_self_service_step_up_action", ""))
			assert.Equal(t, tc.wantReturn, mgr.GetString("mfa_self_service_step_up_return", ""))
		})
	}
}

type localizedSelfServiceStepUpTest struct {
	name       string
	method     string
	path       string
	params     gin.Params
	handle     func(*FrontendHandler, *gin.Context)
	wantAction string
	wantReturn string
}

// localizedSelfServiceStepUpTests returns sensitive localized mutations that
// must redirect HTMX callers to localized self-service MFA step-up.
func localizedSelfServiceStepUpTests() []localizedSelfServiceStepUpTest {
	return []localizedSelfServiceStepUpTest{
		localizedRecoveryGenerateStepUpTest(),
		localizedTOTPDeleteStepUpTest(),
		localizedWebAuthnDeviceDeleteStepUpTest(),
		localizedWebAuthnDeviceRenameStepUpTest(),
	}
}

// localizedRecoveryGenerateStepUpTest covers recovery-code regeneration.
func localizedRecoveryGenerateStepUpTest() localizedSelfServiceStepUpTest {
	return localizedSelfServiceStepUpTest{
		name:       "recovery generation",
		method:     http.MethodPost,
		path:       definitions.MFARoot + "/recovery/generate/de",
		params:     gin.Params{{Key: "languageTag", Value: "de"}},
		handle:     (*FrontendHandler).PostGenerateRecoveryCodes,
		wantAction: "recovery_generate",
		wantReturn: definitions.MFARoot + "/register/home/de",
	}
}

// localizedTOTPDeleteStepUpTest covers TOTP deactivation.
func localizedTOTPDeleteStepUpTest() localizedSelfServiceStepUpTest {
	return localizedSelfServiceStepUpTest{
		name:       "TOTP delete",
		method:     http.MethodDelete,
		path:       definitions.MFARoot + "/totp/de",
		params:     gin.Params{{Key: "languageTag", Value: "de"}},
		handle:     (*FrontendHandler).DeleteTOTP,
		wantAction: "totp_delete",
		wantReturn: definitions.MFARoot + "/register/home/de",
	}
}

// localizedWebAuthnDeviceDeleteStepUpTest covers WebAuthn device deletion.
func localizedWebAuthnDeviceDeleteStepUpTest() localizedSelfServiceStepUpTest {
	return localizedSelfServiceStepUpTest{
		name:   "WebAuthn device delete",
		method: http.MethodDelete,
		path:   definitions.MFARoot + "/webauthn/device/Y3JlZC0x/de",
		params: gin.Params{
			{Key: "id", Value: "Y3JlZC0x"},
			{Key: "languageTag", Value: "de"},
		},
		handle:     (*FrontendHandler).DeleteWebAuthnDevice,
		wantAction: "webauthn_device_delete",
		wantReturn: definitions.MFARoot + "/webauthn/devices/de",
	}
}

// localizedWebAuthnDeviceRenameStepUpTest covers WebAuthn device renaming.
func localizedWebAuthnDeviceRenameStepUpTest() localizedSelfServiceStepUpTest {
	return localizedSelfServiceStepUpTest{
		name:   "WebAuthn device rename",
		method: http.MethodPost,
		path:   definitions.MFARoot + "/webauthn/device/Y3JlZC0x/name/de",
		params: gin.Params{
			{Key: "id", Value: "Y3JlZC0x"},
			{Key: "languageTag", Value: "de"},
		},
		handle:     (*FrontendHandler).UpdateWebAuthnDeviceName,
		wantAction: "webauthn_device_name",
		wantReturn: definitions.MFARoot + "/webauthn/devices/de",
	}
}

func TestMFASelfServiceStepUpReturnTargetIsConsumedAfterMFA(t *testing.T) {
	handler, _ := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodPost, "/login/totp", map[string]any{
		"mfa_self_service_step_up_action": "totp_delete",
		"mfa_self_service_step_up_return": definitions.MFARoot + "/register/home",
	}, nil)

	redirected := handler.redirectPendingSelfServiceStepUp(ctx, cookie.GetManager(ctx))

	assert.True(t, redirected)
	assert.Equal(t, http.StatusFound, ctx.Writer.Status())
	assert.Equal(t, definitions.MFARoot+"/register/home", recorder.Header().Get("Location"))

	mgr := mfaSelfServiceTestManager(t, ctx)
	assert.Empty(t, mgr.GetString("mfa_self_service_step_up_action", ""))
	assert.Empty(t, mgr.GetString("mfa_self_service_step_up_return", ""))
}

func TestMFASelfServiceStepUpReturnTargetFollowsLanguageSwitch(t *testing.T) {
	handler, _ := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodPost, "/login/totp/en", map[string]any{
		"mfa_self_service_step_up_action": "totp_delete",
		"mfa_self_service_step_up_return": definitions.MFARoot + "/register/home/de",
	}, nil)
	ctx.Params = gin.Params{{Key: "languageTag", Value: "en"}}

	redirected := handler.redirectPendingSelfServiceStepUp(ctx, cookie.GetManager(ctx))

	assert.True(t, redirected)
	assert.Equal(t, http.StatusFound, ctx.Writer.Status())
	assert.Equal(t, definitions.MFARoot+"/register/home/en", recorder.Header().Get("Location"))

	mgr := mfaSelfServiceTestManager(t, ctx)
	assert.Empty(t, mgr.GetString("mfa_self_service_step_up_action", ""))
	assert.Empty(t, mgr.GetString("mfa_self_service_step_up_return", ""))
}

func TestMFASelfServiceStepUpRejectsArbitraryPendingAction(t *testing.T) {
	handler, _ := newMFASelfServiceTestHandler()
	ctx, recorder := newMFASelfServiceContext(http.MethodPost, "/login/totp", map[string]any{
		"mfa_self_service_step_up_action": "/login/webauthn",
		"mfa_self_service_step_up_return": definitions.MFARoot + "/register/home",
	}, nil)

	redirected := handler.redirectPendingSelfServiceStepUp(ctx, cookie.GetManager(ctx))

	assert.False(t, redirected)
	assert.Equal(t, http.StatusOK, recorder.Code)

	mgr := mfaSelfServiceTestManager(t, ctx)
	assert.Empty(t, mgr.GetString("mfa_self_service_step_up_action", ""))
	assert.Empty(t, mgr.GetString("mfa_self_service_step_up_return", ""))
}

func assertMFASelfServiceStepUpRedirect(
	t *testing.T,
	ctx *gin.Context,
	recorder *httptest.ResponseRecorder,
	mutationCalls int,
	action string,
	returnTarget string,
) {
	t.Helper()

	assert.Equal(t, http.StatusFound, ctx.Writer.Status())
	assert.Equal(t, frontendMFASelectPath, recorder.Header().Get("Location"))
	assert.Zero(t, mutationCalls)

	mgr := mfaSelfServiceTestManager(t, ctx)
	assert.Equal(t, action, mgr.GetString("mfa_self_service_step_up_action", ""))
	assert.Equal(t, returnTarget, mgr.GetString("mfa_self_service_step_up_return", ""))
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyUsername, ""))
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyMFAAccount, ""))
	assert.Equal(t, "alice", mgr.GetString(definitions.SessionKeyMFAFactorAccount, ""))
	assert.True(t, mgr.HasKey(definitions.SessionKeyAuthResult))
	assert.Equal(t, 1, mgr.saves)
}

func mfaSelfServiceTestManager(t *testing.T, ctx *gin.Context) *mockCookieManager {
	t.Helper()

	mgr, ok := cookie.GetManager(ctx).(*mockCookieManager)
	if !ok {
		t.Fatal("expected mock cookie manager")
	}

	return mgr
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
