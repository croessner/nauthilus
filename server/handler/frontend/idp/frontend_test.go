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
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/cookie"
	corelang "github.com/croessner/nauthilus/v3/server/core/language"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/sessionstate"
	"github.com/croessner/nauthilus/v3/server/util"
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

	r := gin.New()
	r.GET("/test", func(ctx *gin.Context) {
		lm := &mockLangManager{}
		ctx.Set(definitions.CtxLocalizedKey, i18n.NewLocalizer(lm.GetBundle(), "en"))
		data := canonicalBasePageData(
			ctx, cfg, lm, cookie.SessionIdentity{},
			stringValue(sessionData[definitions.SessionKeyIDPFlowType]),
			stringValue(sessionData[definitions.SessionKeyIDPClientID]),
			stringValue(sessionData[definitions.SessionKeyIDPSAMLEntityID]),
		)
		assert.Equal(t, expectedName, data["IDPClientName"])
		ctx.Status(http.StatusOK)
	})

	response := httptest.NewRecorder()
	r.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/test", nil))
}

func stringValue(value any) string {
	result, _ := value.(string)

	return result
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
			account := stringValue(sessionData[definitions.SessionKeyAccount])
			if account != "" {
				cookie.SetCanonicalSession(c, &cookie.CanonicalSession{
					Anchor: sessionstate.Versioned[sessionstate.SessionAnchor]{Value: sessionstate.SessionAnchor{
						Authenticated: true, IdentityReference: "identity-test",
						Identity: sessionstate.IdentitySummary{
							Account: account, Subject: "identity-test", Protocol: definitions.ProtoOIDC,
						},
					}},
				})
			}

			c.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: map[string]any{
				definitions.SessionKeyAccount: "legacy-account",
			}})
			c.Set(canonicalAuthenticatedViewContextKey, true)
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

func TestAppendQueryString(t *testing.T) {
	h := &FrontendHandler{}

	assert.Equal(t, "/path?q=v", h.appendQueryString("/path", "q=v"))
	assert.Equal(t, "/path?a=b&q=v", h.appendQueryString("/path?a=b", "q=v"))
	assert.Equal(t, "/path", h.appendQueryString("/path", ""))
}

func TestMFASelectTemplateRecommended(t *testing.T) {
	output := renderMFASelectTemplate(t, map[string]any{
		"HaveRecoveryCodes": true,
		"RecommendedMethod": "totp",
		"HasOtherMethods":   true,
		"FlowTicket":        "step-up-ticket",
		"TOTPLoginEndpoint": "/login/totp?flow=step-up-ticket",
	})

	assert.Contains(t, output, "autofocus")
	assert.Contains(t, output, "Other methods")
	assert.Contains(t, output, "/login/totp")
	assert.Contains(t, output, "/login/webauthn")
	assert.NotContains(t, output, `name="flow"`)
	assert.Equal(t, 1, strings.Count(output, "flow=step-up-ticket"))
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
	assert.Contains(t, output.String(), `action="/mfa/webauthn/device/Y3JlZC0x/name/de"`)
	assert.Contains(t, output.String(), `method="post"`)
	assert.Contains(t, output.String(), `name="csrf_token" type="hidden" value="csrf-token"`)
	assert.Contains(t, output.String(), `hx-delete="/mfa/webauthn/device/Y3JlZC0x/de"`)
	assert.Contains(t, output.String(), `href="/mfa/webauthn/register/de"`)
	assert.NotContains(t, output.String(), `href="/mfa/register/home"`)
	assert.NotContains(t, output.String(), `hx-post=`)
	assert.NotContains(t, output.String(), `action="/mfa/webauthn/device/Y3JlZC0x/name"`)
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

func TestIDPUIFollowsSafeHtmxRedirectAfterSuccessfulMutation(t *testing.T) {
	script := loadIDPUIScript(t)

	assert.Contains(t, script, "function followSafeHtmxRedirect(event)")
	assert.Contains(t, script, "xhr.getResponseHeader('HX-Redirect')")
	assert.Contains(t, script, "function isSafeHtmxRedirect(redirect)")
	assert.Contains(t, script, "new URL(redirect, window.location.href).origin === window.location.origin")
	assert.Contains(t, script, "window.location.assign(redirect)")
	assert.Contains(t, script, "followSafeHtmxRedirect(evt);")
}

func TestIDPUIWebAuthnPreservesCredentialMetadata(t *testing.T) {
	script := loadIDPUIScript(t)

	assert.Contains(t, script, "function serializePublicKeyCredential(credential)")
	assert.Contains(t, script, "typeof credential.toJSON === 'function'")
	assert.Contains(t, script, "authenticatorAttachment: credential.authenticatorAttachment")
	assert.Contains(t, script, "clientExtensionResults: credential.getClientExtensionResults()")
	assert.Contains(t, script, "response.getTransports()")
	assert.Contains(t, script, "JSON.stringify(serializePublicKeyCredential(assertion))")
	assert.Contains(t, script, "credential: serializePublicKeyCredential(credential)")
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

func TestRedirectWebAuthnDevicesUsesLocalizedBrowserNavigation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		htmx           bool
		wantStatus     int
		wantHeaderName string
	}{
		{
			name:           "native form",
			wantStatus:     http.StatusSeeOther,
			wantHeaderName: "Location",
		},
		{
			name:           "HTMX mutation",
			htmx:           true,
			wantStatus:     http.StatusOK,
			wantHeaderName: "HX-Redirect",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, recorder := newMFASelfServiceContext(http.MethodPost, "/mfa/webauthn/device/Y3JlZC0x/name/de", nil, nil)

			ctx.Params = gin.Params{{Key: "languageTag", Value: "de"}}
			if tc.htmx {
				ctx.Request.Header.Set("HX-Request", "true")
			}

			redirectWebAuthnDevices(ctx)

			assert.Equal(t, tc.wantStatus, ctx.Writer.Status())
			assert.Equal(t, definitions.MFARoot+"/webauthn/devices/de", recorder.Header().Get(tc.wantHeaderName))
		})
	}
}

type mfaSelfServiceProvider struct {
	deleteTOTPCalls       int
	generateRecoveryCalls int
	lastAccount           string
}

func (p *mfaSelfServiceProvider) deleteTOTP(_ *gin.Context, data *UserBackendData) error {
	p.deleteTOTPCalls++
	p.lastAccount = data.Username

	return nil
}

func (p *mfaSelfServiceProvider) generateRecoveryCodes(
	_ *gin.Context,
	data *UserBackendData,
) ([]string, error) {
	p.generateRecoveryCalls++
	p.lastAccount = data.Username

	return []string{"recovery-one", "recovery-two"}, nil
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
		canonicalSelfServiceTOTPDeleter:       provider.deleteTOTP,
		canonicalSelfServiceRecoveryGenerator: provider.generateRecoveryCodes,
		tracer:                                monittrace.New("test/frontend"),
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
{{ define "idp_error.html" }}{{ .ErrorTitle }}: {{ .ErrorMessage }}{{ end }}
{{ define "idp_recovery_codes_modal.html" }}{{ range .Codes }}{{ . }} {{ end }}{{ end }}
{{ define "idp_2fa_home.html" }}{{ .Username }}|{{ .DisplayName }}{{ end }}
{{ define "idp_2fa_webauthn_devices.html" }}{{ range .Devices }}{{ .Name }}{{ end }}{{ end }}
`)))

	ctx.Request = httptest.NewRequest(method, path, body)
	ctx.Set(definitions.CtxSecureDataKey, &mockCookieManager{data: sessionData})
	ctx.Set(definitions.CtxGUIDKey, "test-guid")
	ctx.Set(definitions.CtxLocalizedKey, i18n.NewLocalizer((&mockLangManager{}).GetBundle(), "en"))

	return ctx, recorder
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
