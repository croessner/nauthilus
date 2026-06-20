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

// Package devui provides devui functionality.
package devui

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v3/server/core/cookie"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/frontend"
	"github.com/croessner/nauthilus/v3/server/handler/deps"
	handleridp "github.com/croessner/nauthilus/v3/server/handler/frontend/idp"
	"github.com/croessner/nauthilus/v3/server/middleware/i18n"
	"github.com/croessner/nauthilus/v3/server/middleware/securityheaders"
	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
)

const (
	devUIDeviceCodeExample     = "ABCD-EFGH"
	devUILoggedOutPath         = "/logged_out"
	devUILogoutTaskKeyID       = "id"
	devUILogoutTaskKeyName     = "display_name"
	devUILogoutTaskKeyMethod   = "method"
	devUILogoutTaskKeyProtocol = "protocol"
	devUIMethodGet             = "GET"
	devUIMethodGetPost         = "GET/POST"
	devUIMethodPost            = "POST"
	devUIMFAMethodTOTP         = "totp"
	devUIPreviewApplication    = "Application"
	devUIPreviewBack           = "Back"
	devUIPreviewCancel         = "Cancel"
	devUIPreviewClose          = "Close"
	devUIPreviewContinue       = "Continue"
	devUIPreviewCopy           = "Copy"
	devUIPreviewDeactivate     = "Deactivate"
	devUIPreviewDeny           = "Deny"
	devUIPreviewDownload       = "Download"
	devUIPreviewNever          = "Never"
	devUIPreviewRecoverCode    = "Recovery Code"
	devUIPreviewRecommended    = "Recommended"
	devUIPreviewSubmit         = "Submit"
	devUIPreviewKeyChecked     = "Checked"
	devUIPreviewKeyCreatedAt   = "CreatedAt"
	devUIPreviewKeyDescription = "Description"
	devUIPreviewKeyID          = "ID"
	devUIPreviewKeyLastUsed    = "LastUsed"
	devUIPreviewKeyName        = "Name"
	devUIPreviewAllow          = "Allow"
	devUIProtocolOIDC          = "oidc"
	devUIRecoveryCodeFirst     = "ABCD-1234"
	devUIRecoveryCodeFourth    = "MNOP-3456"
	devUIRecoveryCodeFifth     = "QRST-7890"
	devUIRecoveryCodeSecond    = "EFGH-5678"
	devUIRecoveryCodeThird     = "IJKL-9012"
	devUISampleErrorMessage    = "This is a sample error message for dev preview."
)

const devUIIndexHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Nauthilus Dev UI</title>
    <style>
        body { font-family: sans-serif; margin: 0; display: flex; height: 100vh; background: #0f172a; color: #e2e8f0; }
        #sidebar { width: 320px; border-right: 1px solid #1f2937; overflow-y: auto; background: #111827; }
        #content { flex-grow: 1; display: flex; flex-direction: column; }
        #toolbar { padding: 10px; background: #1e293b; border-bottom: 1px solid #334155; display: flex; align-items: center; gap: 10px; color: #e2e8f0; }
        iframe { border: none; flex-grow: 1; width: 100%; height: 100%; }
        .endpoint { padding: 10px; border-bottom: 1px solid #1f2937; cursor: pointer; transition: background-color 120ms ease, border-left-color 120ms ease; border-left: 3px solid transparent; }
        .endpoint:hover { background: #1f2937; }
        .endpoint.active { background: #243447; border-left-color: #38bdf8; }
        .method { font-weight: bold; margin-right: 5px; min-width: 50px; display: inline-block; color: #93c5fd; }
        .path { color: #e5e7eb; }
        .template { font-size: 0.8em; color: #94a3b8; display: block; }
        h2 { padding: 10px; margin: 0; background: #0b1220; color: #f8fafc; font-size: 1.2em; border-bottom: 1px solid #1f2937; }
        select { padding: 5px; background: #0f172a; color: #e2e8f0; border: 1px solid #334155; border-radius: 4px; }
    </style>
</head>
<body>
    <div id="sidebar">
        <h2>IDP Endpoints</h2>
        {{range .Endpoints}}
        <div class="endpoint" onclick="loadTemplate('{{.Template}}', this)">
            <span class="method">{{.Method}}</span>
            <span class="path">{{.Path}}</span>
            <span class="template">{{.Template}}</span>
        </div>
        {{end}}
    </div>
    <div id="content">
        <div id="toolbar">
            <label for="lang-select">Language:</label>
            <select id="lang-select" onchange="reloadTemplate()">
                {{range .Languages}}
                <option value="{{.Tag}}">{{.Name}}</option>
                {{end}}
            </select>
            <span id="current-template" style="font-weight: bold; margin-left: 20px; color: #7dd3fc;"></span>
        </div>
        <iframe id="preview"></iframe>
    </div>
    <script>
        let currentVersion = {{.Version}};
        let currentTemplate = '';

        function setActiveEndpoint(el) {
            document.querySelectorAll('.endpoint').forEach(function (item) {
                item.classList.remove('active');
            });

            if (el) {
                el.classList.add('active');
            }
        }

        function loadTemplate(name, el) {
            currentTemplate = name;
            document.getElementById('current-template').innerText = name;
            setActiveEndpoint(el);
            reloadTemplate();
        }

        function reloadTemplate() {
            if (!currentTemplate) return;
            const lang = document.getElementById('lang-select').value;
            document.getElementById('preview').src = '/api/v1/dev/ui/render/' + currentTemplate + '/' + lang;
        }

        function checkVersion() {
            fetch('/api/v1/dev/ui/version')
                .then(response => response.json())
                .then(data => {
                    if (data.version !== currentVersion) {
                        currentVersion = data.version;
                        const iframe = document.getElementById('preview');
                        if (iframe.src) {
                            iframe.contentWindow.location.reload();
                        }
                    }
                })
                .catch(err => console.error('Error checking version:', err));
        }
        setInterval(checkVersion, 1000);
    </script>
</body>
</html>
`

// Handler handles the development UI for previewing templates.
type Handler struct {
	deps    *deps.Deps
	version int64
	mu      sync.RWMutex
}

// New returns a new Handler.
func New(deps *deps.Deps) *Handler {
	h := &Handler{
		deps:    deps,
		version: time.Now().UnixNano(),
	}

	h.startWatcher()

	return h
}

func (h *Handler) startWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("DevUI: failed to create watcher: %v", err)

		return
	}

	go func() {
		defer func() { _ = watcher.Close() }()

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
					h.mu.Lock()
					h.version = time.Now().UnixNano()
					h.mu.Unlock()
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}

				log.Printf("DevUI: watcher error: %v", err)
			}
		}
	}()

	path := h.deps.Cfg.GetServer().Frontend.GetHTMLStaticContentPath()

	err = watcher.Add(path)
	if err != nil {
		log.Printf("DevUI: failed to add path to watcher: %v", err)
	}
}

// Endpoint represents an IDP endpoint for the dev UI list.
type Endpoint struct {
	Method   string
	Path     string
	Template string
}

// Register adds the dev UI routes to the router.
func (h *Handler) Register(router gin.IRouter) {
	// DevUI uses its own cookie (nauthilus_dev) for development purposes
	devCookieMW := func(ctx *gin.Context) {
		mgr := cookie.NewSecureManager([]byte(definitions.DevCookieSecret), definitions.DevCookieName, h.deps.Cfg, h.deps.Env)
		_ = mgr.Load(ctx)
		ctx.Set(definitions.CtxSecureDataKey, mgr)
		ctx.Next()
		_ = mgr.Save(ctx)
	}

	group := router.Group("/dev/ui", devCookieMW)

	i18nMW := i18n.WithLanguage(h.deps.Cfg, h.deps.Logger, h.deps.LangManager)

	group.GET("", h.Index)
	group.GET("/render/:template", i18nMW, h.RenderTemplate)
	group.GET("/render/:template/:languageTag", i18nMW, h.RenderTemplate)
	group.GET("/version", h.GetVersion)
}

// GetVersion returns the current template version.
func (h *Handler) GetVersion(ctx *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	ctx.JSON(http.StatusOK, gin.H{"version": h.version})
}

// Index renders the main dev UI page.
func (h *Handler) Index(ctx *gin.Context) {
	tmpl, err := template.New("index").Parse(devUIIndexHTML)
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())

		return
	}

	h.mu.RLock()
	version := h.version
	h.mu.RUnlock()

	ctx.Status(http.StatusOK)

	err = tmpl.Execute(ctx.Writer, gin.H{
		"Endpoints": devUIEndpoints(),
		"Version":   version,
		"Languages": h.devUILanguages(),
	})
	if err != nil {
		_ = ctx.Error(err)
	}
}

// devUIEndpoints returns the sorted preview endpoint list.
func devUIEndpoints() []Endpoint {
	endpoints := []Endpoint{
		{Method: devUIMethodGetPost, Path: "/login", Template: "idp_login.html"},
		{Method: devUIMethodGet, Path: "/login/mfa", Template: "idp_mfa_select.html"},
		{Method: devUIMethodGetPost, Path: "/login/totp", Template: "idp_totp_verify.html"},
		{Method: devUIMethodGet, Path: "/login/webauthn", Template: "idp_webauthn_verify.html"},
		{Method: devUIMethodGetPost, Path: "/login/recovery", Template: "idp_recovery_login.html"},
		{Method: devUIMethodGet, Path: "/mfa/register/home", Template: "idp_2fa_home.html"},
		{Method: devUIMethodGetPost, Path: "/mfa/totp/register", Template: "idp_totp_register.html"},
		{Method: devUIMethodGet, Path: "/mfa/webauthn/register", Template: "idp_webauthn_register.html"},
		{Method: devUIMethodGet, Path: "/mfa/webauthn/devices", Template: "idp_2fa_webauthn_devices.html"},
		{Method: devUIMethodGetPost, Path: "/mfa/recovery/register", Template: "idp_recovery_codes_register.html"},
		{Method: devUIMethodPost, Path: "/mfa/recovery/generate", Template: "idp_recovery_codes_modal.html"},
		{Method: devUIMethodGet, Path: devUILoggedOutPath, Template: "idp_logged_out.html"},
		{Method: devUIMethodGet, Path: "/oidc/consent", Template: "idp_consent.html"},
		{Method: devUIMethodGet, Path: "/oidc/logout", Template: "idp_logout_frames.html"},
		{Method: devUIMethodGet, Path: "/saml/sso", Template: "idp_saml_post.html"},
		{Method: devUIMethodGet, Path: "/error", Template: "idp_error_modal.html"},
		{Method: devUIMethodGetPost, Path: "/oidc/device/verify", Template: "idp_device_verify.html"},
		{Method: devUIMethodGet, Path: "/oidc/device/verify/success", Template: "idp_device_verify_success.html"},
		{Method: devUIMethodGet, Path: "/oidc/device/verify/failed", Template: "idp_device_verify_failed.html"},
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Path == endpoints[j].Path {
			return endpoints[i].Method < endpoints[j].Method
		}

		return endpoints[i].Path < endpoints[j].Path
	})

	return endpoints
}

// devUILanguages returns language selector data for the preview UI.
func (h *Handler) devUILanguages() []map[string]string {
	languages := make([]map[string]string, 0, len(h.deps.LangManager.GetTags()))

	for _, tag := range h.deps.LangManager.GetTags() {
		languages = append(languages, map[string]string{
			"Tag":               tag.String(),
			devUIPreviewKeyName: tag.String(), // Could be improved with display name
		})
	}

	return languages
}

// RenderTemplate renders a specific template with dummy data.
func (h *Handler) RenderTemplate(ctx *gin.Context) {
	templateName := ctx.Param("template")
	templatePath := filepath.Join(h.deps.Cfg.GetServer().Frontend.GetHTMLStaticContentPath(), templateName)

	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		ctx.String(http.StatusNotFound, "Template not found: %s", templateName)

		return
	}

	data := h.devTemplateData(ctx, templateName)

	// Functions used in templates
	funcMap := template.FuncMap{
		"int": func(v any) int {
			switch x := v.(type) {
			case int:
				return x
			case int32:
				return int(x)
			case int64:
				return int(x)
			case float32:
				return int(x)
			case float64:
				return int(x)
			default:
				return 0
			}
		},
		"upper": func(s string) string {
			return strings.ToUpper(s)
		},
		"cspNonce": func(data any) string {
			return securityheaders.NonceFromTemplateData(data)
		},
	}

	// Load all templates in the directory to support nesting (header/footer)
	tmpl := template.New(templateName).Funcs(funcMap)
	pattern := filepath.Join(h.deps.Cfg.GetServer().Frontend.GetHTMLStaticContentPath(), "*.html")

	tmpl, err := tmpl.ParseGlob(pattern)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Template parse error: %v", err)

		return
	}

	ctx.Header("Content-Type", "text/html; charset=utf-8")

	err = tmpl.ExecuteTemplate(ctx.Writer, templateName, data)
	if err != nil {
		_ = ctx.Error(err)
	}
}

// devTemplateData builds the dummy data map used by the template preview renderer.
func (h *Handler) devTemplateData(ctx *gin.Context, templateName string) gin.H {
	data := handleridp.BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)
	data["DevMode"] = true
	data["HXRequest"] = false
	data["Title"] = "Dev Preview: " + templateName
	data["Username"] = "dev-user@example.com"

	h.addLoginPreviewData(ctx, data)
	h.addMFAPreviewData(ctx, data)
	h.addLogoutAndSAMLPreviewData(ctx, data)
	h.addRecoveryAndWebAuthnPreviewData(ctx, data)
	h.addDeviceAndConsentPreviewData(ctx, data)
	h.addSampleStatePreviewData(ctx, data)

	return data
}

// addLoginPreviewData adds localized login labels to preview data.
func (h *Handler) addLoginPreviewData(ctx *gin.Context, data gin.H) {
	h.addLocalizedFields(ctx, data, map[string]string{
		"UsernameLabel":       "Username",
		"UsernamePlaceholder": "Please enter your username or email address",
		"PasswordLabel":       "Password",
		"PasswordPlaceholder": "Please enter your password",
		"Submit":              devUIPreviewSubmit,
		"LoginWithWebAuthn":   "Login with WebAuthn",
		"Or":                  "or",
		"RememberMeLabel":     "Remember me",
		"LegalNoticeLabel":    "Legal notice",
		"PrivacyPolicyLabel":  "Privacy policy",
	})
}

// addMFAPreviewData adds localized MFA labels to preview data.
func (h *Handler) addMFAPreviewData(ctx *gin.Context, data gin.H) {
	h.addLocalizedFields(ctx, data, map[string]string{
		"AuthenticatorAppTOTP":      "Authenticator App (TOTP)",
		"TOTPDescription":           "Use an app like Google Authenticator or Authy.",
		"Deactivate":                devUIPreviewDeactivate,
		"DeactivateTOTPConfirm":     "Are you sure you want to deactivate TOTP?",
		"RegisterTOTP":              "Register TOTP",
		"SecurityKeyWebAuthn":       "Security Key (WebAuthn)",
		"SecurityKeysWebAuthn":      "Security Keys (WebAuthn)",
		"RegisteredDevices":         "Registered Devices",
		"NoDevicesFound":            "No registered security keys found.",
		"LastUsed":                  "Last used",
		"Never":                     devUIPreviewNever,
		"DeleteConfirm":             "Are you sure you want to delete this security key?",
		"AddDevice":                 "Add new security key",
		"BackTo2FA":                 "Back to 2FA Overview",
		"WebAuthnDescription":       "Use a physical key like Yubikey.",
		"DeactivateWebAuthnConfirm": "Are you sure you want to deactivate WebAuthn?",
		"RegisterWebAuthn":          "Register WebAuthn",
		"TOTPVerifyMessage":         "Please enter your 2FA code",
		"RecoveryVerifyMessage":     "Please enter one of your recovery codes",
		"Code":                      devUIPreviewRecoverCode,
		"Back":                      devUIPreviewBack,
		"SelectMFA":                 "Select Multi-Factor Authentication",
		"ChooseMFADescription":      "Choose your preferred second factor",
		"AuthenticatorApp":          "Authenticator App",
		"SecurityKey":               "Security Key",
		"RecoveryCode":              devUIPreviewRecoverCode,
		"Recommended":               devUIPreviewRecommended,
		"OtherMethods":              "Other methods",
	})
}

// addLogoutAndSAMLPreviewData adds logout orchestration and SAML preview data.
func (h *Handler) addLogoutAndSAMLPreviewData(ctx *gin.Context, data gin.H) {
	h.addLocalizedFields(ctx, data, map[string]string{
		"LoggedOutTitle":                          "Successfully Logged Out",
		"LoggedOutMessage":                        "You have been successfully logged out of your session.",
		"BackToLogin":                             "Back to Login",
		"LoggingOutFromAllApplications":           "Logging out from all applications...",
		"PleaseWaitWhileLogoutProcessIsCompleted": "Please wait while the logout process is completed.",
		"LogoutProgress":                          "Logout progress",
		"LogoutStatusPerApplication":              "Logout status per application",
		"LogoutSummaryPending":                    "Logout is in progress.",
		"LogoutSummaryDone":                       "Logout completed successfully.",
		"LogoutSummaryPartial":                    "Logout completed with partial failures.",
		"LogoutStatusPending":                     "Pending",
		"LogoutStatusRunning":                     "Running",
		"LogoutStatusSuccess":                     "Success",
		"LogoutStatusTimeout":                     "Timeout",
		"LogoutStatusError":                       "Error",
		"LogoutStatusSkipped":                     "Skipped",
		"LogoutRetrying":                          "Retrying",
		"LogoutAttempt":                           "Attempt",
		"SAMLPostTitle":                           "Signing you in",
		"SAMLPostMessage":                         "You are being redirected to the application.",
		"SAMLPostHint":                            "If this does not happen automatically, click Continue.",
	})

	data["FrontChannelLogoutTasks"] = devUIFrontChannelLogoutTasks()
	data["FrontChannelLogoutTaskConfig"] = `[{"id":"oidc-1","display_name":"OIDC app 1","protocol":"oidc","method":"GET","url":"https://app1.example.com/logout"},{"id":"saml-1","display_name":"SAML SP 1","protocol":"saml","method":"POST","payload_base64":"PGh0bWw+PGJvZHk+U0FNTCBQT1NUIHBheWxvYWQ8L2JvZHk+PC9odG1sPg=="}]`
	data["FrontChannelLogoutTimeoutMS"] = 4000
	data["FrontChannelLogoutMaxRetries"] = 1
	data["FrontChannelLogoutRedirectDelayMS"] = 1500
	data["LogoutTarget"] = devUILoggedOutPath
	data["SAMLPostURL"] = "https://sp.example.com/saml/acs"
	data["SAMLResponse"] = "PHNhbWxwOlJlc3BvbnNlPkRldiBwcmV2aWV3PC9zYW1scDpSZXNwb25zZT4="
	data["RelayState"] = "dev-relay-state"
	data["AutoSubmitSAMLForm"] = false
}

// addRecoveryAndWebAuthnPreviewData adds recovery-code, TOTP, and WebAuthn preview data.
func (h *Handler) addRecoveryAndWebAuthnPreviewData(ctx *gin.Context, data gin.H) {
	h.addLocalizedFields(ctx, data, map[string]string{
		"RecoveryCodes":                "Recovery Codes",
		"RecoveryCodesDescription":     "Backup codes can be used to log in if you lose access to your 2FA device.",
		"RecoveryCodesLeft":            "You have %d recovery codes left.",
		"GenerateNewRecoveryCodes":     "Generate new recovery codes",
		"GenerateRecoveryCodesConfirm": "Are you sure you want to generate new recovery codes? Any existing codes will be permanently replaced.",
		"NewRecoveryCodes":             "New recovery codes",
		"BackupTheseCodes":             "Backup these codes!",
		"ShownOnlyOnce":                "They will be shown only once.",
		"Copy":                         devUIPreviewCopy,
		"Download":                     devUIPreviewDownload,
		"Continue":                     devUIPreviewContinue,
		"CopiedToClipboard":            "Copied to clipboard",
		"Cancel":                       devUIPreviewCancel,
		"RequireMFAMessage":            "Your application requires this authentication method to be set up before you can continue",
		"Close":                        devUIPreviewClose,
		"WebAuthnVerifyMessage":        "Please use your security key to login",
		"JSInteractWithKey":            "Please interact with your security key...",
		"JSCompletingLogin":            "Completing login...",
		"JSUnknownError":               "An unknown error occurred",
		"TOTPMessage":                  "Please scan and verify the following QR code",
		"WebAuthnMessage":              "Please connect your security key and follow the instructions",
		"JSCompletingRegistration":     "Completing registration...",
	})

	data["RequireMFAFlow"] = true
	data["Codes"] = []string{devUIRecoveryCodeFirst, devUIRecoveryCodeSecond, devUIRecoveryCodeThird, devUIRecoveryCodeFourth}
	data["QRCode"] = "otpauth://totp/Nauthilus:dev-user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Nauthilus"
	data["Secret"] = "JBSWY3DPEHPK3PXP"
}

// addDeviceAndConsentPreviewData adds device-code and consent preview data.
func (h *Handler) addDeviceAndConsentPreviewData(ctx *gin.Context, data gin.H) {
	h.addLocalizedFields(ctx, data, map[string]string{
		"DeviceVerifyDescription":    "Enter the code displayed on your device and sign in to authorize it.",
		"UserCodeLabel":              "Device Code",
		"DeviceVerifySuccessMessage": "Your device has been successfully authorized.",
		"DeviceVerifySuccessHint":    "You can close this window and return to your device.",
		"DeviceVerifyFailedMessage":  "Authorization denied",
		"DeviceVerifyFailedHint":     "This code can no longer be used. Please start again on your device.",
		"Application":                devUIPreviewApplication,
		"WantsToAccessYourAccount":   "wants to access your account",
		"RequestedPermissions":       "Requested permissions",
		"Allow":                      devUIPreviewAllow,
		"Deny":                       devUIPreviewDeny,
		"NoAdditionalPermissions":    "No additional permissions requested.",
	})

	data["UserCodePlaceholder"] = devUIDeviceCodeExample
	data["PostDeviceVerifyEndpoint"] = "#"
	data["UserCode"] = devUIDeviceCodeExample
	data["ConsentModeGranularOptional"] = true
	data["ClientID"] = "test-client"
	data["ConsentChallenge"] = "test-challenge"
	data["State"] = "test-state"
	data["Scopes"] = []string{h.localized(ctx, "Access your basic profile information")}
	data["OptionalScopeChoices"] = h.devUIOptionalScopeChoices(ctx)
}

// addSampleStatePreviewData adds static endpoint URLs and sample entity state.
func (h *Handler) addSampleStatePreviewData(_ *gin.Context, data gin.H) {
	addSampleEndpointURLs(data)
	addSampleStateFlags(data)
	addSampleProfileData(data)
}

// addSampleStateFlags adds boolean preview state flags.
func addSampleStateFlags(data gin.H) {
	data["HaveError"] = true
	data["IsTOTP"] = true
	data["IsWebAuthn"] = true
	data["TOTPEnabled"] = true
	data["WebAuthnEnabled"] = true
	data["ShowRecoveryCodes"] = true
	data["RecoveryCodesList"] = []string{
		devUIRecoveryCodeFirst,
		devUIRecoveryCodeSecond,
		devUIRecoveryCodeThird,
		devUIRecoveryCodeFourth,
		devUIRecoveryCodeFifth,
	}
	data["NumRecoveryCodes"] = 5
	data["HaveTOTP"] = true
	data["HaveWebAuthn"] = true
	data["HaveRecoveryCodes"] = true
	data["BackendError"] = false
	data["ShowRememberMe"] = true
	data["HasOtherMethods"] = true
}

// addSampleProfileData adds sample profile, device, and feedback data.
func addSampleProfileData(data gin.H) {
	data["Protocol"] = devUIProtocolOIDC
	data["LastMFAMethod"] = devUIMFAMethodTOTP
	data["RecommendedMethod"] = devUIMFAMethodTOTP
	data["Message"] = devUISampleErrorMessage
	data["ErrorMessage"] = devUISampleErrorMessage
	data["BackendErrorMessage"] = "This is a sample backend error message for dev preview."
	data["Success"] = "This is a sample success message for dev preview."
	data["RecoveryCodesList"] = []string{
		devUIRecoveryCodeFirst,
		devUIRecoveryCodeSecond,
		devUIRecoveryCodeThird,
		devUIRecoveryCodeFourth,
		devUIRecoveryCodeFifth,
	}
	data["NumRecoveryCodes"] = 5
	data["TermsOfServiceURL"] = "https://example.com/tos"
	data["PrivacyPolicyURL"] = "https://example.com/privacy"
	data["PasswordForgottenURL"] = "https://example.com/forgot-password"
	data["PasswordForgottenLabel"] = "Forgot password?"
	data["WebAuthnAuthenticators"] = devUIWebAuthnAuthenticators()
	data["Devices"] = devUIDevices()
	data["Step"] = 1
}

// addSampleEndpointURLs adds static endpoint URLs used by preview templates.
func addSampleEndpointURLs(data gin.H) {
	data["WebAuthnLoginURL"] = "#"
	data["CSRFToken"] = "dev-csrf-token"
	data["PostLoginEndpoint"] = "#"
	data["PostTOTPVerifyEndpoint"] = "#"
	data["PostConsentEndpoint"] = "#"
	data["PostRecoveryVerifyEndpoint"] = "#"
	data["ReturnTo"] = ""
	data["QueryString"] = ""
	data["MFAURL"] = "#"
	data["ReturnToURL"] = "#"
	data["BackURL"] = "#"
	data["LoginWebAuthnBeginURL"] = "#"
	data["LoginWebAuthnFinishURL"] = "#"
	data["WebAuthnBeginEndpoint"] = "#"
	data["WebAuthnFinishEndpoint"] = "#"
	data["TOTPRegisterURL"] = "#"
	data["WebAuthnRegisterURL"] = "#"
	data["WebAuthnRegisterBeginURL"] = "#"
	data["WebAuthnRegisterFinishURL"] = "#"
	data["RecoveryGenerateURL"] = "#"
	data["TOTPDeleteURL"] = "#"
	data["WebAuthnDeleteURL"] = "#"
}

// addLocalizedFields fills preview fields from localization message IDs.
func (h *Handler) addLocalizedFields(ctx *gin.Context, data gin.H, fields map[string]string) {
	for key, messageID := range fields {
		data[key] = h.localized(ctx, messageID)
	}
}

// localized resolves a frontend message for the dev preview context.
func (h *Handler) localized(ctx *gin.Context, messageID string) string {
	return frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, messageID)
}

// devUIFrontChannelLogoutTasks returns sample front-channel logout tasks.
func devUIFrontChannelLogoutTasks() []map[string]string {
	return []map[string]string{
		{
			devUILogoutTaskKeyID:       "oidc-1",
			devUILogoutTaskKeyName:     "OIDC app 1",
			devUILogoutTaskKeyProtocol: devUIProtocolOIDC,
			devUILogoutTaskKeyMethod:   devUIMethodGet,
			"url":                      "https://app1.example.com/logout",
		},
		{
			devUILogoutTaskKeyID:       "saml-1",
			devUILogoutTaskKeyName:     "SAML SP 1",
			devUILogoutTaskKeyProtocol: "saml",
			devUILogoutTaskKeyMethod:   devUIMethodPost,
			"payload_base64":           "PGh0bWw+PGJvZHk+U0FNTCBQT1NUIHBheWxvYWQ8L2JvZHk+PC9odG1sPg==",
		},
	}
}

// devUIWebAuthnAuthenticators returns sample WebAuthn authenticator rows.
func devUIWebAuthnAuthenticators() []gin.H {
	return []gin.H{
		{devUIPreviewKeyID: "1", devUIPreviewKeyName: "YubiKey 5C", devUIPreviewKeyCreatedAt: time.Now().Add(-24 * time.Hour).Format(time.RFC822)},
		{devUIPreviewKeyID: "2", devUIPreviewKeyName: "Android Phone", devUIPreviewKeyCreatedAt: time.Now().Add(-48 * time.Hour).Format(time.RFC822)},
	}
}

// devUIDevices returns sample registered-device rows.
func devUIDevices() []gin.H {
	return []gin.H{
		{devUIPreviewKeyID: "MTIzNDU2Nzg5MA", devUIPreviewKeyLastUsed: time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04:05")},
		{devUIPreviewKeyID: "YWJjZGVmZ2hpams", devUIPreviewKeyLastUsed: devUIPreviewNever},
	}
}

// devUIOptionalScopeChoices returns sample optional OIDC consent choices.
func (h *Handler) devUIOptionalScopeChoices(ctx *gin.Context) []gin.H {
	return []gin.H{
		{
			devUIPreviewKeyName:        "email",
			devUIPreviewKeyDescription: h.localized(ctx, "Access your email address"),
			devUIPreviewKeyChecked:     true,
		},
		{
			devUIPreviewKeyName:        "groups",
			devUIPreviewKeyDescription: h.localized(ctx, "Access your group memberships"),
			devUIPreviewKeyChecked:     true,
		},
		{
			devUIPreviewKeyName:        "offline_access",
			devUIPreviewKeyDescription: h.localized(ctx, "Maintain access when you are offline"),
			devUIPreviewKeyChecked:     false,
		},
	}
}
