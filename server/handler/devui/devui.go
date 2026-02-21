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

	"github.com/croessner/nauthilus/server/core/cookie"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/handler/deps"
	handleridp "github.com/croessner/nauthilus/server/handler/frontend/idp"
	"github.com/croessner/nauthilus/server/middleware/i18n"
	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
)

// DevUIHandler handles the development UI for previewing templates.
type DevUIHandler struct {
	deps    *deps.Deps
	version int64
	mu      sync.RWMutex
}

// New returns a new DevUIHandler.
func New(deps *deps.Deps) *DevUIHandler {
	h := &DevUIHandler{
		deps:    deps,
		version: time.Now().UnixNano(),
	}

	h.startWatcher()

	return h
}

func (h *DevUIHandler) startWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("DevUI: failed to create watcher: %v", err)

		return
	}

	go func() {
		defer watcher.Close()

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

// Endpoint represents an IdP endpoint for the dev UI list.
type Endpoint struct {
	Method   string
	Path     string
	Template string
}

// Register adds the dev UI routes to the router.
func (h *DevUIHandler) Register(router gin.IRouter) {
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
func (h *DevUIHandler) GetVersion(ctx *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	ctx.JSON(http.StatusOK, gin.H{"version": h.version})
}

// Index renders the main dev UI page.
func (h *DevUIHandler) Index(ctx *gin.Context) {
	endpoints := []Endpoint{
		{Method: "GET", Path: "/login", Template: "idp_login.html"},
		{Method: "POST", Path: "/login", Template: "idp_login.html"},
		{Method: "GET", Path: "/login/mfa", Template: "idp_mfa_select.html"},
		{Method: "GET", Path: "/login/totp", Template: "idp_totp_verify.html"},
		{Method: "POST", Path: "/login/totp", Template: "idp_totp_verify.html"},
		{Method: "GET", Path: "/login/webauthn", Template: "idp_webauthn_verify.html"},
		{Method: "GET", Path: "/login/recovery", Template: "idp_recovery_login.html"},
		{Method: "POST", Path: "/login/recovery", Template: "idp_recovery_login.html"},
		{Method: "GET", Path: "/mfa/register/home", Template: "idp_2fa_home.html"},
		{Method: "GET", Path: "/mfa/totp/register", Template: "idp_totp_register.html"},
		{Method: "POST", Path: "/mfa/totp/register", Template: "idp_totp_register.html"},
		{Method: "GET", Path: "/mfa/webauthn/register", Template: "idp_webauthn_register.html"},
		{Method: "GET", Path: "/mfa/webauthn/devices", Template: "idp_2fa_webauthn_devices.html"},
		{Method: "GET", Path: "/mfa/recovery/codes", Template: "idp_recovery_codes_modal.html"},
		{Method: "GET", Path: "/logged_out", Template: "idp_logged_out.html"},
		{Method: "GET", Path: "/oidc/consent", Template: "idp_consent.html"},
		{Method: "GET", Path: "/oidc/logout", Template: "idp_logout_frames.html"},
		{Method: "GET", Path: "/error", Template: "idp_error_modal.html"},
		{Method: "GET", Path: "/oidc/device/verify", Template: "idp_device_verify.html"},
		{Method: "POST", Path: "/oidc/device/verify", Template: "idp_device_verify.html"},
		{Method: "GET", Path: "/oidc/device/verify/success", Template: "idp_device_verify_success.html"},
	}

	// Sort by path, then method
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Path == endpoints[j].Path {
			return endpoints[i].Method < endpoints[j].Method
		}

		return endpoints[i].Path < endpoints[j].Path
	})

	languages := make([]map[string]string, 0, len(h.deps.LangManager.GetTags()))

	for _, tag := range h.deps.LangManager.GetTags() {
		languages = append(languages, map[string]string{
			"Tag":  tag.String(),
			"Name": tag.String(), // Could be improved with display name
		})
	}

	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Nauthilus Dev UI</title>
    <style>
        body { font-family: sans-serif; margin: 0; display: flex; height: 100vh; }
        #sidebar { width: 300px; border-right: 1px solid #ccc; overflow-y: auto; background: #f4f4f4; }
        #content { flex-grow: 1; display: flex; flex-direction: column; }
        #toolbar { padding: 10px; background: #eee; border-bottom: 1px solid #ccc; display: flex; align-items: center; gap: 10px; }
        iframe { border: none; flex-grow: 1; width: 100%; height: 100%; }
        .endpoint { padding: 10px; border-bottom: 1px solid #eee; cursor: pointer; }
        .endpoint:hover { background: #e0e0e0; }
        .method { font-weight: bold; margin-right: 5px; min-width: 50px; display: inline-block; }
        .path { color: #333; }
        .template { font-size: 0.8em; color: #666; display: block; }
        h2 { padding: 10px; margin: 0; background: #333; color: white; font-size: 1.2em; }
        select { padding: 5px; }
    </style>
</head>
<body>
    <div id="sidebar">
        <h2>IdP Endpoints</h2>
        {{range .Endpoints}}
        <div class="endpoint" onclick="loadTemplate('{{.Template}}')">
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
            <span id="current-template" style="font-weight: bold; margin-left: 20px;"></span>
        </div>
        <iframe id="preview"></iframe>
    </div>
    <script>
        let currentVersion = {{.Version}};
        let currentTemplate = '';

        function loadTemplate(name) {
            currentTemplate = name;
            document.getElementById('current-template').innerText = name;
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
	tmpl, err := template.New("index").Parse(html)
	if err != nil {
		ctx.String(http.StatusInternalServerError, err.Error())

		return
	}

	h.mu.RLock()
	version := h.version
	h.mu.RUnlock()

	ctx.Status(http.StatusOK)
	err = tmpl.Execute(ctx.Writer, gin.H{
		"Endpoints": endpoints,
		"Version":   version,
		"Languages": languages,
	})
	if err != nil {
		_ = ctx.Error(err)
	}
}

// RenderTemplate renders a specific template with dummy data.
func (h *DevUIHandler) RenderTemplate(ctx *gin.Context) {
	templateName := ctx.Param("template")
	templatePath := filepath.Join(h.deps.Cfg.GetServer().Frontend.GetHTMLStaticContentPath(), templateName)

	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		ctx.String(http.StatusNotFound, "Template not found: %s", templateName)

		return
	}

	// Dummy data
	data := handleridp.BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)
	data["DevMode"] = true
	data["HXRequest"] = false
	data["Title"] = "Dev Preview: " + templateName
	data["Username"] = "dev-user@example.com"

	// Localized labels
	data["UsernameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Username")
	data["UsernamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your username or email address")
	data["PasswordLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
	data["PasswordPlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your password")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["LoginWithWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login with WebAuthn")
	data["Or"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or")
	data["RememberMeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Remember me")
	data["LegalNoticeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Legal notice")
	data["PrivacyPolicyLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Privacy policy")

	data["AuthenticatorAppTOTP"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Authenticator App (TOTP)")
	data["TOTPDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Use an app like Google Authenticator or Authy.")
	data["Deactivate"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Deactivate")
	data["DeactivateTOTPConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to deactivate TOTP?")
	data["RegisterTOTP"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register TOTP")

	data["SecurityKeyWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Security Key (WebAuthn)")
	data["SecurityKeysWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Security Keys (WebAuthn)")
	data["RegisteredDevices"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Registered Devices")
	data["NoDevicesFound"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "No registered security keys found.")
	data["LastUsed"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Last used")
	data["Never"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Never")
	data["DeleteConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to delete this security key?")
	data["AddDevice"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Add new security key")
	data["BackTo2FA"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back to 2FA Overview")
	data["WebAuthnDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Use a physical key like Yubikey.")
	data["DeactivateWebAuthnConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to deactivate WebAuthn?")
	data["RegisterWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register WebAuthn")

	data["RecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Codes")
	data["RecoveryCodesDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Backup codes can be used to log in if you lose access to your 2FA device.")
	data["RecoveryCodesLeft"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "You have %d recovery codes left.")
	data["GenerateNewRecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Generate new recovery codes")
	data["GenerateRecoveryCodesConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to generate new recovery codes? Any existing codes will be permanently replaced.")

	data["LoggedOutTitle"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Successfully Logged Out")
	data["LoggedOutMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "You have been successfully logged out of your session.")
	data["BackToLogin"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back to Login")

	data["TOTPVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your 2FA code")
	data["RecoveryVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter one of your recovery codes")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Code")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")

	data["LoggingOutFromAllApplications"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logging out from all applications...")
	data["PleaseWaitWhileLogoutProcessIsCompleted"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please wait while the logout process is completed.")
	data["FrontChannelLogoutURIs"] = []string{"https://app1.example.com/logout", "https://app2.example.com/logout"}
	data["LogoutTarget"] = "/logged_out"

	data["NewRecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "New Recovery Codes")
	data["BackupTheseCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please backup these codes!")
	data["ShownOnlyOnce"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "They will be shown only once.")
	data["Codes"] = []string{"ABCD-1234", "EFGH-5678", "IJKL-9012", "MNOP-3456"}
	data["Close"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Close")

	data["WebAuthnVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please use your security key to login")
	data["JSInteractWithKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please interact with your security key...")
	data["JSCompletingLogin"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Completing login...")
	data["JSUnknownError"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An unknown error occurred")

	data["TOTPMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please scan and verify the following QR code")

	data["WebAuthnMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please connect your security key and follow the instructions")
	data["JSCompletingRegistration"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Completing registration...")

	// Device code verification
	data["DeviceVerifyDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Enter the code displayed on your device and sign in to authorize it.")
	data["UserCodeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device Code")
	data["UserCodePlaceholder"] = "ABCD-EFGH"
	data["PostDeviceVerifyEndpoint"] = "#"
	data["UserCode"] = "ABCD-EFGH"
	data["DeviceVerifySuccessMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Your device has been successfully authorized.")
	data["DeviceVerifySuccessHint"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "You can close this window and return to your device.")

	data["Application"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Application")
	data["WantsToAccessYourAccount"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "wants to access your account")
	data["RequestedPermissions"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Requested permissions")
	data["Allow"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Allow")
	data["Deny"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Deny")

	data["WebAuthnLoginURL"] = "#"
	data["CSRFToken"] = "dev-csrf-token"
	data["PostLoginEndpoint"] = "#"
	data["PostTOTPVerifyEndpoint"] = "#"
	data["PostConsentEndpoint"] = "#"
	data["PostRecoveryVerifyEndpoint"] = "#"
	data["ReturnTo"] = ""
	data["QueryString"] = ""
	data["Protocol"] = "oidc"
	data["LastMFAMethod"] = "totp"
	data["HaveError"] = true
	data["Message"] = "This is a sample error message for dev preview."
	data["ErrorMessage"] = "This is a sample error message for dev preview."
	data["BackendErrorMessage"] = "This is a sample backend error message for dev preview."
	data["Success"] = "This is a sample success message for dev preview."
	data["IsTOTP"] = true
	data["IsWebAuthn"] = true
	data["TOTPEnabled"] = true
	data["WebAuthnEnabled"] = true
	data["ShowRecoveryCodes"] = true
	data["RecoveryCodesList"] = []string{"ABCD-1234", "EFGH-5678", "IJKL-9012", "MNOP-3456", "QRST-7890"}
	data["NumRecoveryCodes"] = 5
	data["HaveTOTP"] = true
	data["HaveWebAuthn"] = true
	data["HaveRecoveryCodes"] = true
	data["BackendError"] = false
	data["ShowRememberMe"] = true
	data["TermsOfServiceURL"] = "https://example.com/tos"
	data["PrivacyPolicyURL"] = "https://example.com/privacy"
	data["WebAuthnAuthenticators"] = []gin.H{
		{"ID": "1", "Name": "YubiKey 5C", "CreatedAt": time.Now().Add(-24 * time.Hour).Format(time.RFC822)},
		{"ID": "2", "Name": "Android Phone", "CreatedAt": time.Now().Add(-48 * time.Hour).Format(time.RFC822)},
	}
	data["Devices"] = []gin.H{
		{"ID": "MTIzNDU2Nzg5MA", "LastUsed": time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04:05")},
		{"ID": "YWJjZGVmZ2hpams", "LastUsed": "Never"},
	}
	data["QRCode"] = "otpauth://totp/Nauthilus:dev-user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Nauthilus"
	data["Secret"] = "JBSWY3DPEHPK3PXP"
	data["Step"] = 1
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
	data["ClientID"] = "test-client"
	data["ConsentChallenge"] = "test-challenge"
	data["State"] = "test-state"
	data["Scopes"] = []string{"openid", "profile", "email"}

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
