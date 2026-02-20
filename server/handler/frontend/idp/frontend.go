// Copyright (C) 2024 Christian Rößner
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
	"encoding/base64"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/cookie"
	corelang "github.com/croessner/nauthilus/server/core/language"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/middleware/csrf"
	"github.com/croessner/nauthilus/server/middleware/i18n"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"
	"github.com/croessner/nauthilus/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// FrontendHandler handles general IdP frontend pages like login and consent.
type FrontendHandler struct {
	deps        *deps.Deps
	mfa         idp.MFAProvider
	deviceStore idp.DeviceCodeStore
	tracer      monittrace.Tracer
}

type mfaAvailability struct {
	haveTOTP          bool
	haveWebAuthn      bool
	haveRecoveryCodes bool
	count             int
}

// NewFrontendHandler creates a new FrontendHandler.
func NewFrontendHandler(d *deps.Deps) *FrontendHandler {
	prefix := d.Cfg.GetServer().GetRedis().GetPrefix()

	return &FrontendHandler{
		deps:        d,
		mfa:         idp.NewMFAService(d),
		deviceStore: idp.NewRedisDeviceCodeStore(d.Redis, prefix),
		tracer:      monittrace.New("nauthilus/idp/frontend"),
	}
}

func (h *FrontendHandler) getLoginURL(ctx *gin.Context) string {
	return h.appendQueryString(h.getLoginPath(ctx), ctx.Request.URL.RawQuery)
}

func (h *FrontendHandler) getLoginPath(ctx *gin.Context) string {
	// For device code flow, redirect back to the device verify page
	if mgr := cookie.GetManager(ctx); mgr != nil {
		if mgr.GetString(definitions.SessionKeyOIDCGrantType, "") == definitions.OIDCFlowDeviceCode {
			return h.deviceVerifyPath(ctx)
		}
	}

	lang := ctx.Param("languageTag")

	if lang != "" {
		return "/login/" + lang
	}

	return "/login"
}

// deviceVerifyPath returns the device verify page path with optional language tag.
func (h *FrontendHandler) deviceVerifyPath(ctx *gin.Context) string {
	lang := ctx.Param("languageTag")

	if lang != "" {
		return "/oidc/device/verify/" + lang
	}

	return "/oidc/device/verify"
}

func (h *FrontendHandler) getMFASelectPath(ctx *gin.Context) string {
	path := "/login/mfa"
	lang := ctx.Param("languageTag")

	if lang != "" {
		path += "/" + lang
	}

	return path
}

func (h *FrontendHandler) appendQueryString(path string, query string) string {
	if query == "" {
		return path
	}

	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}

	return path + separator + query
}

// isValidIdPFlow checks if an active IdP flow exists in the secure session cookie.
// A valid IdP flow is either an OIDC request (authorization code or device code grant)
// or a SAML2 SSO request.
// The /login endpoint MUST NOT be accessed directly without a proper IdP flow.
// All flow state is stored in the encrypted cookie - no URL parameters are used for security.
func (h *FrontendHandler) isValidIdPFlow(ctx *gin.Context) bool {
	mgr := cookie.GetManager(ctx)
	if mgr == nil {
		return false
	}

	// Check if an IdP flow is active in the cookie
	flowActive := mgr.GetBool(definitions.SessionKeyIdPFlowActive, false)
	if !flowActive {
		return false
	}

	// Verify the flow type is valid (OIDC or SAML)
	flowType := mgr.GetString(definitions.SessionKeyIdPFlowType, "")
	if flowType != definitions.ProtoOIDC && flowType != definitions.ProtoSAML {
		return false
	}

	// For OIDC, verify we have required parameters based on the grant type
	if flowType == definitions.ProtoOIDC {
		grantType := mgr.GetString(definitions.SessionKeyOIDCGrantType, "")
		clientID := mgr.GetString(definitions.SessionKeyIdPClientID, "")

		if grantType == definitions.OIDCFlowDeviceCode {
			// Device Code flow requires device code and client ID
			deviceCode := mgr.GetString(definitions.SessionKeyDeviceCode, "")

			if deviceCode == "" || clientID == "" {
				return false
			}
		} else {
			// Authorization Code flow requires client ID and redirect URI
			redirectURI := mgr.GetString(definitions.SessionKeyIdPRedirectURI, "")

			if clientID == "" || redirectURI == "" {
				return false
			}
		}
	}

	// For SAML, verify we have the original URL to resume
	if flowType == definitions.ProtoSAML {
		originalURL := mgr.GetString(definitions.SessionKeyIdPOriginalURL, "")

		if originalURL == "" {
			return false
		}
	}

	return true
}

// renderNoFlowError renders an error page when the /login endpoint is accessed without a valid IdP flow.
func (h *FrontendHandler) renderNoFlowError(ctx *gin.Context) {
	// Check if deps is available (may not be in tests)
	if h.deps == nil || h.deps.Cfg == nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": "This login page can only be accessed through a valid OIDC or SAML2 authentication flow.",
		})

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Error")
	data["ErrorTitle"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid Request")
	data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "This login page can only be accessed through a valid OIDC or SAML2 authentication flow. Please use your application to initiate the login process.")

	ctx.HTML(http.StatusBadRequest, "idp_error.html", data)
}

// Register adds frontend routes to the router.
func (h *FrontendHandler) Register(router gin.IRouter) {
	staticPath := filepath.Clean(h.deps.Cfg.GetServer().Frontend.GetHTMLStaticContentPath())
	assetBase := staticPath

	if filepath.Base(staticPath) == "templates" {
		assetBase = filepath.Dir(staticPath)
	}

	router.StaticFile("/favicon.ico", filepath.Join(assetBase, "img", "favicon.ico"))
	router.Static("/static/css", filepath.Join(assetBase, "css"))
	router.Static("/static/js", filepath.Join(assetBase, "js"))
	router.Static("/static/img", filepath.Join(assetBase, "img"))
	router.Static("/static/fonts", filepath.Join(assetBase, "fonts"))

	router.Use(func(ctx *gin.Context) {
		ctx.Set(definitions.CtxServiceKey, definitions.ServIdP)
		ctx.Next()
	}, mdlua.LuaContextMiddleware())

	var frontendSecret []byte
	h.deps.Cfg.GetServer().GetFrontend().GetEncryptionSecret().WithBytes(func(value []byte) {
		if len(value) == 0 {
			return
		}

		frontendSecret = bytes.Clone(value)
	})
	secureMW := cookie.Middleware(frontendSecret, h.deps.Cfg, h.deps.Env)
	i18nMW := i18n.WithLanguage(h.deps.Cfg, h.deps.Logger, h.deps.LangManager)
	csrfMW := csrf.New()

	router.GET("/login", csrfMW, secureMW, i18nMW, h.Login)
	router.GET("/login/:languageTag", csrfMW, secureMW, i18nMW, h.Login)
	router.POST("/login", csrfMW, secureMW, i18nMW, h.PostLogin)
	router.POST("/login/:languageTag", csrfMW, secureMW, i18nMW, h.PostLogin)
	router.GET("/login/totp", csrfMW, secureMW, i18nMW, h.LoginTOTP)
	router.GET("/login/totp/:languageTag", csrfMW, secureMW, i18nMW, h.LoginTOTP)
	router.POST("/login/totp", csrfMW, secureMW, i18nMW, h.PostLoginTOTP)
	router.POST("/login/totp/:languageTag", csrfMW, secureMW, i18nMW, h.PostLoginTOTP)
	router.GET("/login/webauthn", csrfMW, secureMW, i18nMW, h.LoginWebAuthn)
	router.GET("/login/webauthn/:languageTag", csrfMW, secureMW, i18nMW, h.LoginWebAuthn)
	router.GET("/login/webauthn/begin", csrfMW, secureMW, i18nMW, core.LoginWebAuthnBegin(h.deps.Auth()))
	router.GET("/login/webauthn/begin/:languageTag", csrfMW, secureMW, i18nMW, core.LoginWebAuthnBegin(h.deps.Auth()))
	router.POST("/login/webauthn/finish", csrfMW, secureMW, i18nMW, core.LoginWebAuthnFinish(h.deps.Auth()))
	router.POST("/login/webauthn/finish/:languageTag", csrfMW, secureMW, i18nMW, core.LoginWebAuthnFinish(h.deps.Auth()))
	router.GET("/login/mfa", csrfMW, secureMW, i18nMW, h.LoginMFASelect)
	router.GET("/login/mfa/:languageTag", csrfMW, secureMW, i18nMW, h.LoginMFASelect)
	router.GET("/login/recovery", csrfMW, secureMW, i18nMW, h.LoginRecovery)
	router.GET("/login/recovery/:languageTag", csrfMW, secureMW, i18nMW, h.LoginRecovery)
	router.POST("/login/recovery", csrfMW, secureMW, i18nMW, h.PostLoginRecovery)
	router.POST("/login/recovery/:languageTag", csrfMW, secureMW, i18nMW, h.PostLoginRecovery)

	// Auth protected routes
	authGroup := router.Group(definitions.MFARoot, csrfMW, secureMW, i18nMW, h.AuthMiddleware())
	authGroup.GET("/register/home", h.TwoFAHome)
	authGroup.GET("/register/home/:languageTag", h.TwoFAHome)
	authGroup.GET("/totp/register", h.RegisterTOTP)
	authGroup.GET("/totp/register/:languageTag", h.RegisterTOTP)
	authGroup.POST("/totp/register", h.PostRegisterTOTP)
	authGroup.POST("/totp/register/:languageTag", h.PostRegisterTOTP)
	authGroup.DELETE("/totp", h.DeleteTOTP)

	authGroup.GET("/webauthn/register", h.RegisterWebAuthn)
	authGroup.GET("/webauthn/register/:languageTag", h.RegisterWebAuthn)
	authGroup.GET("/webauthn/register/begin", core.BeginRegistration(h.deps.Auth()))
	authGroup.GET("/webauthn/register/begin/:languageTag", core.BeginRegistration(h.deps.Auth()))
	authGroup.POST("/webauthn/register/finish", core.FinishRegistration(h.deps.Auth()))
	authGroup.POST("/webauthn/register/finish/:languageTag", core.FinishRegistration(h.deps.Auth()))
	authGroup.DELETE("/webauthn", h.DeleteWebAuthn)
	authGroup.GET("/webauthn/devices", h.WebAuthnDevices)
	authGroup.GET("/webauthn/devices/:languageTag", h.WebAuthnDevices)
	authGroup.DELETE("/webauthn/device/:id", h.DeleteWebAuthnDevice)
	authGroup.POST("/webauthn/device/:id/name", h.UpdateWebAuthnDeviceName)

	authGroup.POST("/recovery/generate", h.PostGenerateRecoveryCodes)
	authGroup.POST("/recovery/generate/:languageTag", h.PostGenerateRecoveryCodes)

	router.GET("/logged_out", csrfMW, secureMW, i18nMW, h.LoggedOut)
	router.GET("/logged_out/:languageTag", csrfMW, secureMW, i18nMW, h.LoggedOut)
}

// AuthMiddleware ensures the user is logged in for protected pages like 2FA Self-Service.
// Users must already have a valid session from a completed IdP flow.
// Direct access without a prior login redirects to an error page.
func (h *FrontendHandler) AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		mgr := cookie.GetManager(ctx)
		account := ""

		if mgr != nil {
			account = mgr.GetString(definitions.SessionKeyAccount, "")
		}

		if account == "" {
			// User is not logged in - show error page instead of redirect to login.
			// The 2FA Self-Service pages are only accessible after a completed IdP flow.
			h.renderNoFlowError(ctx)
			ctx.Abort()

			return
		}

		ctx.Next()
	}
}

func (h *FrontendHandler) basePageData(ctx *gin.Context) gin.H {
	data := BasePageData(ctx, h.deps.Cfg, h.deps.LangManager)

	data["DevMode"] = h.deps.Env.GetDevMode()
	data["HXRequest"] = ctx.GetHeader("HX-Request") != ""

	return data
}

// BasePageData returns the common data for all IdP frontend pages.
func BasePageData(ctx *gin.Context, cfg config.File, langManager corelang.Manager) gin.H {
	mgr := cookie.GetManager(ctx)
	lang := "en"
	username := ""
	flowType := ""
	oidcClientID := ""
	samlEntityID := ""

	if mgr != nil {
		lang = mgr.GetString(definitions.SessionKeyLang, "en")
		username = mgr.GetString(definitions.SessionKeyAccount, "")
		flowType = mgr.GetString(definitions.SessionKeyIdPFlowType, "")

		switch flowType {
		case definitions.ProtoOIDC:
			oidcClientID = mgr.GetString(definitions.SessionKeyIdPClientID, "")
		case definitions.ProtoSAML:
			samlEntityID = mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")
		}
	}

	tag := language.Make(lang)
	currentName := cases.Title(tag, cases.NoLower).String(display.Self.Name(tag))

	path := ctx.Request.URL.Path
	// Remove language tag from path for CreateLanguagePassive
	parts := strings.Split(path, "/")

	if len(parts) > 1 {
		lastPart := parts[len(parts)-1]
		for _, t := range langManager.GetTags() {
			b, _ := t.Base()
			if b.String() == lastPart {
				path = strings.Join(parts[:len(parts)-1], "/")

				break
			}
		}
	}

	idpClientName := resolveIdPClientName(cfg, flowType, oidcClientID, samlEntityID)

	return gin.H{
		"LanguageTag":         lang,
		"LanguageCurrentName": currentName,
		"LanguagePassive":     frontend.CreateLanguagePassive(ctx, path, langManager.GetTags(), currentName),
		"Username":            username,
		"ConfirmTitle":        frontend.GetLocalized(ctx, cfg, nil, "Confirmation"),
		"ConfirmYes":          frontend.GetLocalized(ctx, cfg, nil, "Yes"),
		"ConfirmNo":           frontend.GetLocalized(ctx, cfg, nil, "Cancel"),
		"IdPClientName":       idpClientName,
	}
}

func resolveIdPClientName(cfg config.File, flowType string, oidcClientID string, samlEntityID string) string {
	if flowType == definitions.ProtoOIDC && oidcClientID != "" {
		clients := cfg.GetIdP().OIDC.Clients
		for i := range clients {
			if clients[i].ClientID == oidcClientID {
				return clients[i].Name
			}
		}
	}

	if flowType == definitions.ProtoSAML && samlEntityID != "" {
		for _, sp := range cfg.GetIdP().SAML2.ServiceProviders {
			if sp.EntityID == samlEntityID {
				return sp.Name
			}
		}
	}

	return ""
}

// Login renders the modern login page.
// This endpoint is ONLY for IdP flows (OIDC/SAML2). Direct access without a proper flow is rejected.
// All flow state is read from the secure encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) Login(ctx *gin.Context) {
	// Validate that this is a proper IdP flow (checks cookie for active flow)
	if !h.isValidIdPFlow(ctx) {
		h.renderNoFlowError(ctx)

		return
	}

	mgr := cookie.GetManager(ctx)

	// Read flow state from cookie
	flowType := ""
	oidcCID := ""
	samlEntityID := ""

	if mgr != nil {
		flowType = mgr.GetString(definitions.SessionKeyIdPFlowType, "")

		switch flowType {
		case definitions.ProtoOIDC:
			oidcCID = mgr.GetString(definitions.SessionKeyIdPClientID, "")
		case definitions.ProtoSAML:
			samlEntityID = mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")
			if samlEntityID == "" {
				samlEntityID = definitions.ProtoSAML
			}
		}
	}

	// If user is already logged in with a valid session, redirect back to the IdP endpoint
	if mgr != nil && mgr.GetString(definitions.SessionKeyAccount, "") != "" {
		h.redirectToIdPEndpoint(ctx, mgr)

		return
	}

	// For device code flow, user must re-authenticate via the device verify page
	oidcGrantType := ""
	if mgr != nil {
		oidcGrantType = mgr.GetString(definitions.SessionKeyOIDCGrantType, "")
	}

	if oidcGrantType == definitions.OIDCFlowDeviceCode {
		ctx.Redirect(http.StatusFound, h.deviceVerifyPath(ctx))

		return
	}

	if mgr != nil {
		mgr.Delete(definitions.SessionKeyMFAMulti)
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "IdP Login page request",
		"flow_type", flowType,
	)

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
	data["UsernameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Username")
	data["UsernamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your username or email address")
	data["PasswordLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
	data["PasswordPlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your password")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	data["CSRFToken"] = csrf.Token(ctx)
	data["PostLoginEndpoint"] = ctx.Request.URL.Path

	// Check for error message from previous MFA attempt (Fall B Punkt 1)
	// This occurs when user had wrong initial credentials but completed MFA,
	// and is redirected back to login with error message.
	haveError := false
	errorMessage := ""

	if mgr != nil {
		if loginError := mgr.GetString(definitions.SessionKeyLoginError, ""); loginError != "" {
			haveError = true
			errorMessage = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, loginError)

			// Clear the error after reading it
			mgr.Delete(definitions.SessionKeyLoginError)
			_ = mgr.Save(ctx)
		}
	}

	data["HaveError"] = haveError
	data["ErrorMessage"] = errorMessage

	idpInstance := idp.NewNauthilusIdP(h.deps)
	showRememberMe := false

	if oidcCID != "" {
		if client, ok := idpInstance.FindClient(oidcCID); ok {
			showRememberMe = client.RememberMeTTL > 0
		}
	} else if samlEntityID != "" {
		if sp, ok := idpInstance.FindSAMLServiceProvider(samlEntityID); ok {
			showRememberMe = sp.RememberMeTTL > 0
		}
	}

	data["ShowRememberMe"] = showRememberMe
	data["RememberMeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Remember me")
	data["TermsOfServiceURL"] = h.deps.Cfg.GetIdP().TermsOfServiceURL
	data["PrivacyPolicyURL"] = h.deps.Cfg.GetIdP().PrivacyPolicyURL
	data["LegalNoticeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Legal notice")
	data["PrivacyPolicyLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Privacy policy")

	ctx.HTML(http.StatusOK, "idp_login.html", data)
}

// redirectToIdPEndpoint redirects the user back to the appropriate IdP endpoint based on the flow type.
// For OIDC flows, it reconstructs the /oidc/authorize URL from cookie data.
// For SAML flows, it redirects back to the original /saml/sso URL stored in the cookie.
func (h *FrontendHandler) redirectToIdPEndpoint(ctx *gin.Context, mgr cookie.Manager) {
	flowType := mgr.GetString(definitions.SessionKeyIdPFlowType, "")

	// Device code flow must be checked before the general OIDC authorize redirect,
	// because it does not use redirectURI, responseType, etc.
	if flowType == definitions.ProtoOIDC && mgr.GetString(definitions.SessionKeyOIDCGrantType, "") == definitions.OIDCFlowDeviceCode {
		h.completeDeviceCodeFlow(ctx, mgr)

		return
	}

	if flowType == definitions.ProtoOIDC {
		// Reconstruct the OIDC authorize URL from cookie parameters
		clientID := mgr.GetString(definitions.SessionKeyIdPClientID, "")
		redirectURI := mgr.GetString(definitions.SessionKeyIdPRedirectURI, "")
		scope := mgr.GetString(definitions.SessionKeyIdPScope, "")
		state := mgr.GetString(definitions.SessionKeyIdPState, "")
		nonce := mgr.GetString(definitions.SessionKeyIdPNonce, "")
		responseType := mgr.GetString(definitions.SessionKeyIdPResponseType, "")

		authorizeURL := "/oidc/authorize?client_id=" + url.QueryEscape(clientID)
		authorizeURL += "&redirect_uri=" + url.QueryEscape(redirectURI)

		if scope != "" {
			authorizeURL += "&scope=" + url.QueryEscape(scope)
		}

		if state != "" {
			authorizeURL += "&state=" + url.QueryEscape(state)
		}

		if nonce != "" {
			authorizeURL += "&nonce=" + url.QueryEscape(nonce)
		}

		if responseType != "" {
			authorizeURL += "&response_type=" + url.QueryEscape(responseType)
		}

		ctx.Redirect(http.StatusFound, authorizeURL)

		return
	}

	if flowType == definitions.ProtoSAML {
		// Redirect back to the original SAML SSO URL
		originalURL := mgr.GetString(definitions.SessionKeyIdPOriginalURL, "")
		if originalURL != "" {
			ctx.Redirect(http.StatusFound, originalURL)

			return
		}
	}

	// Fallback: redirect to root (should not happen if flow is valid)
	ctx.Redirect(http.StatusFound, "/")
}

// deviceCodeNeedsConsent checks whether the device code flow requires user consent for the given client.
// It mirrors the consent logic from the authorization code grant: consent is needed when
// the client has not set skip_consent and the user has not previously consented in this session.
func (h *FrontendHandler) deviceCodeNeedsConsent(ctx *gin.Context, clientID string) bool {
	idpInstance := idp.NewNauthilusIdP(h.deps)

	client, ok := idpInstance.FindClient(clientID)
	if !ok {
		return false
	}

	if client.SkipConsent {
		return false
	}

	mgr := cookie.GetManager(ctx)

	return !hasClientConsent(mgr, clientID)
}

// completeDeviceCodeFlow authorizes the device code and renders the success page.
// This is called after successful authentication (and MFA if required) in the device code flow.
func (h *FrontendHandler) completeDeviceCodeFlow(ctx *gin.Context, mgr cookie.Manager) {
	deviceCode := mgr.GetString(definitions.SessionKeyDeviceCode, "")
	if deviceCode == "" {
		ctx.Redirect(http.StatusFound, "/")

		return
	}

	request, err := h.deviceStore.GetDeviceCode(ctx.Request.Context(), deviceCode)
	if err != nil || request == nil {
		ctx.Redirect(http.StatusFound, "/")

		return
	}

	// Check if consent is needed before authorizing
	if h.deviceCodeNeedsConsent(ctx, request.ClientID) {
		lang := ctx.Param("languageTag")
		consentPath := "/oidc/device/consent"

		if lang != "" {
			consentPath += "/" + lang
		}

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgIdp,
			definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
			definitions.LogKeyMsg, "Device code flow requires consent (after MFA)",
			"client_id", request.ClientID,
		)

		ctx.Redirect(http.StatusFound, consentPath)

		return
	}

	// Authorize the device code
	request.Status = idp.DeviceCodeStatusAuthorized
	request.UserID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")

	if err := h.deviceStore.UpdateDeviceCode(ctx.Request.Context(), deviceCode, request); err != nil {
		ctx.Redirect(http.StatusFound, "/")

		return
	}

	addClientToCookie(mgr, request.ClientID)

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "Device code authorized via MFA flow (consent skipped)",
		"client_id", request.ClientID,
		"user_id", request.UserID,
		"user_code", request.UserCode,
	)

	// Clean up device code flow session data
	mgr.Delete(definitions.SessionKeyDeviceCode)
	mgr.Delete(definitions.SessionKeyIdPFlowActive)
	mgr.Delete(definitions.SessionKeyIdPFlowType)
	mgr.Delete(definitions.SessionKeyOIDCGrantType)

	renderDeviceCodeSuccess(ctx, h.deps)
}

// PostLogin handles the login submission.
// This endpoint is ONLY for IdP flows (OIDC/SAML2). Direct access without a proper flow is rejected.
// All flow state is read from the secure encrypted cookie - no form parameters for flow state.
func (h *FrontendHandler) PostLogin(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_login")
	defer sp.End()

	// Validate that this is a proper IdP flow (checks cookie for active flow)
	if !h.isValidIdPFlow(ctx) {
		h.renderNoFlowError(ctx)

		return
	}

	mgr := cookie.GetManager(ctx)

	// Read flow state from cookie
	flowType := ""
	oidcCID := ""
	samlEntityID := ""

	if mgr != nil {
		flowType = mgr.GetString(definitions.SessionKeyIdPFlowType, "")

		switch flowType {
		case definitions.ProtoOIDC:
			oidcCID = mgr.GetString(definitions.SessionKeyIdPClientID, "")
		case definitions.ProtoSAML:
			samlEntityID = mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")
			if samlEntityID == "" {
				samlEntityID = definitions.ProtoSAML
			}
		}
	}

	// Device code flow has its own login handler
	if flowType == definitions.ProtoOIDC && mgr != nil && mgr.GetString(definitions.SessionKeyOIDCGrantType, "") == definitions.OIDCFlowDeviceCode {
		ctx.Redirect(http.StatusFound, h.deviceVerifyPath(ctx))

		return
	}

	username := ctx.PostForm("username")
	password := ctx.PostForm("password")
	rememberMe := ctx.PostForm("remember_me") == "on"

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "IdP Login attempt",
		"username", username,
		"flow_type", flowType,
	)

	idpInstance := idp.NewNauthilusIdP(h.deps)

	var rememberMeTTL int

	if rememberMe {
		var ttl time.Duration

		if oidcCID != "" {
			if client, ok := idpInstance.FindClient(oidcCID); ok {
				ttl = client.RememberMeTTL
			}
		} else if samlEntityID != "" {
			if spConfig, ok := idpInstance.FindSAMLServiceProvider(samlEntityID); ok {
				ttl = spConfig.RememberMeTTL
			}
		}

		rememberMeTTL = int(ttl.Seconds())
	}

	sp.SetAttributes(
		attribute.String("username", username),
		attribute.String("oidc_cid", oidcCID),
		attribute.String("saml_entity_id", samlEntityID),
	)

	// Try to get user to see if MFA is present
	user, err := idpInstance.Authenticate(ctx, username, password, oidcCID, samlEntityID)

	protocol := definitions.ProtoIDP

	if oidcCID != "" {
		protocol = definitions.ProtoOIDC
	} else if samlEntityID != "" {
		protocol = definitions.ProtoSAML
	}

	if err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "fail").Inc()

		// Check for Delayed Response
		if idpInstance.IsDelayedResponse(oidcCID, samlEntityID) {
			if user, _ := idpInstance.GetUserByUsername(ctx, username, oidcCID, samlEntityID); user != nil {
				if h.hasTOTP(user) || h.hasWebAuthn(ctx, user, protocol) {
					if mgr != nil {
						mgr.Set(definitions.SessionKeyUsername, username)
						mgr.Set(definitions.SessionKeyUniqueUserID, user.Id)
						mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultFail))
						mgr.Set(definitions.SessionKeyProtocol, protocol)

						if rememberMeTTL > 0 {
							mgr.Set(definitions.SessionKeyRememberTTL, rememberMeTTL)
						}

						mgr.Debug(ctx, h.deps.Logger, "MFA required - pre-auth session data stored (delayed response)")
					}

					// If user has only one MFA option, redirect directly to it
					if redirectURL, ok := h.getMFARedirectURLFromCookie(ctx, user); ok {
						ctx.Redirect(http.StatusFound, redirectURL)

						return
					}

					// Multiple MFA options - redirect to selection page (no query params needed)
					ctx.Redirect(http.StatusFound, "/login/mfa")

					return
				}
			}
		}

		data := h.basePageData(ctx)
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
		data["UsernameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Username")
		data["UsernamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your username or email address")
		data["PasswordLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
		data["PasswordPlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your password")
		data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
		data["LoginWithWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login with WebAuthn")
		data["Or"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or")
		data["WebAuthnLoginURL"] = h.getMFAURLFromCookie(ctx, "webauthn")

		data["CSRFToken"] = csrf.Token(ctx)
		data["PostLoginEndpoint"] = ctx.Request.URL.Path
		data["HaveError"] = true
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid login or password")

		// Calculate ShowRememberMe based on flow state.
		showRememberMe := false
		idpInstance := idp.NewNauthilusIdP(h.deps)

		if oidcCID != "" {
			if client, ok := idpInstance.FindClient(oidcCID); ok {
				showRememberMe = client.RememberMeTTL > 0
			}
		} else if samlEntityID != "" {
			if sp, ok := idpInstance.FindSAMLServiceProvider(samlEntityID); ok {
				showRememberMe = sp.RememberMeTTL > 0
			}
		}

		data["ShowRememberMe"] = showRememberMe
		data["RememberMeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Remember me")
		data["TermsOfServiceURL"] = h.deps.Cfg.GetIdP().TermsOfServiceURL
		data["PrivacyPolicyURL"] = h.deps.Cfg.GetIdP().PrivacyPolicyURL
		data["LegalNoticeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Legal notice")
		data["PrivacyPolicyLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Privacy policy")

		ctx.HTML(http.StatusOK, "idp_login.html", data)

		return
	}

	// Check if user has MFA
	if h.hasTOTP(user) || h.hasWebAuthn(ctx, user, protocol) {
		if mgr != nil {
			mgr.Set(definitions.SessionKeyUsername, username)
			mgr.Set(definitions.SessionKeyUniqueUserID, user.Id)
			mgr.Set(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultOK))
			mgr.Set(definitions.SessionKeyProtocol, protocol)

			if rememberMeTTL > 0 {
				mgr.Set(definitions.SessionKeyRememberTTL, rememberMeTTL)
			}

			mgr.Debug(ctx, h.deps.Logger, "MFA required - pre-auth session data stored")
		}

		// If user has only one MFA option, redirect directly to it
		if redirectURL, ok := h.getMFARedirectURLFromCookie(ctx, user); ok {
			ctx.Redirect(http.StatusFound, redirectURL)

			return
		}

		// Multiple MFA options - redirect to selection page (no query params needed)
		ctx.Redirect(http.StatusFound, "/login/mfa")

		return
	}

	if mgr != nil {
		mgr.Set(definitions.SessionKeyAccount, user.Name)
		mgr.Set(definitions.SessionKeyUniqueUserID, user.Id)
		mgr.Set(definitions.SessionKeyDisplayName, user.DisplayName)
		mgr.Set(definitions.SessionKeySubject, user.Id)
		mgr.Set(definitions.SessionKeyProtocol, protocol)

		if rememberMeTTL > 0 {
			mgr.Set(definitions.SessionKeyRememberTTL, rememberMeTTL)
		}

		mgr.Debug(ctx, h.deps.Logger, "Login successful - session data stored")
	}

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "success").Inc()

	// Redirect back to IdP endpoint to complete the flow
	h.redirectToIdPEndpoint(ctx, mgr)
}

func (h *FrontendHandler) hasTOTP(user *backend.User) bool {
	totpField := user.TOTPSecretField

	if totpField == "" {
		if protocols := h.deps.Cfg.GetLDAP().GetSearch(); len(protocols) > 0 {
			totpField = protocols[0].GetTotpSecretField()
		}
	}

	if totpField != "" {
		if val, ok := user.Attributes[totpField]; ok {
			if len(val) > 0 && val[0] != "" {
				return true
			}
		}
	}

	return false
}

func (h *FrontendHandler) hasWebAuthn(ctx *gin.Context, user *backend.User, protocolName string) bool {
	return h.hasWebAuthnWithProvider(ctx, user, protocolName, nil)
}

func (h *FrontendHandler) hasWebAuthnWithProvider(ctx *gin.Context, user *backend.User, protocolName string, provider webAuthnCredentialProvider) bool {
	if ctx == nil || user == nil {
		return false
	}

	mgr := cookie.GetManager(ctx)

	if provider == nil {
		authDeps := h.deps.Auth()
		state := core.NewAuthStateWithSetupWithDeps(ctx, authDeps)
		if state == nil {
			return false
		}

		resolvedProtocol := protocolName
		if resolvedProtocol == "" && mgr != nil {
			resolvedProtocol = mgr.GetString(definitions.SessionKeyProtocol, "")
		}

		if resolvedProtocol == "" {
			resolvedProtocol = definitions.ProtoIDP
		}

		authState := state.(*core.AuthState)
		authState.SetUsername(user.Name)
		authState.SetProtocol(config.NewProtocol(resolvedProtocol))
		authState.SetNoAuth(true)

		provider = authState
	}

	data := &UserBackendData{
		Username:     user.Name,
		DisplayName:  user.DisplayName,
		UniqueUserID: user.Id,
	}

	h.resolveWebAuthnUser(ctx, nil, data, provider)

	return data.HaveWebAuthn
}

func (h *FrontendHandler) hasRecoveryCodes(user *backend.User) bool {
	recoveryField := user.TOTPRecoveryField

	if recoveryField == "" {
		if protocols := h.deps.Cfg.GetLDAP().GetSearch(); len(protocols) > 0 {
			recoveryField = protocols[0].GetTotpRecoveryField()
		}
	}

	if recoveryField != "" {
		if val, ok := user.Attributes[recoveryField]; ok {
			return len(val) > 0
		}
	}

	return false
}

// LoginMFASelect renders the MFA selection page.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) LoginMFASelect(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	username := ""
	protocol := ""

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyUsername, "")
		protocol = mgr.GetString(definitions.SessionKeyIdPFlowType, "")
	}

	if username == "" {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	// Get user to check available MFA methods
	idpInstance := idp.NewNauthilusIdP(h.deps)
	user, err := idpInstance.GetUserByUsername(ctx, username, "", "")

	if err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	availability := h.getMFAAvailability(ctx, user, protocol)
	multi := availability.count > 1

	if mgr != nil {
		mgr.Set(definitions.SessionKeyMFAMulti, multi)
	}

	// If user has only one MFA option, redirect directly to it
	if redirectURL, ok := h.getMFARedirectURLFromCookie(ctx, user); ok {
		ctx.Redirect(http.StatusFound, redirectURL)

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["SelectMFA"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Select Multi-Factor Authentication")
	data["ChooseMFADescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Choose your preferred second factor")
	data["AuthenticatorApp"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Authenticator App")
	data["SecurityKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Security Key")
	data["RecoveryCode"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Code")
	data["Recommended"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recommended")
	data["Or"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	data["HaveTOTP"] = availability.haveTOTP
	data["HaveWebAuthn"] = availability.haveWebAuthn
	data["HaveRecoveryCodes"] = availability.haveRecoveryCodes

	// Check for last used MFA method
	lastMFA, _ := ctx.Cookie("last_mfa_method")
	recommendedMethod := ""

	switch lastMFA {
	case "totp":
		if availability.haveTOTP {
			recommendedMethod = "totp"
		}
	case "webauthn":
		if availability.haveWebAuthn {
			recommendedMethod = "webauthn"
		}
	case "recovery":
		if availability.haveRecoveryCodes {
			recommendedMethod = "recovery"
		}
	}

	hasOtherMethods := recommendedMethod != "" && ((availability.haveTOTP && recommendedMethod != "totp") ||
		(availability.haveWebAuthn && recommendedMethod != "webauthn") || (availability.haveRecoveryCodes && recommendedMethod != "recovery"))

	data["LastMFAMethod"] = lastMFA
	data["RecommendedMethod"] = recommendedMethod
	data["HasOtherMethods"] = hasOtherMethods
	data["OtherMethods"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Other methods")
	data["BackURL"] = h.getLoginPath(ctx)

	ctx.HTML(http.StatusOK, "idp_mfa_select.html", data)
}

// LoginRecovery renders the recovery code verification page during login.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) LoginRecovery(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)

	if mgr == nil || mgr.GetString(definitions.SessionKeyUsername, "") == "" {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["RecoveryVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter one of your recovery codes")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")

	data["CSRFToken"] = csrf.Token(ctx)
	data["PostRecoveryVerifyEndpoint"] = ctx.Request.URL.Path
	data["BackURL"] = h.getLoginMFABackURLFromCookie(ctx)
	data["HaveError"] = false

	ctx.HTML(http.StatusOK, "idp_recovery_login.html", data)
}

// mfaSessionState holds the common session state extracted for MFA verification handlers.
type mfaSessionState struct {
	mgr          cookie.Manager
	username     string
	oidcCID      string
	samlEntityID string
}

// extractMFASessionAndUser reads the MFA session state and form code from the cookie/request,
// validates presence of required fields, and looks up the user. Returns nil if any step fails
// (the caller is redirected to the login page in that case).
func (h *FrontendHandler) extractMFASessionAndUser(ctx *gin.Context) (*mfaSessionState, *backend.User, string) {
	mgr := cookie.GetManager(ctx)

	var (
		username      string
		hasAuthResult bool
		oidcCID       string
		samlEntityID  string
	)

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyUsername, "")
		hasAuthResult = mgr.HasKey(definitions.SessionKeyAuthResult)

		flowType := mgr.GetString(definitions.SessionKeyIdPFlowType, "")

		switch flowType {
		case definitions.ProtoOIDC:
			oidcCID = mgr.GetString(definitions.SessionKeyIdPClientID, "")
		case definitions.ProtoSAML:
			samlEntityID = mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")
			if samlEntityID == "" {
				samlEntityID = definitions.ProtoSAML
			}
		}
	}

	code := ctx.PostForm("code")

	if username == "" || !hasAuthResult || code == "" {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return nil, nil, ""
	}

	idpInstance := idp.NewNauthilusIdP(h.deps)
	user, err := idpInstance.GetUserByUsername(ctx, username, oidcCID, samlEntityID)

	if err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return nil, nil, ""
	}

	state := &mfaSessionState{
		mgr:          mgr,
		username:     username,
		oidcCID:      oidcCID,
		samlEntityID: samlEntityID,
	}

	return state, user, code
}

// PostLoginRecovery handles the recovery code verification during login.
// All flow state is read from the encrypted cookie - no form parameters for flow state.
func (h *FrontendHandler) PostLoginRecovery(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_login_recovery")
	defer sp.End()

	sess, user, code := h.extractMFASessionAndUser(ctx)
	if sess == nil {
		return
	}

	// Verify Recovery Code
	sourceBackend := uint8(definitions.BackendLDAP)

	if sess.mgr != nil {
		sourceBackend = sess.mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
	}

	success, err := h.mfa.UseRecoveryCode(ctx, sess.username, code, sourceBackend)

	if err != nil {
		h.deps.Logger.Error("Failed to use recovery code", "error", err)
	}

	if !success {
		data := h.basePageData(ctx)
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
		data["RecoveryVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter one of your recovery codes")
		data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Code")
		data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
		data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")

		data["CSRFToken"] = csrf.Token(ctx)
		data["PostRecoveryVerifyEndpoint"] = ctx.Request.URL.Path
		data["BackURL"] = h.getLoginMFABackURLFromCookie(ctx)
		data["HaveError"] = true
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid recovery code")

		ctx.HTML(http.StatusOK, "idp_recovery_login.html", data)

		return
	}

	// MFA Success
	h.setLastMFAMethod(ctx, "recovery")
	h.finalizeMFALogin(ctx, user)
}

func (h *FrontendHandler) setLastMFAMethod(ctx *gin.Context, method string) {
	secure := util.ShouldSetSecureCookie()

	ctx.SetCookie("last_mfa_method", method, 365*24*60*60, "/", "", secure, true)

	if mgr := cookie.GetManager(ctx); mgr != nil {
		mgr.Set(definitions.SessionKeyMFAMethod, method)
	}
}

func (h *FrontendHandler) getMFAAvailability(ctx *gin.Context, user *backend.User, protocolParam string) mfaAvailability {
	haveTOTP := h.hasTOTP(user)
	haveWebAuthn := h.hasWebAuthn(ctx, user, protocolParam)
	haveRecoveryCodes := h.hasRecoveryCodes(user)

	count := 0

	if haveTOTP {
		count++
	}

	if haveWebAuthn {
		count++
	}

	if count != 0 && haveRecoveryCodes {
		count++
	}

	return mfaAvailability{
		haveTOTP:          haveTOTP,
		haveWebAuthn:      haveWebAuthn,
		haveRecoveryCodes: haveRecoveryCodes,
		count:             count,
	}
}

// getMFARedirectURLFromCookie returns the MFA redirect URL based on user's available MFA methods.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) getMFARedirectURLFromCookie(ctx *gin.Context, user *backend.User) (string, bool) {
	mgr := cookie.GetManager(ctx)
	protocolParam := ""

	if mgr != nil {
		protocolParam = mgr.GetString(definitions.SessionKeyIdPFlowType, "")
	}

	availability := h.getMFAAvailability(ctx, user, protocolParam)

	if availability.count > 1 {
		return "", false
	}

	var target string

	if availability.haveTOTP {
		target = "/login/totp"
	} else if availability.haveWebAuthn {
		target = "/login/webauthn"
	} else if availability.haveRecoveryCodes {
		target = "/login/recovery"
	} else {
		// No MFA methods available
		return "", false
	}

	// No query parameters needed - all flow state is in the cookie
	return target, true
}

// getMFAURLFromCookie returns the URL for a specific MFA method.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) getMFAURLFromCookie(_ *gin.Context, mfaType string) string {
	return "/login/" + mfaType
}

// getLoginMFABackURLFromCookie returns the URL to go back from MFA verification.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) getLoginMFABackURLFromCookie(ctx *gin.Context) string {
	mgr := cookie.GetManager(ctx)
	multi := false

	if mgr != nil {
		multi = mgr.GetBool(definitions.SessionKeyMFAMulti, false)
	}

	if !multi {
		return h.getLoginPath(ctx)
	}

	return h.getMFASelectPath(ctx)
}

// finalizeMFALogin completes the MFA login process and redirects to the IdP endpoint.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) finalizeMFALogin(ctx *gin.Context, user *backend.User) {
	mgr := cookie.GetManager(ctx)
	protocol := ""
	rememberMeTTL := 0

	if mgr != nil {
		protocol = mgr.GetString(definitions.SessionKeyProtocol, "")
		rememberMeTTL = mgr.GetInt(definitions.SessionKeyRememberTTL, 0)

		mgr.Set(definitions.SessionKeyAccount, user.Name)
		mgr.Set(definitions.SessionKeyUniqueUserID, user.Id)
		mgr.Set(definitions.SessionKeyDisplayName, user.DisplayName)
		mgr.Set(definitions.SessionKeySubject, user.Id)
		mgr.Set(definitions.SessionKeyProtocol, protocol)
		mgr.Set(definitions.SessionKeyMFACompleted, true)

		if rememberMeTTL > 0 {
			mgr.Set(definitions.SessionKeyRememberTTL, rememberMeTTL)
		}

		mgr.Debug(ctx, h.deps.Logger, "MFA login finalized - session data stored")
	}

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "success").Inc()

	// Redirect back to IdP endpoint to complete the flow
	h.redirectToIdPEndpoint(ctx, mgr)
}

// LoginWebAuthn renders the WebAuthn verification page during login.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) LoginWebAuthn(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)
	username := ""

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyUsername, "")
	}

	if username == "" {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["WebAuthnVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please use your security key to login")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")

	data["CSRFToken"] = csrf.Token(ctx)
	data["WebAuthnBeginEndpoint"] = h.getMFAURLFromCookie(ctx, "webauthn/begin")
	data["WebAuthnFinishEndpoint"] = h.getMFAURLFromCookie(ctx, "webauthn/finish")
	data["BackURL"] = h.getLoginMFABackURLFromCookie(ctx)

	// JS Localizations
	data["JSInteractWithKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please interact with your security key...")
	data["JSCompletingLogin"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Completing login...")
	data["JSUnknownError"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An unknown error occurred")
	data["Username"] = username

	ctx.HTML(http.StatusOK, "idp_webauthn_verify.html", data)
}

// LoginTOTP renders the TOTP verification page during login.
// All flow state is read from the encrypted cookie - no URL parameters are used.
func (h *FrontendHandler) LoginTOTP(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)

	if mgr == nil || mgr.GetString(definitions.SessionKeyUsername, "") == "" {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["TOTPVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your 2FA code")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")

	data["CSRFToken"] = csrf.Token(ctx)
	data["PostTOTPVerifyEndpoint"] = ctx.Request.URL.Path
	data["BackURL"] = h.getLoginMFABackURLFromCookie(ctx)
	data["HaveError"] = false

	ctx.HTML(http.StatusOK, "idp_totp_verify.html", data)
}

// PostLoginTOTP handles the TOTP verification during login.
// All flow state is read from the encrypted cookie - no form parameters for flow state.
func (h *FrontendHandler) PostLoginTOTP(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_login_totp")
	defer sp.End()

	sess, user, code := h.extractMFASessionAndUser(ctx)
	if sess == nil {
		return
	}

	authResult := uint8(definitions.AuthResultFail)

	if sess.mgr != nil {
		authResult = sess.mgr.GetUint8(definitions.SessionKeyAuthResult, uint8(definitions.AuthResultFail))
	}

	// Verify TOTP
	authDeps := h.deps.Auth()
	state := core.NewAuthStateWithSetupWithDeps(ctx, authDeps)

	if state == nil {
		ctx.Redirect(http.StatusFound, h.getLoginPath(ctx))

		return
	}

	auth := state.(*core.AuthState)
	auth.SetUsername(sess.username)
	auth.SetOIDCCID(sess.oidcCID)
	auth.SetSAMLEntityID(sess.samlEntityID)

	// We need to load user into auth to get TOTP secret and recovery codes
	// GetUserByUsername already did some of this, but TotpValidation expects secrets in AuthState
	auth.ReplaceAllAttributes(user.Attributes)
	auth.SetTOTPSecretField(user.TOTPSecretField)
	auth.SetTOTPRecoveryField(user.TOTPRecoveryField)

	err := core.TotpValidation(ctx, auth, code, authDeps)

	if err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "totp", "fail").Inc()

		data := h.basePageData(ctx)
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
		data["TOTPVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your 2FA code")
		data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
		data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

		data["CSRFToken"] = csrf.Token(ctx)
		data["PostTOTPVerifyEndpoint"] = ctx.Request.URL.Path
		data["BackURL"] = h.getLoginMFABackURLFromCookie(ctx)
		data["HaveError"] = true
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid OTP code")

		ctx.HTML(http.StatusOK, "idp_totp_verify.html", data)

		return
	}

	// MFA OK. Now check if the original password was OK.
	if authResult != uint8(definitions.AuthResultOK) {
		stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "fail").Inc()

		data := h.basePageData(ctx)
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
		data["UsernameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Username")
		data["UsernamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your username or email address")
		data["PasswordLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
		data["PasswordPlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your password")
		data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
		data["LoginWithWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login with WebAuthn")
		data["Or"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or")
		data["WebAuthnLoginURL"] = h.getMFAURLFromCookie(ctx, "webauthn")

		data["CSRFToken"] = csrf.Token(ctx)
		lang := ctx.Param("languageTag")

		if lang != "" {
			data["PostLoginEndpoint"] = "/login/" + lang
		} else {
			data["PostLoginEndpoint"] = "/login"
		}

		data["HaveError"] = true
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid login or password")

		// Calculate ShowRememberMe based on flow state.
		showRememberMe := false
		idpInstance := idp.NewNauthilusIdP(h.deps)

		if sess.oidcCID != "" {
			if client, ok := idpInstance.FindClient(sess.oidcCID); ok {
				showRememberMe = client.RememberMeTTL > 0
			}
		} else if sess.samlEntityID != "" {
			if sp, ok := idpInstance.FindSAMLServiceProvider(sess.samlEntityID); ok {
				showRememberMe = sp.RememberMeTTL > 0
			}
		}

		data["ShowRememberMe"] = showRememberMe
		data["RememberMeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Remember me")
		data["TermsOfServiceURL"] = h.deps.Cfg.GetIdP().TermsOfServiceURL
		data["PrivacyPolicyURL"] = h.deps.Cfg.GetIdP().PrivacyPolicyURL
		data["LegalNoticeLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Legal notice")
		data["PrivacyPolicyLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Privacy policy")

		// Important: clean up cookie so they start over
		if sess.mgr != nil {
			sess.mgr.Delete(definitions.SessionKeyUsername)
			sess.mgr.Delete(definitions.SessionKeyAuthResult)
		}

		ctx.HTML(http.StatusOK, "idp_login.html", data)

		return
	}

	// All OK!
	h.setLastMFAMethod(ctx, "totp")
	h.finalizeMFALogin(ctx, user)
}

// TwoFAHome renders the 2FA management overview.
func (h *FrontendHandler) TwoFAHome(ctx *gin.Context) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "IdP 2FA Self-Service home request",
	)

	mgr := cookie.GetManager(ctx)
	data := h.basePageData(ctx)

	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Self-Service")
	data["AuthenticatorAppTOTP"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Authenticator App (TOTP)")
	data["TOTPDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Use an app like Google Authenticator or Authy.")
	data["SecurityKeyWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Security Key (WebAuthn)")
	data["WebAuthnDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Use a physical key like Yubikey.")
	data["RegisterTOTP"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register TOTP")
	data["RegisterWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register WebAuthn")
	data["Deactivate"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Deactivate")
	data["DeactivateTOTPConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to deactivate TOTP?")
	data["DeactivateWebAuthnConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to deactivate WebAuthn?")
	data["RecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Codes")
	data["RecoveryCodesDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Backup codes can be used to log in if you lose access to your 2FA device.")
	data["RecoveryCodesLeft"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "You have %d recovery codes left.")
	data["GenerateNewRecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Generate new recovery codes")
	data["Home"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Home")
	data["Logout"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout")

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.handleTwoFAHomeError(ctx, data, err, "")

		return
	}

	data["Username"] = userData.Username
	data["DisplayName"] = userData.DisplayName
	data["HaveTOTP"] = userData.HaveTOTP
	data["HaveRecoveryCodes"] = userData.NumRecoveryCodes > 0
	data["NumRecoveryCodes"] = userData.NumRecoveryCodes
	data["HaveWebAuthn"] = userData.HaveWebAuthn

	// Sync cookie if account exists
	if mgr != nil && mgr.GetString(definitions.SessionKeyAccount, "") != "" {
		mgr.Set(definitions.SessionKeyHaveTOTP, userData.HaveTOTP)
	}

	data["CSRFToken"] = csrf.Token(ctx)

	ctx.HTML(http.StatusOK, "idp_2fa_home.html", data)
}

func (h *FrontendHandler) handleTwoFAHomeError(ctx *gin.Context, data gin.H, err error, username string) {
	h.deps.Logger.Error("Session error in TwoFAHome",
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		"username", username,
		definitions.LogKeyError, err,
	)

	data["BackendError"] = true
	data["BackendErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An internal error occurred. Please contact your administrator.")
	data["CSRFToken"] = csrf.Token(ctx)

	ctx.HTML(http.StatusOK, "idp_2fa_home.html", data)
}

// RegisterTOTP renders the TOTP registration page.
func (h *FrontendHandler) RegisterTOTP(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)

	haveTOTP := false
	account := ""

	if mgr != nil {
		haveTOTP = mgr.GetBool(definitions.SessionKeyHaveTOTP, false)
		account = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	if haveTOTP {
		ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
		ctx.Status(http.StatusFound)

		return
	}

	if account == "" {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	secret, qrCodeURL, err := h.mfa.GenerateTOTPSecret(ctx, account)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to generate TOTP key")

		return
	}

	if mgr != nil {
		mgr.Set(definitions.SessionKeyTOTPSecret, secret)
	}

	data := h.basePageData(ctx)
	data["QRCode"] = qrCodeURL
	data["Secret"] = secret
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register TOTP")
	data["TOTPMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please scan and verify the following QR code")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["CSRFToken"] = csrf.Token(ctx)

	ctx.HTML(http.StatusOK, "idp_totp_register.html", data)
}

// PostRegisterTOTP handles the TOTP registration submission.
func (h *FrontendHandler) PostRegisterTOTP(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_register_totp")
	defer sp.End()

	mgr := cookie.GetManager(ctx)
	secret := ""
	username := ""
	sourceBackend := uint8(definitions.BackendLDAP)

	if mgr != nil {
		secret = mgr.GetString(definitions.SessionKeyTOTPSecret, "")
		username = mgr.GetString(definitions.SessionKeyAccount, "")
		sourceBackend = mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
	}

	code := ctx.PostForm("code")

	if secret == "" || username == "" || code == "" {
		h.renderErrorModal(ctx, "Invalid request")

		return
	}

	if err := h.mfa.VerifyAndSaveTOTP(ctx, username, secret, code, sourceBackend); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "totp", "fail").Inc()
		h.renderErrorModal(ctx, err.Error())

		return
	}

	auth := core.NewAuthStateFromContextWithDeps(ctx, h.deps.Auth())
	auth.PurgeCacheFor(username)

	// Success!
	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "totp", "success").Inc()

	if mgr != nil {
		mgr.Set(definitions.SessionKeyHaveTOTP, true)
		mgr.Delete(definitions.SessionKeyTOTPSecret)
	}

	ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
	ctx.Status(http.StatusOK)
}

// PostGenerateRecoveryCodes handles generating new recovery codes.
func (h *FrontendHandler) PostGenerateRecoveryCodes(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_generate_recovery_codes")
	defer sp.End()

	mgr := cookie.GetManager(ctx)
	username := ""
	sourceBackend := uint8(definitions.BackendLDAP)

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyAccount, "")
		sourceBackend = mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
	}

	if username == "" {
		h.renderErrorModal(ctx, "Invalid request")

		return
	}

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.renderErrorModal(ctx, "Failed to fetch user data")

		return
	}

	if !userData.HaveTOTP && !userData.HaveWebAuthn {
		h.renderErrorModal(ctx, "At least one MFA method (TOTP or WebAuthn) must be active to generate recovery codes")

		return
	}

	codes, err := h.mfa.GenerateRecoveryCodes(ctx, username, sourceBackend)
	if err != nil {
		sp.RecordError(err)
		h.renderErrorModal(ctx, "Failed to generate recovery codes: "+err.Error())

		return
	}

	// Success!
	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "recovery", "success").Inc()

	state := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
	if state != nil {
		state.PurgeCacheFor(username)
	}

	data := h.basePageData(ctx)
	data["NewRecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "New recovery codes")
	data["BackupTheseCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Backup these codes!")
	data["ShownOnlyOnce"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "They will be shown only once.")
	data["Close"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Close")
	data["Codes"] = codes

	ctx.HTML(http.StatusOK, "idp_recovery_codes_modal.html", data)
}

// DeleteTOTP removes TOTP for the user.
func (h *FrontendHandler) DeleteTOTP(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.delete_totp")
	defer sp.End()

	mgr := cookie.GetManager(ctx)
	username := ""
	sourceBackend := uint8(definitions.BackendLDAP)

	if mgr != nil {
		username = mgr.GetString(definitions.SessionKeyAccount, "")
		sourceBackend = mgr.GetUint8(definitions.SessionKeyUserBackend, uint8(definitions.BackendLDAP))
	}

	if username == "" {
		h.renderErrorModal(ctx, "Invalid request")

		return
	}

	if err := h.mfa.DeleteTOTP(ctx, username, sourceBackend); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "fail").Inc()
		h.renderErrorModal(ctx, "Failed to delete TOTP secret: "+err.Error())

		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "success").Inc()

	if mgr != nil {
		mgr.Set(definitions.SessionKeyHaveTOTP, false)
	}

	state := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
	if state == nil {
		h.renderErrorModal(ctx, "Failed to initialize auth state")

		return
	}

	state.PurgeCacheFor(username)

	ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
	ctx.Status(http.StatusOK)
}

// DeleteWebAuthn removes WebAuthn credentials for the user.
func (h *FrontendHandler) DeleteWebAuthn(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.delete_webauthn")
	defer sp.End()

	mgr := cookie.GetManager(ctx)
	userID := ""
	username := ""

	if mgr != nil {
		userID = mgr.GetString(definitions.SessionKeyUniqueUserID, "")
		username = mgr.GetString(definitions.SessionKeyAccount, "")
	}

	if userID == "" || username == "" {
		h.renderErrorModal(ctx, "Invalid request")

		return
	}

	// First, clear the Redis cache
	key := h.deps.Cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + userID
	if err := h.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), key).Err(); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "fail").Inc()
		h.renderErrorModal(ctx, "Failed to delete WebAuthn from Redis: "+err.Error())

		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "success").Inc()

	state := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
	if state != nil {
		state.PurgeCacheFor(username)
	}

	ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
	ctx.Status(http.StatusOK)
}

// RegisterWebAuthn renders the WebAuthn registration page.
func (h *FrontendHandler) RegisterWebAuthn(ctx *gin.Context) {
	mgr := cookie.GetManager(ctx)

	if mgr == nil || mgr.GetString(definitions.SessionKeyUniqueUserID, "") == "" {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register WebAuthn")
	data["WebAuthnMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please connect your security key and follow the instructions")
	data["DeviceNameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device name")
	data["DeviceNamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "e.g. Office YubiKey")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	// JS Localizations
	data["JSInteractWithKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please interact with your security key...")
	data["JSCompletingRegistration"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Completing registration...")
	data["JSDeviceNameRequired"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter a device name")
	data["JSUnknownError"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An unknown error occurred")
	data["CSRFToken"] = csrf.Token(ctx)

	ctx.HTML(http.StatusOK, "idp_webauthn_register.html", data)
}

// LoggedOut renders the logout confirmation page.
func (h *FrontendHandler) LoggedOut(ctx *gin.Context) {
	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logged Out")
	data["LoggedOutTitle"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Successfully Logged Out")
	data["LoggedOutMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "You have been successfully logged out of your session.")
	data["BackToLogin"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back to Login")

	ctx.HTML(http.StatusOK, "idp_logged_out.html", data)
}

func (h *FrontendHandler) renderErrorModal(ctx *gin.Context, msg string) {
	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Error")
	data["Message"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, msg)
	data["Close"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Close")

	ctx.HTML(http.StatusOK, "idp_error_modal.html", data)
}

// WebAuthnDevices renders the WebAuthn devices overview page.
func (h *FrontendHandler) WebAuthnDevices(ctx *gin.Context) {
	data := h.basePageData(ctx)

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.handleTwoFAHomeError(ctx, data, err, "")

		return
	}

	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Security Keys (WebAuthn)")
	data["RegisteredDevices"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Registered Devices")
	data["DeviceName"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device name")
	data["DeviceID"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Device ID")
	data["NoDevicesFound"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "No registered security keys found.")
	data["LastUsed"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Last used")
	data["Never"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Never")
	data["Rename"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Rename")
	data["Save"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Save")
	data["Cancel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Cancel")
	data["Delete"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Delete")
	data["DeleteConfirm"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Are you sure you want to delete this security key?")
	data["AddDevice"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Add new security key")
	data["BackTo2FA"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back to 2FA Overview")
	data["UnnamedDevice"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Unnamed device")

	type device struct {
		Name     string
		ID       string
		LastUsed string
	}

	var devices []device
	if userData.WebAuthnUser != nil {
		for _, cred := range userData.WebAuthnUser.Credentials {
			name := strings.TrimSpace(cred.Name)

			lastUsed := data["Never"].(string)
			if !cred.LastUsed.IsZero() {
				lastUsed = cred.LastUsed.Format("2006-01-02 15:04:05")
			}

			devices = append(devices, device{
				Name:     name,
				ID:       base64.RawURLEncoding.EncodeToString(cred.ID),
				LastUsed: lastUsed,
			})
		}
	}

	data["Devices"] = devices
	data["CSRFToken"] = csrf.Token(ctx)

	ctx.HTML(http.StatusOK, "idp_2fa_webauthn_devices.html", data)
}

// DeleteWebAuthnDevice removes a specific WebAuthn credential for the user.
func (h *FrontendHandler) DeleteWebAuthnDevice(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.delete_webauthn_device")
	defer sp.End()

	id := ctx.Param("id")
	if id == "" {
		h.renderErrorModal(ctx, "Missing device ID")

		return
	}

	decodedID, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		h.renderErrorModal(ctx, "Invalid device ID")

		return
	}

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.renderErrorModal(ctx, "Not logged in")

		return
	}

	if userData.WebAuthnUser == nil {
		h.renderErrorModal(ctx, "User not found")

		return
	}

	// Find the credential
	var targetCred *mfa.PersistentCredential
	for _, cred := range userData.WebAuthnUser.Credentials {
		if bytes.Equal(cred.ID, decodedID) {
			targetCred = &cred
			break
		}
	}

	if targetCred == nil {
		h.renderErrorModal(ctx, "Credential not found")

		return
	}

	// Delete from backend via AuthState
	if err := userData.AuthState.DeleteWebAuthnCredential(targetCred); err != nil {
		sp.RecordError(err)
		h.renderErrorModal(ctx, "Failed to delete credential: "+err.Error())

		return
	}

	// update Redis cache
	// Also remove the entire user if no credentials left?
	// Existing code just Del the key in DeleteWebAuthn.
	// We'll update it here.
	if len(userData.WebAuthnUser.Credentials) <= 1 {
		// If this was the last credential, we can delete the Redis key
		key := h.deps.Cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + userData.UniqueUserID
		_ = h.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), key).Err()
	} else {
		// Remove from Credentials slice
		newCreds := make([]mfa.PersistentCredential, 0, len(userData.WebAuthnUser.Credentials)-1)
		for _, c := range userData.WebAuthnUser.Credentials {
			if !bytes.Equal(c.ID, decodedID) {
				newCreds = append(newCreds, c)
			}
		}
		userData.WebAuthnUser.Credentials = newCreds

		// Update Redis cache (with original TTL or default)
		_ = backend.SaveWebAuthnToRedis(ctx.Request.Context(), h.deps.Logger, h.deps.Cfg, h.deps.Redis, userData.WebAuthnUser, h.deps.Cfg.GetServer().GetTimeouts().GetRedisWrite())
	}

	userData.AuthState.PurgeCacheFor(userData.Username)

	ctx.Header("HX-Redirect", definitions.MFARoot+"/webauthn/devices")
	ctx.Status(http.StatusOK)
}

// UpdateWebAuthnDeviceName renames a specific WebAuthn credential for the user.
func (h *FrontendHandler) UpdateWebAuthnDeviceName(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.update_webauthn_device_name")
	defer sp.End()

	id := ctx.Param("id")
	if id == "" {
		h.renderErrorModal(ctx, "Missing device ID")

		return
	}

	name := strings.TrimSpace(ctx.PostForm("name"))
	if name == "" {
		h.renderErrorModal(ctx, "Missing device name")

		return
	}

	decodedID, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		h.renderErrorModal(ctx, "Invalid device ID")

		return
	}

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.renderErrorModal(ctx, "Not logged in")

		return
	}

	if userData.WebAuthnUser == nil {
		h.renderErrorModal(ctx, "User not found")

		return
	}

	targetIndex := slices.IndexFunc(userData.WebAuthnUser.Credentials, func(credential mfa.PersistentCredential) bool {
		return bytes.Equal(credential.ID, decodedID)
	})

	if targetIndex == -1 {
		h.renderErrorModal(ctx, "Credential not found")

		return
	}

	oldCredential := userData.WebAuthnUser.Credentials[targetIndex]
	newCredential := oldCredential
	newCredential.Name = name

	if err := userData.AuthState.UpdateWebAuthnCredential(&oldCredential, &newCredential); err != nil {
		sp.RecordError(err)
		h.renderErrorModal(ctx, "Failed to update credential: "+err.Error())

		return
	}

	userData.WebAuthnUser.Credentials[targetIndex].Name = name
	_ = backend.SaveWebAuthnToRedis(ctx.Request.Context(), h.deps.Logger, h.deps.Cfg, h.deps.Redis, userData.WebAuthnUser, h.deps.Cfg.GetServer().GetTimeouts().GetRedisWrite())

	userData.AuthState.PurgeCacheFor(userData.Username)

	ctx.Header("HX-Redirect", definitions.MFARoot+"/webauthn/devices")
	ctx.Status(http.StatusOK)
}
