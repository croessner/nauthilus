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
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	corelang "github.com/croessner/nauthilus/server/core/language"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/middleware/i18n"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"
	"github.com/croessner/nauthilus/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// FrontendHandler handles general IdP frontend pages like login and consent.
type FrontendHandler struct {
	deps   *deps.Deps
	store  sessions.Store
	mfa    idp.MFAProvider
	tracer monittrace.Tracer
}

// NewFrontendHandler creates a new FrontendHandler.
func NewFrontendHandler(sessStore sessions.Store, d *deps.Deps) *FrontendHandler {
	return &FrontendHandler{
		deps:   d,
		store:  sessStore,
		mfa:    idp.NewMFAService(d),
		tracer: monittrace.New("nauthilus/idp/frontend"),
	}
}

func (h *FrontendHandler) getLoginURL(ctx *gin.Context) string {
	lang := ctx.Param("languageTag")
	var path string

	if lang != "" {
		path = "/login/" + lang
	} else {
		path = "/login"
	}

	return h.appendQueryString(path, ctx.Request.URL.RawQuery)
}

func (h *FrontendHandler) getMFAURL(ctx *gin.Context, mfaType string) string {
	path := "/login/" + mfaType
	lang := ctx.Param("languageTag")

	if lang != "" {
		path += "/" + lang
	}

	return h.appendQueryString(path, ctx.Request.URL.RawQuery)
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

func (h *FrontendHandler) redirectWithQuery(ctx *gin.Context, target string) {
	ctx.Redirect(http.StatusFound, h.appendQueryString(target, ctx.Request.URL.RawQuery))
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

	sessionMW := sessions.Sessions(definitions.SessionName, h.store)
	i18nMW := i18n.WithLanguage(h.deps.Cfg, h.deps.Logger, h.deps.LangManager)

	router.GET("/login", sessionMW, i18nMW, h.Login)
	router.GET("/login/:languageTag", sessionMW, i18nMW, h.Login)
	router.POST("/login", sessionMW, i18nMW, h.PostLogin)
	router.POST("/login/:languageTag", sessionMW, i18nMW, h.PostLogin)
	router.GET("/login/totp", sessionMW, i18nMW, h.LoginTOTP)
	router.GET("/login/totp/:languageTag", sessionMW, i18nMW, h.LoginTOTP)
	router.POST("/login/totp", sessionMW, i18nMW, h.PostLoginTOTP)
	router.POST("/login/totp/:languageTag", sessionMW, i18nMW, h.PostLoginTOTP)
	router.GET("/login/webauthn", sessionMW, i18nMW, h.LoginWebAuthn)
	router.GET("/login/webauthn/:languageTag", sessionMW, i18nMW, h.LoginWebAuthn)
	router.GET("/login/webauthn/begin", sessionMW, i18nMW, core.LoginWebAuthnBegin(h.deps.Auth()))
	router.GET("/login/webauthn/begin/:languageTag", sessionMW, i18nMW, core.LoginWebAuthnBegin(h.deps.Auth()))
	router.POST("/login/webauthn/finish", sessionMW, i18nMW, core.LoginWebAuthnFinish(h.deps.Auth()))
	router.POST("/login/webauthn/finish/:languageTag", sessionMW, i18nMW, core.LoginWebAuthnFinish(h.deps.Auth()))
	router.GET("/login/mfa", sessionMW, i18nMW, h.LoginMFASelect)
	router.GET("/login/mfa/:languageTag", sessionMW, i18nMW, h.LoginMFASelect)
	router.GET("/login/recovery", sessionMW, i18nMW, h.LoginRecovery)
	router.GET("/login/recovery/:languageTag", sessionMW, i18nMW, h.LoginRecovery)
	router.POST("/login/recovery", sessionMW, i18nMW, h.PostLoginRecovery)
	router.POST("/login/recovery/:languageTag", sessionMW, i18nMW, h.PostLoginRecovery)

	// Auth protected routes
	authGroup := router.Group(definitions.MFARoot, sessionMW, h.AuthMiddleware(), i18nMW)
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

	router.GET("/logged_out", sessionMW, i18nMW, h.LoggedOut)
	router.GET("/logged_out/:languageTag", sessionMW, i18nMW, h.LoggedOut)
}

// AuthMiddleware ensures the user is logged in.
func (h *FrontendHandler) AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		_, err := util.GetSessionValue[string](session, definitions.CookieAccount)

		if err != nil {
			ctx.Redirect(http.StatusFound, h.getLoginURL(ctx)+"?return_to="+ctx.Request.URL.Path)
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
	session := sessions.Default(ctx)
	lang := "en"

	if l, err := util.GetSessionValue[string](session, definitions.CookieLang); err == nil {
		lang = l
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

	username, _ := util.GetSessionValue[string](session, definitions.CookieAccount)

	return gin.H{
		"LanguageTag":         lang,
		"LanguageCurrentName": currentName,
		"LanguagePassive":     frontend.CreateLanguagePassive(ctx, cfg, path, langManager.GetTags(), currentName),
		"Username":            username,
		"ConfirmTitle":        frontend.GetLocalized(ctx, cfg, nil, "Confirmation"),
		"ConfirmYes":          frontend.GetLocalized(ctx, cfg, nil, "Yes"),
		"ConfirmNo":           frontend.GetLocalized(ctx, cfg, nil, "Cancel"),
	}
}

// Login renders the modern login page.
func (h *FrontendHandler) Login(ctx *gin.Context) {
	session := sessions.Default(ctx)
	if _, err := util.GetSessionValue[string](session, definitions.CookieAccount); err == nil {
		returnTo := ctx.Query("return_to")
		if returnTo == "" {
			returnTo = definitions.MFARoot + "/register/home"
		}

		ctx.Redirect(http.StatusFound, returnTo)

		return
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "IdP Login page request",
	)

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
	data["UsernameLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Username")
	data["UsernamePlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your username or email address")
	data["PasswordLabel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
	data["PasswordPlaceholder"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your password")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	data["CSRFToken"] = "TODO_CSRF"
	data["PostLoginEndpoint"] = ctx.Request.URL.Path
	returnTo := ctx.Query("return_to")
	data["ReturnTo"] = returnTo
	protocol := ctx.Query("protocol")
	data["Protocol"] = protocol
	data["HaveError"] = false

	var oidcCID, samlEntityID string
	if returnTo != "" {
		if u, err := url.Parse(returnTo); err == nil {
			oidcCID = u.Query().Get("client_id")
			samlEntityID = u.Query().Get("entity_id")

			if samlEntityID == "" && strings.HasPrefix(u.Path, "/saml/sso") {
				samlEntityID = definitions.ProtoSAML
			}
		}
	}

	if protocol == definitions.ProtoSAML && samlEntityID == "" {
		samlEntityID = definitions.ProtoSAML
	}

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

// PostLogin handles the login submission.
func (h *FrontendHandler) PostLogin(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_login")
	defer sp.End()

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgIdp,
		definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey),
		definitions.LogKeyMsg, "IdP Login attempt",
		"username", ctx.PostForm("username"),
	)

	username := ctx.PostForm("username")
	password := ctx.PostForm("password")
	returnTo := ctx.PostForm("return_to")
	protocolParam := ctx.PostForm("protocol")
	rememberMe := ctx.PostForm("remember_me") == "on"

	// Try to extract client_id or saml_entity_id from returnTo
	var oidcCID, samlEntityID string
	if returnTo != "" {
		if u, err := url.Parse(returnTo); err == nil {
			oidcCID = u.Query().Get("client_id")
			samlEntityID = u.Query().Get("entity_id") // Assuming entity_id for SAML

			if samlEntityID == "" && strings.HasPrefix(u.Path, "/saml/sso") {
				// It's a SAML request, even if we don't have the entity_id yet
				if protocolParam == "" {
					protocolParam = definitions.ProtoSAML
				}
			}
		}
	}

	// If we have an explicit protocol parameter, respect it
	if protocolParam == definitions.ProtoSAML && samlEntityID == "" {
		// We need some non-empty string to trigger ProtoSAML in Authenticate for now,
		// or we modify Authenticate to take protocol as well.
		// Let's use a special marker if we don't know the entity ID yet.
		samlEntityID = "urn:nauthilus:saml:unknown"
	}

	idpInstance := idp.NewNauthilusIdP(h.deps)

	var rememberMeTTL int

	if rememberMe {
		var ttl time.Duration

		if oidcCID != "" {
			if client, ok := idpInstance.FindClient(oidcCID); ok {
				ttl = client.RememberMeTTL
			}
		} else if samlEntityID != "" {
			if sp, ok := idpInstance.FindSAMLServiceProvider(samlEntityID); ok {
				ttl = sp.RememberMeTTL
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
					session := sessions.Default(ctx)
					session.Set(definitions.CookieUsername, username)
					session.Set(definitions.CookieUniqueUserID, user.Id)
					session.Set(definitions.CookieAuthResult, uint8(definitions.AuthResultFail))
					session.Set(definitions.CookieProtocol, protocol)

					if rememberMeTTL > 0 {
						session.Set(definitions.CookieRememberTTL, rememberMeTTL)
					}

					session.Save()

					// If user has only one MFA option, redirect directly to it
					if redirectURL, ok := h.getMFARedirectURL(ctx, user, returnTo, protocolParam); ok {
						ctx.Redirect(http.StatusFound, redirectURL)

						return
					}

					redirectURL := h.appendQueryString("/login/mfa", "return_to="+url.QueryEscape(returnTo))
					if protocolParam != "" {
						redirectURL = h.appendQueryString(redirectURL, "protocol="+url.QueryEscape(protocolParam))
					}

					ctx.Redirect(http.StatusFound, redirectURL)

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
		data["WebAuthnLoginURL"] = h.getMFAURL(ctx, "webauthn")

		data["CSRFToken"] = "TODO_CSRF"
		data["PostLoginEndpoint"] = ctx.Request.URL.Path
		data["ReturnTo"] = returnTo
		data["HaveError"] = true
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid login or password")

		ctx.HTML(http.StatusOK, "idp_login.html", data)

		return
	}

	// Check if user has MFA
	if h.hasTOTP(user) || h.hasWebAuthn(ctx, user, protocol) {
		session := sessions.Default(ctx)
		session.Set(definitions.CookieUsername, username)
		session.Set(definitions.CookieUniqueUserID, user.Id)
		session.Set(definitions.CookieAuthResult, uint8(definitions.AuthResultOK))
		session.Set(definitions.CookieProtocol, protocol)

		if rememberMeTTL > 0 {
			session.Set(definitions.CookieRememberTTL, rememberMeTTL)
		}

		session.Save()

		// If user has only one MFA option, redirect directly to it
		if redirectURL, ok := h.getMFARedirectURL(ctx, user, returnTo, protocolParam); ok {
			ctx.Redirect(http.StatusFound, redirectURL)

			return
		}

		// If user has multiple MFA options OR if we want to show the selection page anyway
		// Requirement says: "If a person has configured one or more MFA options, there should be an intermediate page..."
		redirectURL := h.appendQueryString("/login/mfa", "return_to="+url.QueryEscape(returnTo))
		if protocolParam != "" {
			redirectURL = h.appendQueryString(redirectURL, "protocol="+url.QueryEscape(protocolParam))
		}

		ctx.Redirect(http.StatusFound, redirectURL)

		return
	}

	session := sessions.Default(ctx)
	session.Set(definitions.CookieAccount, user.Name)
	session.Set(definitions.CookieUniqueUserID, user.Id)
	session.Set(definitions.CookieDisplayName, user.DisplayName)
	session.Set(definitions.CookieSubject, user.Id)
	session.Set(definitions.CookieProtocol, protocol)

	if rememberMeTTL > 0 {
		session.Options(sessions.Options{
			MaxAge: rememberMeTTL,
			Path:   "/",
		})
	}

	session.Save()

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "success").Inc()

	if returnTo != "" {
		ctx.Redirect(http.StatusFound, returnTo)

		return
	}

	ctx.Redirect(http.StatusFound, definitions.MFARoot+"/register/home")
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

	session := sessions.Default(ctx)

	if provider == nil {
		authDeps := h.deps.Auth()
		state := core.NewAuthStateWithSetupWithDeps(ctx, authDeps)
		if state == nil {
			return false
		}

		resolvedProtocol := protocolName
		if resolvedProtocol == "" && session != nil {
			resolvedProtocol, _ = util.GetSessionValue[string](session, definitions.CookieProtocol)
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

	h.resolveWebAuthnUser(ctx, session, data, provider)

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
func (h *FrontendHandler) LoginMFASelect(ctx *gin.Context) {
	session := sessions.Default(ctx)
	username, err := util.GetSessionValue[string](session, definitions.CookieUsername)

	if err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	returnTo := ctx.Query("return_to")
	protocol := ctx.Query("protocol")

	// Get user to check available MFA methods
	idpInstance := idp.NewNauthilusIdP(h.deps)
	user, err := idpInstance.GetUserByUsername(ctx, username, "", "")
	if err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	// If user has only one MFA option, redirect directly to it
	if redirectURL, ok := h.getMFARedirectURL(ctx, user, returnTo, protocol); ok {
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

	data["HaveTOTP"] = h.hasTOTP(user)
	data["HaveWebAuthn"] = h.hasWebAuthn(ctx, user, protocol)
	data["HaveRecoveryCodes"] = h.hasRecoveryCodes(user)

	data["QueryString"] = h.appendQueryString("", ctx.Request.URL.RawQuery)
	data["ReturnTo"] = returnTo
	data["Protocol"] = protocol

	// Check for last used MFA method
	lastMFA, _ := ctx.Cookie("last_mfa_method")
	data["LastMFAMethod"] = lastMFA

	ctx.HTML(http.StatusOK, "idp_mfa_select.html", data)
}

// LoginRecovery renders the recovery code verification page during login.
func (h *FrontendHandler) LoginRecovery(ctx *gin.Context) {
	session := sessions.Default(ctx)
	if _, err := util.GetSessionValue[string](session, definitions.CookieUsername); err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["RecoveryVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter one of your recovery codes")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")

	data["CSRFToken"] = "TODO_CSRF"
	data["PostRecoveryVerifyEndpoint"] = ctx.Request.URL.Path
	data["ReturnTo"] = ctx.Query("return_to")
	data["Protocol"] = ctx.Query("protocol")
	data["QueryString"] = h.appendQueryString("", ctx.Request.URL.RawQuery)
	data["HaveError"] = false

	ctx.HTML(http.StatusOK, "idp_recovery_login.html", data)
}

// PostLoginRecovery handles the recovery code verification during login.
func (h *FrontendHandler) PostLoginRecovery(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_login_recovery")
	defer sp.End()

	session := sessions.Default(ctx)
	username, errU := util.GetSessionValue[string](session, definitions.CookieUsername)
	_, errA := util.GetSessionValue[uint8](session, definitions.CookieAuthResult)
	code := ctx.PostForm("code")
	returnTo := ctx.PostForm("return_to")
	protocolParam := ctx.PostForm("protocol")

	if errU != nil || errA != nil || code == "" {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	var oidcCID, samlEntityID string
	if returnTo != "" {
		if u, err := url.Parse(returnTo); err == nil {
			oidcCID = u.Query().Get("client_id")
			samlEntityID = u.Query().Get("entity_id")

			if samlEntityID == "" && strings.HasPrefix(u.Path, "/saml/sso") {
				samlEntityID = definitions.ProtoSAML
			}
		}
	}

	if protocolParam == definitions.ProtoSAML && samlEntityID == "" {
		samlEntityID = definitions.ProtoSAML
	}

	idpInstance := idp.NewNauthilusIdP(h.deps)
	user, err := idpInstance.GetUserByUsername(ctx, username, oidcCID, samlEntityID)

	if err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	// Verify Recovery Code
	sourceBackend, err := util.GetSessionValue[uint8](session, definitions.CookieUserBackend)
	if err != nil {
		sourceBackend = uint8(definitions.BackendLDAP)
	}

	success, err := h.mfa.UseRecoveryCode(ctx, username, code, sourceBackend)
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

		data["CSRFToken"] = "TODO_CSRF"
		data["PostRecoveryVerifyEndpoint"] = ctx.Request.URL.Path
		data["ReturnTo"] = returnTo
		data["Protocol"] = protocolParam
		data["QueryString"] = h.appendQueryString("", "return_to="+url.QueryEscape(returnTo)+"&protocol="+url.QueryEscape(protocolParam))
		data["HaveError"] = true
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid recovery code")

		ctx.HTML(http.StatusOK, "idp_recovery_login.html", data)

		return
	}

	// MFA Success
	h.setLastMFAMethod(ctx, "recovery")
	h.finalizeMFALogin(ctx, user, returnTo)
}

func (h *FrontendHandler) setLastMFAMethod(ctx *gin.Context, method string) {
	ctx.SetCookie("last_mfa_method", method, 365*24*60*60, "/", "", true, true)
}

func (h *FrontendHandler) getMFARedirectURL(ctx *gin.Context, user *backend.User, returnTo string, protocolParam string) (string, bool) {
	haveTOTP := h.hasTOTP(user)
	haveWebAuthn := h.hasWebAuthn(ctx, user, protocolParam)
	haveRecovery := h.hasRecoveryCodes(user)

	count := 0

	if haveTOTP {
		count++
	}

	if haveWebAuthn {
		count++
	}

	if count != 0 && haveRecovery {
		count++
	}

	// If more than one is present, we need selection
	if count > 1 {
		return "", false
	}

	var target string

	if haveTOTP {
		target = "/login/totp"
	} else if haveWebAuthn {
		target = "/login/webauthn"
	} else if haveRecovery {
		target = "/login/recovery"
	} else {
		// No MFA methods available
		return "", false
	}

	redirectURL := h.appendQueryString(target, "return_to="+url.QueryEscape(returnTo))
	if protocolParam != "" {
		redirectURL = h.appendQueryString(redirectURL, "protocol="+url.QueryEscape(protocolParam))
	}

	return redirectURL, true
}

func (h *FrontendHandler) finalizeMFALogin(ctx *gin.Context, user *backend.User, returnTo string) {
	session := sessions.Default(ctx)
	protocol, _ := util.GetSessionValue[string](session, definitions.CookieProtocol)
	rememberMeTTL, _ := util.GetSessionValue[int](session, definitions.CookieRememberTTL)

	session.Set(definitions.CookieAccount, user.Name)
	session.Set(definitions.CookieUniqueUserID, user.Id)
	session.Set(definitions.CookieDisplayName, user.DisplayName)
	session.Set(definitions.CookieSubject, user.Id)
	session.Set(definitions.CookieProtocol, protocol)

	if rememberMeTTL > 0 {
		session.Options(sessions.Options{
			MaxAge: rememberMeTTL,
			Path:   "/",
		})
	}

	session.Save()

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "success").Inc()

	if returnTo != "" {
		ctx.Redirect(http.StatusFound, returnTo)

		return
	}

	ctx.Redirect(http.StatusFound, definitions.MFARoot+"/register/home")
}

// LoginWebAuthn renders the WebAuthn verification page during login.
func (h *FrontendHandler) LoginWebAuthn(ctx *gin.Context) {
	session := sessions.Default(ctx)
	username, err := util.GetSessionValue[string](session, definitions.CookieUsername)

	if err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["WebAuthnVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please use your security key to login")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")

	data["CSRFToken"] = "TODO_CSRF"
	data["ReturnTo"] = ctx.Query("return_to")
	data["WebAuthnBeginEndpoint"] = h.getMFAURL(ctx, "webauthn/begin")
	data["WebAuthnFinishEndpoint"] = h.getMFAURL(ctx, "webauthn/finish")
	data["BackURL"] = h.getLoginURL(ctx)

	// JS Localizations
	data["JSInteractWithKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please interact with your security key...")
	data["JSCompletingLogin"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Completing login...")
	data["JSUnknownError"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An unknown error occurred")
	data["Username"] = username

	ctx.HTML(http.StatusOK, "idp_webauthn_verify.html", data)
}

// LoginTOTP renders the TOTP verification page during login.
func (h *FrontendHandler) LoginTOTP(ctx *gin.Context) {
	session := sessions.Default(ctx)
	if _, err := util.GetSessionValue[string](session, definitions.CookieUsername); err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "2FA Verification")
	data["TOTPVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your 2FA code")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["Back"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Back")

	data["CSRFToken"] = "TODO_CSRF"
	data["PostTOTPVerifyEndpoint"] = ctx.Request.URL.Path
	data["ReturnTo"] = ctx.Query("return_to")
	data["Protocol"] = ctx.Query("protocol")
	data["BackURL"] = h.getLoginURL(ctx)
	data["HaveError"] = false

	ctx.HTML(http.StatusOK, "idp_totp_verify.html", data)
}

// PostLoginTOTP handles the TOTP verification during login.
func (h *FrontendHandler) PostLoginTOTP(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_login_totp")
	defer sp.End()

	session := sessions.Default(ctx)
	username, errU := util.GetSessionValue[string](session, definitions.CookieUsername)
	authResult, errA := util.GetSessionValue[uint8](session, definitions.CookieAuthResult)
	code := ctx.PostForm("code")
	returnTo := ctx.PostForm("return_to")
	protocolParam := ctx.PostForm("protocol")

	if errU != nil || errA != nil || code == "" {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	var oidcCID, samlEntityID string
	if returnTo != "" {
		if u, err := url.Parse(returnTo); err == nil {
			oidcCID = u.Query().Get("client_id")
			samlEntityID = u.Query().Get("entity_id")

			if samlEntityID == "" && strings.HasPrefix(u.Path, "/saml/sso") {
				samlEntityID = definitions.ProtoSAML
			}
		}
	}

	if protocolParam == definitions.ProtoSAML && samlEntityID == "" {
		samlEntityID = definitions.ProtoSAML
	}

	idpInstance := idp.NewNauthilusIdP(h.deps)
	user, err := idpInstance.GetUserByUsername(ctx, username, oidcCID, samlEntityID)

	if err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	// Verify TOTP
	authDeps := h.deps.Auth()
	state := core.NewAuthStateWithSetupWithDeps(ctx, authDeps)
	if state == nil {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	auth := state.(*core.AuthState)
	auth.SetUsername(username)
	auth.SetOIDCCID(oidcCID)
	auth.SetSAMLEntityID(samlEntityID)

	// We need to load user into auth to get TOTP secret and recovery codes
	// GetUserByUsername already did some of this, but TotpValidation expects secrets in AuthState
	auth.ReplaceAllAttributes(user.Attributes)
	auth.SetTOTPSecretField(user.TOTPSecretField)
	auth.SetTOTPRecoveryField(user.TOTPRecoveryField)

	err = core.TotpValidation(ctx, auth, code, authDeps)

	if err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("login", "totp", "fail").Inc()

		data := h.basePageData(ctx)
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
		data["TOTPVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your 2FA code")
		data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
		data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

		data["CSRFToken"] = "TODO_CSRF"
		data["PostTOTPVerifyEndpoint"] = ctx.Request.URL.Path
		data["ReturnTo"] = returnTo
		data["Protocol"] = protocolParam
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
		data["WebAuthnLoginURL"] = h.getMFAURL(ctx, "webauthn")

		data["CSRFToken"] = "TODO_CSRF"
		lang := ctx.Param("languageTag")
		if lang != "" {
			data["PostLoginEndpoint"] = "/login/" + lang
		} else {
			data["PostLoginEndpoint"] = "/login"
		}
		data["ReturnTo"] = returnTo
		data["HaveError"] = true
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid login or password")

		// Important: clean up session so they start over
		session.Delete(definitions.CookieUsername)
		session.Delete(definitions.CookieAuthResult)
		session.Save()

		ctx.HTML(http.StatusOK, "idp_login.html", data)

		return
	}

	// All OK!
	h.setLastMFAMethod(ctx, "totp")
	h.finalizeMFALogin(ctx, user, returnTo)
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

	session := sessions.Default(ctx)
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

	// Sync session if it exists
	if _, err := util.GetSessionValue[string](session, definitions.CookieAccount); err == nil {
		session.Set(definitions.CookieHaveTOTP, userData.HaveTOTP)
		_ = session.Save()
	}

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

	ctx.HTML(http.StatusOK, "idp_2fa_home.html", data)
}

// RegisterTOTP renders the TOTP registration page.
func (h *FrontendHandler) RegisterTOTP(ctx *gin.Context) {
	session := sessions.Default(ctx)

	haveTOTP, _ := util.GetSessionValue[bool](session, definitions.CookieHaveTOTP)
	if haveTOTP {
		ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
		ctx.Status(http.StatusFound)

		return
	}

	account, err := util.GetSessionValue[string](session, definitions.CookieAccount)
	if err != nil {
		ctx.Redirect(http.StatusFound, h.getLoginURL(ctx))

		return
	}

	secret, qrCodeURL, err := h.mfa.GenerateTOTPSecret(ctx, account)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to generate TOTP key")

		return
	}

	session.Set(definitions.CookieTOTPSecret, secret)
	session.Save()

	data := h.basePageData(ctx)
	data["QRCode"] = qrCodeURL
	data["Secret"] = secret
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register TOTP")
	data["TOTPMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please scan and verify the following QR code")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	ctx.HTML(http.StatusOK, "idp_totp_register.html", data)
}

// PostRegisterTOTP handles the TOTP registration submission.
func (h *FrontendHandler) PostRegisterTOTP(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_register_totp")
	defer sp.End()

	session := sessions.Default(ctx)
	secret, errS := util.GetSessionValue[string](session, definitions.CookieTOTPSecret)
	code := ctx.PostForm("code")
	username, errU := util.GetSessionValue[string](session, definitions.CookieAccount)

	if errS != nil || errU != nil || code == "" {
		h.renderErrorModal(ctx, "Invalid request", http.StatusBadRequest)

		return
	}

	sourceBackend, err := util.GetSessionValue[uint8](session, definitions.CookieUserBackend)
	if err != nil {
		sourceBackend = uint8(definitions.BackendLDAP)
	}

	if err := h.mfa.VerifyAndSaveTOTP(ctx, username, secret, code, sourceBackend); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "totp", "fail").Inc()
		h.renderErrorModal(ctx, err.Error(), http.StatusBadRequest)

		return
	}

	auth := core.NewAuthStateFromContextWithDeps(ctx, h.deps.Auth())
	auth.PurgeCacheFor(username)

	// Success!
	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "totp", "success").Inc()
	session.Set(definitions.CookieHaveTOTP, true)
	session.Delete(definitions.CookieTOTPSecret)
	session.Save()

	ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
	ctx.Status(http.StatusOK)
}

// PostGenerateRecoveryCodes handles generating new recovery codes.
func (h *FrontendHandler) PostGenerateRecoveryCodes(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_generate_recovery_codes")
	defer sp.End()

	session := sessions.Default(ctx)
	username, errU := util.GetSessionValue[string](session, definitions.CookieAccount)

	if errU != nil {
		h.renderErrorModal(ctx, "Invalid request", http.StatusBadRequest)

		return
	}

	sourceBackend, err := util.GetSessionValue[uint8](session, definitions.CookieUserBackend)
	if err != nil {
		sourceBackend = uint8(definitions.BackendLDAP)
	}

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.renderErrorModal(ctx, "Failed to fetch user data", http.StatusInternalServerError)

		return
	}

	if !userData.HaveTOTP && !userData.HaveWebAuthn {
		h.renderErrorModal(ctx, "At least one MFA method (TOTP or WebAuthn) must be active to generate recovery codes", http.StatusBadRequest)

		return
	}

	codes, err := h.mfa.GenerateRecoveryCodes(ctx, username, sourceBackend)
	if err != nil {
		sp.RecordError(err)
		h.renderErrorModal(ctx, "Failed to generate recovery codes: "+err.Error(), http.StatusInternalServerError)

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

	session := sessions.Default(ctx)
	username, errU := util.GetSessionValue[string](session, definitions.CookieAccount)
	if errU != nil {
		h.renderErrorModal(ctx, "Invalid request", http.StatusBadRequest)

		return
	}

	sourceBackend, err := util.GetSessionValue[uint8](session, definitions.CookieUserBackend)
	if err != nil {
		sourceBackend = uint8(definitions.BackendLDAP)
	}

	if err := h.mfa.DeleteTOTP(ctx, username, sourceBackend); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "fail").Inc()
		h.renderErrorModal(ctx, "Failed to delete TOTP secret: "+err.Error(), http.StatusInternalServerError)

		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "success").Inc()
	session.Set(definitions.CookieHaveTOTP, false)
	session.Save()

	state := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth())
	if state == nil {
		h.renderErrorModal(ctx, "Failed to initialize auth state", http.StatusInternalServerError)

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

	session := sessions.Default(ctx)
	userID, errU := util.GetSessionValue[string](session, definitions.CookieUniqueUserID)
	username, errA := util.GetSessionValue[string](session, definitions.CookieAccount)

	if errU != nil || errA != nil {
		h.renderErrorModal(ctx, "Invalid request", http.StatusBadRequest)

		return
	}

	// First, clear the Redis cache
	key := h.deps.Cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + userID
	if err := h.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), key).Err(); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "fail").Inc()
		h.renderErrorModal(ctx, "Failed to delete WebAuthn from Redis: "+err.Error(), http.StatusInternalServerError)

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
	session := sessions.Default(ctx)

	if uniqueUserID, err := util.GetSessionValue[string](session, definitions.CookieUniqueUserID); err == nil {
		user, err := backend.GetWebAuthnFromRedis(ctx.Request.Context(), h.deps.Cfg, h.deps.Logger, h.deps.Redis, uniqueUserID)

		if err == nil && user != nil && len(user.WebAuthnCredentials()) > 0 {
			ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
			ctx.Status(http.StatusFound)

			return
		}
	} else {
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

func (h *FrontendHandler) renderErrorModal(ctx *gin.Context, msg string, code int) {
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

	ctx.HTML(http.StatusOK, "idp_2fa_webauthn_devices.html", data)
}

// DeleteWebAuthnDevice removes a specific WebAuthn credential for the user.
func (h *FrontendHandler) DeleteWebAuthnDevice(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.delete_webauthn_device")
	defer sp.End()

	id := ctx.Param("id")
	if id == "" {
		h.renderErrorModal(ctx, "Missing device ID", http.StatusBadRequest)

		return
	}

	decodedID, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		h.renderErrorModal(ctx, "Invalid device ID", http.StatusBadRequest)

		return
	}

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.renderErrorModal(ctx, "Not logged in", http.StatusUnauthorized)

		return
	}

	if userData.WebAuthnUser == nil {
		h.renderErrorModal(ctx, "User not found", http.StatusNotFound)

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
		h.renderErrorModal(ctx, "Credential not found", http.StatusNotFound)

		return
	}

	// Delete from backend via AuthState
	if err := userData.AuthState.DeleteWebAuthnCredential(targetCred); err != nil {
		sp.RecordError(err)
		h.renderErrorModal(ctx, "Failed to delete credential: "+err.Error(), http.StatusInternalServerError)

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
		h.renderErrorModal(ctx, "Missing device ID", http.StatusBadRequest)

		return
	}

	name := strings.TrimSpace(ctx.PostForm("name"))
	if name == "" {
		h.renderErrorModal(ctx, "Missing device name", http.StatusBadRequest)

		return
	}

	decodedID, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		h.renderErrorModal(ctx, "Invalid device ID", http.StatusBadRequest)

		return
	}

	userData, err := h.GetUserBackendData(ctx)
	if err != nil || userData == nil {
		h.renderErrorModal(ctx, "Not logged in", http.StatusUnauthorized)

		return
	}

	if userData.WebAuthnUser == nil {
		h.renderErrorModal(ctx, "User not found", http.StatusNotFound)

		return
	}

	var targetIndex int
	found := false
	for i := range userData.WebAuthnUser.Credentials {
		if bytes.Equal(userData.WebAuthnUser.Credentials[i].ID, decodedID) {
			targetIndex = i
			found = true
			break
		}
	}

	if !found {
		h.renderErrorModal(ctx, "Credential not found", http.StatusNotFound)

		return
	}

	oldCredential := userData.WebAuthnUser.Credentials[targetIndex]
	newCredential := oldCredential
	newCredential.Name = name

	if err := userData.AuthState.UpdateWebAuthnCredential(&oldCredential, &newCredential); err != nil {
		sp.RecordError(err)
		h.renderErrorModal(ctx, "Failed to update credential: "+err.Error(), http.StatusInternalServerError)

		return
	}

	userData.WebAuthnUser.Credentials[targetIndex].Name = name
	_ = backend.SaveWebAuthnToRedis(ctx.Request.Context(), h.deps.Logger, h.deps.Cfg, h.deps.Redis, userData.WebAuthnUser, h.deps.Cfg.GetServer().GetTimeouts().GetRedisWrite())

	userData.AuthState.PurgeCacheFor(userData.Username)

	ctx.Header("HX-Redirect", definitions.MFARoot+"/webauthn/devices")
	ctx.Status(http.StatusOK)
}
