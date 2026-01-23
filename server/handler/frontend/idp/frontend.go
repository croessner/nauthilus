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
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/middleware/i18n"
	"github.com/croessner/nauthilus/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// FrontendHandler handles general IdP frontend pages like login and consent.
type FrontendHandler struct {
	deps   *deps.Deps
	tracer monittrace.Tracer
}

// NewFrontendHandler creates a new FrontendHandler.
func NewFrontendHandler(d *deps.Deps) *FrontendHandler {
	return &FrontendHandler{
		deps:   d,
		tracer: monittrace.New("nauthilus/idp/frontend"),
	}
}

// Register adds frontend routes to the router.
func (h *FrontendHandler) Register(router gin.IRouter) {
	i18nMW := i18n.WithLanguage(h.deps.Cfg, h.deps.Logger)

	router.GET("/login", i18nMW, h.Login)
	router.POST("/login", i18nMW, h.PostLogin)
	router.GET("/login/totp", i18nMW, h.LoginTOTP)
	router.POST("/login/totp", i18nMW, h.PostLoginTOTP)
	router.GET("/login/webauthn", i18nMW, h.LoginWebAuthn)
	router.GET("/login/webauthn/begin", i18nMW, core.LoginWebAuthnBegin(h.deps.Auth()))
	router.POST("/login/webauthn/finish", i18nMW, core.LoginWebAuthnFinish(h.deps.Auth()))

	// Auth protected routes
	authGroup := router.Group("/", h.AuthMiddleware(), i18nMW)
	authGroup.GET("/2fa/v1/register/home", h.TwoFAHome)
	authGroup.GET("/2fa/v1/totp/register", h.RegisterTOTP)
	authGroup.POST("/2fa/v1/totp/register", h.PostRegisterTOTP)
	authGroup.DELETE("/2fa/v1/totp", h.DeleteTOTP)

	authGroup.GET("/2fa/v1/webauthn/register", h.RegisterWebAuthn)
	authGroup.GET("/2fa/v1/webauthn/register/begin", core.BeginRegistration(h.deps.Auth()))
	authGroup.POST("/2fa/v1/webauthn/register/finish", core.FinishRegistration(h.deps.Auth()))
	authGroup.DELETE("/2fa/v1/webauthn", h.DeleteWebAuthn)

	authGroup.POST("/2fa/v1/recovery/generate", h.PostGenerateRecoveryCodes)
}

// AuthMiddleware ensures the user is logged in.
func (h *FrontendHandler) AuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		session := sessions.Default(ctx)
		account := session.Get(definitions.CookieAccount)

		if account == nil {
			ctx.Redirect(http.StatusFound, "/login?return_to="+ctx.Request.URL.Path)
			ctx.Abort()

			return
		}

		ctx.Next()
	}
}

func (h *FrontendHandler) basePageData(ctx *gin.Context) gin.H {
	return BasePageData(ctx, h.deps.Cfg)
}

// BasePageData returns the common data for all IdP frontend pages.
func BasePageData(ctx *gin.Context, cfg config.File) gin.H {
	session := sessions.Default(ctx)
	lang := "en"

	if l := session.Get(definitions.CookieLang); l != nil {
		lang = l.(string)
	}

	tag := language.Make(lang)
	currentName := cases.Title(tag, cases.NoLower).String(display.Self.Name(tag))

	path := ctx.Request.URL.Path
	// Remove language tag from path for CreateLanguagePassive
	parts := strings.Split(path, "/")

	if len(parts) > 1 {
		lastPart := parts[len(parts)-1]
		for _, t := range config.DefaultLanguageTags {
			b, _ := t.Base()
			if b.String() == lastPart {
				path = strings.Join(parts[:len(parts)-1], "/")

				break
			}
		}
	}

	return gin.H{
		"LanguageTag":         lang,
		"LanguageCurrentName": currentName,
		"LanguagePassive":     frontend.CreateLanguagePassive(ctx, cfg, path, config.DefaultLanguageTags, currentName),
		"Username":            session.Get(definitions.CookieAccount),
	}
}

// Login renders the modern login page.
func (h *FrontendHandler) Login(ctx *gin.Context) {
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
	data["Login"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
	data["Password"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
	data["LoginWithWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login with WebAuthn")
	data["Or"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or")

	data["CSRFToken"] = "TODO_CSRF"
	data["PostLoginEndpoint"] = "/login"
	data["ReturnTo"] = ctx.Query("return_to")
	data["HaveError"] = false

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

	// Try to extract client_id or saml_entity_id from returnTo
	var oidcCID, samlEntityID string
	if returnTo != "" {
		if u, err := url.Parse(returnTo); err == nil {
			oidcCID = u.Query().Get("client_id")
			samlEntityID = u.Query().Get("entity_id") // Assuming entity_id for SAML
		}
	}

	sp.SetAttributes(
		attribute.String("username", username),
		attribute.String("oidc_cid", oidcCID),
		attribute.String("saml_entity_id", samlEntityID),
	)

	// Try to get user to see if MFA is present
	idpInstance := idp.NewNauthilusIdP(h.deps)
	user, err := idpInstance.Authenticate(ctx, username, password, oidcCID, samlEntityID)

	if err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "fail").Inc()

		// Check for Delayed Response
		if idpInstance.IsDelayedResponse(oidcCID, samlEntityID) {
			if user, _ := idpInstance.GetUserByUsername(ctx, username, oidcCID, samlEntityID); user != nil {
				if h.hasTOTP(user) || h.hasWebAuthn(user) {
					session := sessions.Default(ctx)
					session.Set(definitions.CookieUsername, username)
					session.Set(definitions.CookieAuthResult, uint8(definitions.AuthResultFail))
					session.Save()

					if h.hasWebAuthn(user) {
						ctx.Redirect(http.StatusFound, "/login/webauthn?return_to="+url.QueryEscape(returnTo))
					} else {
						ctx.Redirect(http.StatusFound, "/login/totp?return_to="+url.QueryEscape(returnTo))
					}

					return
				}
			}
		}

		data := h.basePageData(ctx)
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
		data["Login"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
		data["Password"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
		data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
		data["LoginWithWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login with WebAuthn")
		data["Or"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or")

		data["CSRFToken"] = "TODO_CSRF"
		data["PostLoginEndpoint"] = "/login"
		data["ReturnTo"] = returnTo
		data["HaveError"] = true
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid login or password")

		ctx.HTML(http.StatusOK, "idp_login.html", data)

		return
	}

	// Check if user has MFA
	if h.hasTOTP(user) || h.hasWebAuthn(user) {
		session := sessions.Default(ctx)
		session.Set(definitions.CookieUsername, username)
		session.Set(definitions.CookieAuthResult, uint8(definitions.AuthResultOK))
		session.Save()

		if h.hasWebAuthn(user) {
			ctx.Redirect(http.StatusFound, "/login/webauthn?return_to="+url.QueryEscape(returnTo))
		} else {
			ctx.Redirect(http.StatusFound, "/login/totp?return_to="+url.QueryEscape(returnTo))
		}

		return
	}

	session := sessions.Default(ctx)
	session.Set(definitions.CookieAccount, user.Name)
	session.Set(definitions.CookieUniqueUserID, user.Id)
	session.Set(definitions.CookieDisplayName, user.DisplayName)
	session.Set(definitions.CookieSubject, user.Id)
	session.Save()

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "success").Inc()

	if returnTo != "" {
		ctx.Redirect(http.StatusFound, returnTo)

		return
	}

	ctx.Redirect(http.StatusFound, "/")
}

func (h *FrontendHandler) hasTOTP(user *backend.User) bool {
	var totpField string
	if protocols := h.deps.Cfg.GetLDAP().GetSearch(); len(protocols) > 0 {
		totpField = protocols[0].GetTotpSecretField()
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

func (h *FrontendHandler) hasWebAuthn(user *backend.User) bool {
	uniqueUserID := user.Id
	ctx := context.Background()
	userWA, err := backend.GetWebAuthnFromRedis(ctx, h.deps.Cfg, h.deps.Logger, h.deps.Redis, uniqueUserID)

	return err == nil && userWA != nil && len(userWA.WebAuthnCredentials()) > 0
}

// LoginWebAuthn renders the WebAuthn verification page during login.
func (h *FrontendHandler) LoginWebAuthn(ctx *gin.Context) {
	session := sessions.Default(ctx)
	username := session.Get(definitions.CookieUsername)

	if username == nil {
		ctx.Redirect(http.StatusFound, "/login")

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
	data["WebAuthnVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please use your security key to login")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	data["CSRFToken"] = "TODO_CSRF"
	data["ReturnTo"] = ctx.Query("return_to")

	// JS Localizations
	data["JSInteractWithKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please interact with your security key...")
	data["JSCompletingLogin"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Completing login...")
	data["JSUnknownError"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An unknown error occurred")

	ctx.HTML(http.StatusOK, "idp_webauthn_verify.html", data)
}

// LoginTOTP renders the TOTP verification page during login.
func (h *FrontendHandler) LoginTOTP(ctx *gin.Context) {
	session := sessions.Default(ctx)
	username := session.Get(definitions.CookieUsername)

	if username == nil {
		ctx.Redirect(http.StatusFound, "/login")

		return
	}

	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
	data["TOTPVerifyMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your 2FA code")
	data["Code"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP Code")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	data["CSRFToken"] = "TODO_CSRF"
	data["PostTOTPVerifyEndpoint"] = "/login/totp"
	data["ReturnTo"] = ctx.Query("return_to")
	data["HaveError"] = false

	ctx.HTML(http.StatusOK, "idp_totp_verify.html", data)
}

// PostLoginTOTP handles the TOTP verification during login.
func (h *FrontendHandler) PostLoginTOTP(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_login_totp")
	defer sp.End()

	session := sessions.Default(ctx)
	username := session.Get(definitions.CookieUsername)
	authResult := session.Get(definitions.CookieAuthResult)
	code := ctx.PostForm("code")
	returnTo := ctx.PostForm("return_to")

	if username == nil || authResult == nil || code == "" {
		ctx.Redirect(http.StatusFound, "/login")

		return
	}

	var oidcCID, samlEntityID string
	if returnTo != "" {
		if u, err := url.Parse(returnTo); err == nil {
			oidcCID = u.Query().Get("client_id")
			samlEntityID = u.Query().Get("entity_id")
		}
	}

	idpInstance := idp.NewNauthilusIdP(h.deps)
	user, err := idpInstance.GetUserByUsername(ctx, username.(string), oidcCID, samlEntityID)

	if err != nil {
		ctx.Redirect(http.StatusFound, "/login")

		return
	}

	// Verify TOTP
	authDeps := h.deps.Auth()
	auth := core.NewAuthStateWithSetupWithDeps(ctx, authDeps).(*core.AuthState)
	auth.SetUsername(username.(string))
	auth.SetOIDCCID(oidcCID)
	auth.SetSAMLEntityID(samlEntityID)

	// We need to load user into auth to get TOTP secret
	// GetUserByUsername already did some of this, but TotpValidation expects secrets in AuthState
	var totpField string
	if protocols := h.deps.Cfg.GetLDAP().GetSearch(); len(protocols) > 0 {
		totpField = protocols[0].GetTotpSecretField()
	}

	if totpField != "" {
		if val, ok := user.Attributes[totpField]; ok && len(val) > 0 {
			auth.SetTOTPSecret(val[0].(string))
		}
	}

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
		data["PostTOTPVerifyEndpoint"] = "/login/totp"
		data["ReturnTo"] = returnTo
		data["HaveError"] = true
		data["ErrorMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Invalid OTP code")

		ctx.HTML(http.StatusOK, "idp_totp_verify.html", data)

		return
	}

	// MFA OK. Now check if the original password was OK.
	if authResult.(uint8) != uint8(definitions.AuthResultOK) {
		stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "fail").Inc()

		data := h.basePageData(ctx)
		data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
		data["Login"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login")
		data["Password"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password")
		data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")
		data["LoginWithWebAuthn"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login with WebAuthn")
		data["Or"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or")

		data["CSRFToken"] = "TODO_CSRF"
		data["PostLoginEndpoint"] = "/login"
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
	session.Set(definitions.CookieAccount, user.Name)
	session.Set(definitions.CookieUniqueUserID, user.Id)
	session.Set(definitions.CookieDisplayName, user.DisplayName)
	session.Set(definitions.CookieSubject, user.Id)
	session.Delete(definitions.CookieUsername)
	session.Delete(definitions.CookieAuthResult)
	session.Save()

	stats.GetMetrics().GetIdpLoginsTotal().WithLabelValues("idp", "success").Inc()

	if returnTo != "" {
		ctx.Redirect(http.StatusFound, returnTo)

		return
	}

	ctx.Redirect(http.StatusFound, "/")
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
	data["Home"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Home")
	data["Logout"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Logout")

	data["RecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Recovery Codes")
	data["RecoveryCodesDescription"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Backup codes can be used to log in if you lose access to your 2FA device.")
	data["GenerateNewRecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Generate new recovery codes")
	data["RecoveryCodesLeft"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "You have %d recovery codes left.")

	data["HaveTOTP"] = session.Get(definitions.CookieHaveTOTP) == true

	username := session.Get(definitions.CookieAccount).(string)
	authDeps := h.deps.Auth()
	dummyAuth := core.NewAuthStateWithSetupWithDeps(ctx, authDeps).(*core.AuthState)
	dummyAuth.SetUsername(username)
	dummyAuth.SetProtocol(config.NewProtocol("oidc")) // Use OIDC as default for attribute mapping

	// Fetch user from backend to get latest attributes
	if _, err := dummyAuth.GetBackendManager(definitions.BackendLDAP, definitions.DefaultBackendName).AccountDB(dummyAuth); err == nil {
		codes := dummyAuth.GetTOTPRecoveryCodes()
		data["HaveRecoveryCodes"] = len(codes) > 0
		data["NumRecoveryCodes"] = len(codes)
	}

	uniqueUserID := session.Get(definitions.CookieUniqueUserID).(string)
	user, err := backend.GetWebAuthnFromRedis(ctx.Request.Context(), h.deps.Cfg, h.deps.Logger, h.deps.Redis, uniqueUserID)
	data["HaveWebAuthn"] = err == nil && user != nil && len(user.WebAuthnCredentials()) > 0

	ctx.HTML(http.StatusOK, "idp_2fa_home.html", data)
}

// RegisterTOTP renders the TOTP registration page.
func (h *FrontendHandler) RegisterTOTP(ctx *gin.Context) {
	session := sessions.Default(ctx)
	account := session.Get(definitions.CookieAccount).(string)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      h.deps.Cfg.GetServer().Frontend.GetTotpIssuer(),
		AccountName: account,
	})

	if err != nil {
		ctx.String(http.StatusInternalServerError, "Failed to generate TOTP key")

		return
	}

	session.Set(definitions.CookieTOTPSecret, key.Secret())
	session.Save()

	data := h.basePageData(ctx)
	data["QRCode"] = key.String()
	data["Secret"] = key.Secret()
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
	secret := session.Get(definitions.CookieTOTPSecret)
	code := ctx.PostForm("code")
	username := session.Get(definitions.CookieAccount).(string)

	if secret == nil || code == "" {
		ctx.String(http.StatusBadRequest, "Invalid request")

		return
	}

	if !totp.Validate(code, secret.(string)) {
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "totp", "fail").Inc()
		ctx.String(http.StatusBadRequest, "Invalid OTP code")

		return
	}

	// Save to backend (LDAP/Lua)
	authDeps := h.deps.Auth()
	sourceBackend := session.Get(definitions.CookieUserBackend)

	var addTOTPSecret core.AddTOTPSecretFunc

	switch sourceBackend.(uint8) {
	case uint8(definitions.BackendLDAP):
		addTOTPSecret = core.NewLDAPManager(definitions.DefaultBackendName, authDeps).AddTOTPSecret
	case uint8(definitions.BackendLua):
		addTOTPSecret = core.NewLuaManager(definitions.DefaultBackendName, authDeps).AddTOTPSecret
	default:
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "totp", "fail").Inc()
		ctx.String(http.StatusInternalServerError, "Unsupported backend")

		return
	}

	// We need a dummy AuthState for addTOTPSecret
	dummyAuth := core.NewAuthStateWithSetupWithDeps(ctx, authDeps).(*core.AuthState)
	dummyAuth.SetUsername(username)

	if err := addTOTPSecret(dummyAuth, core.NewTOTPSecret(secret.(string))); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "totp", "fail").Inc()
		ctx.String(http.StatusInternalServerError, "Failed to save TOTP secret: "+err.Error())

		return
	}

	// Success!
	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "totp", "success").Inc()
	session.Set(definitions.CookieHaveTOTP, true)
	session.Delete(definitions.CookieTOTPSecret)
	session.Save()

	// Purge user from positive redis caches
	h.purgeUserCache(dummyAuth, username)

	ctx.Header("HX-Redirect", "/2fa/v1/register/home")
	ctx.Status(http.StatusOK)
}

// PostGenerateRecoveryCodes handles generating new recovery codes.
func (h *FrontendHandler) PostGenerateRecoveryCodes(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.post_generate_recovery_codes")
	defer sp.End()

	session := sessions.Default(ctx)
	username := session.Get(definitions.CookieAccount).(string)

	authDeps := h.deps.Auth()
	sourceBackend := session.Get(definitions.CookieUserBackend)

	var (
		addTOTPRecoveryCodes    func(auth *core.AuthState, recovery *mfa.TOTPRecovery) error
		deleteTOTPRecoveryCodes func(auth *core.AuthState) error
	)

	switch sourceBackend.(uint8) {
	case uint8(definitions.BackendLDAP):
		mgr := core.NewLDAPManager(definitions.DefaultBackendName, authDeps)
		addTOTPRecoveryCodes = mgr.AddTOTPRecoveryCodes
		deleteTOTPRecoveryCodes = mgr.DeleteTOTPRecoveryCodes
	case uint8(definitions.BackendLua):
		mgr := core.NewLuaManager(definitions.DefaultBackendName, authDeps)
		addTOTPRecoveryCodes = mgr.AddTOTPRecoveryCodes
		deleteTOTPRecoveryCodes = mgr.DeleteTOTPRecoveryCodes
	default:
		ctx.String(http.StatusInternalServerError, "Unsupported backend")

		return
	}

	dummyAuth := core.NewAuthStateWithSetupWithDeps(ctx, authDeps).(*core.AuthState)
	dummyAuth.SetUsername(username)
	dummyAuth.SetProtocol(config.NewProtocol("oidc"))

	// 1. Generate new codes
	recovery, err := core.GenerateBackupCodes()
	if err != nil {
		sp.RecordError(err)
		ctx.String(http.StatusInternalServerError, "Failed to generate recovery codes: "+err.Error())

		return
	}

	// 2. Delete old codes
	if err := deleteTOTPRecoveryCodes(dummyAuth); err != nil {
		sp.RecordError(err)
		ctx.String(http.StatusInternalServerError, "Failed to delete old recovery codes: "+err.Error())

		return
	}

	// 3. Save new codes
	if err := addTOTPRecoveryCodes(dummyAuth, recovery); err != nil {
		sp.RecordError(err)
		ctx.String(http.StatusInternalServerError, "Failed to save recovery codes: "+err.Error())

		return
	}

	// Success!
	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("register", "recovery", "success").Inc()

	// Purge user from positive redis caches
	h.purgeUserCache(dummyAuth, username)

	data := h.basePageData(ctx)
	data["NewRecoveryCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "New recovery codes")
	data["BackupTheseCodes"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Backup these codes!")
	data["ShownOnlyOnce"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "They will be shown only once.")
	data["Close"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Close")
	data["Codes"] = recovery.GetCodes()

	ctx.HTML(http.StatusOK, "idp_recovery_codes_modal.html", data)
}

func (h *FrontendHandler) purgeUserCache(auth *core.AuthState, username string) {
	h.purgeCache(auth, username)
}

func (h *FrontendHandler) purgeCache(auth *core.AuthState, username string) {
	authDeps := h.deps.Auth()
	useCache := false

	for _, backendType := range authDeps.Cfg.GetServer().GetBackends() {
		if backendType.Get() == definitions.BackendCache {
			useCache = true

			break
		}
	}

	if !useCache {
		return
	}

	accountName, err := backend.LookupUserAccountFromRedis(auth.Ctx(), authDeps.Cfg, authDeps.Redis, username, definitions.ProtoOryHydra, "")
	if err != nil {
		return
	}

	protocols := authDeps.Cfg.GetAllProtocols()
	userKeys := config.NewStringSet()

	for index := range protocols {
		cacheNames := backend.GetCacheNames(authDeps.Cfg, authDeps.Channel, protocols[index], definitions.CacheAll)

		for _, cacheName := range (&cacheNames).GetStringSlice() {
			var sb strings.Builder

			sb.WriteString(authDeps.Cfg.GetServer().GetRedis().GetPrefix())
			sb.WriteString(definitions.RedisUserPositiveCachePrefix)
			sb.WriteString(cacheName)
			sb.WriteByte(':')
			sb.WriteString(accountName)

			(&userKeys).Set(sb.String())
		}
	}

	for _, userKey := range (&userKeys).GetStringSlice() {
		_, _ = authDeps.Redis.GetWriteHandle().Del(auth.Ctx(), userKey).Result()
	}
}

// DeleteTOTP removes TOTP for the user.
func (h *FrontendHandler) DeleteTOTP(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.delete_totp")
	defer sp.End()

	session := sessions.Default(ctx)
	username := session.Get(definitions.CookieAccount).(string)

	authDeps := h.deps.Auth()
	sourceBackend := session.Get(definitions.CookieUserBackend)

	var deleteTOTPSecret func(auth *core.AuthState) error

	switch sourceBackend.(uint8) {
	case uint8(definitions.BackendLDAP):
		deleteTOTPSecret = core.NewLDAPManager(definitions.DefaultBackendName, authDeps).DeleteTOTPSecret
	case uint8(definitions.BackendLua):
		deleteTOTPSecret = core.NewLuaManager(definitions.DefaultBackendName, authDeps).DeleteTOTPSecret
	default:
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "fail").Inc()
		ctx.String(http.StatusInternalServerError, "Unsupported backend")

		return
	}

	dummyAuth := core.NewAuthStateWithSetupWithDeps(ctx, authDeps).(*core.AuthState)
	dummyAuth.SetUsername(username)

	if err := deleteTOTPSecret(dummyAuth); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "fail").Inc()
		ctx.String(http.StatusInternalServerError, "Failed to delete TOTP secret: "+err.Error())

		return
	}

	stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "totp", "success").Inc()
	session.Set(definitions.CookieHaveTOTP, false)
	session.Save()

	h.purgeUserCache(dummyAuth, username)

	ctx.Header("HX-Redirect", "/2fa/v1/register/home")
	ctx.Status(http.StatusOK)
}

// DeleteWebAuthn removes WebAuthn credentials for the user.
func (h *FrontendHandler) DeleteWebAuthn(ctx *gin.Context) {
	_, sp := h.tracer.Start(ctx.Request.Context(), "frontend.delete_webauthn")
	defer sp.End()

	session := sessions.Default(ctx)
	userID := session.Get(definitions.CookieUniqueUserID).(string)
	username := session.Get(definitions.CookieAccount).(string)

	key := h.deps.Cfg.GetServer().GetRedis().GetPrefix() + "webauthn:user:" + userID
	if err := h.deps.Redis.GetWriteHandle().Del(ctx.Request.Context(), key).Err(); err != nil {
		sp.RecordError(err)
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "fail").Inc()
	} else {
		stats.GetMetrics().GetIdpMfaOperationsTotal().WithLabelValues("delete", "webauthn", "success").Inc()
	}

	dummyAuth := core.NewAuthStateWithSetupWithDeps(ctx, h.deps.Auth()).(*core.AuthState)
	h.purgeUserCache(dummyAuth, username)

	ctx.Header("HX-Redirect", "/2fa/v1/register/home")
	ctx.Status(http.StatusOK)
}

// RegisterWebAuthn renders the WebAuthn registration page.
func (h *FrontendHandler) RegisterWebAuthn(ctx *gin.Context) {
	data := h.basePageData(ctx)
	data["Title"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register WebAuthn")
	data["WebAuthnMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please connect your security key and follow the instructions")
	data["Submit"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit")

	// JS Localizations
	data["JSInteractWithKey"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please interact with your security key...")
	data["JSCompletingRegistration"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Completing registration...")
	data["JSUnknownError"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "An unknown error occurred")

	ctx.HTML(http.StatusOK, "idp_webauthn_register.html", data)
}
