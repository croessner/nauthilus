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

package core

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/tags"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// LoginGET2FA handles GET requests for the 2FA registration page.
func (h *NativeIdPHandlers) LoginGET2FA(ctx *gin.Context) {
	session := sessions.Default(ctx)

	cookieValue := session.Get(definitions.CookieLang)
	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(ctx, h.deps.Cfg, definitions.TwoFAv1Root+h.deps.Cfg.GetServer().Frontend.TwoFactorPage, config.DefaultLanguageTags, languageCurrentName)

	totpSecret, _, _ := h.getSessionTOTPSecret(ctx)
	if totpSecret == "" {
		sessionCleaner(ctx)
		h.displayLoginpage(ctx, languageCurrentName, languagePassive)
	} else {
		cookieValue = session.Get(definitions.CookieHome)
		if cookieValue != nil {
			if loggedIn, assertOk := cookieValue.(bool); assertOk && loggedIn {
				h.processTwoFARedirect(ctx, true)

				return
			}
		}

		h.displayTOTPpage(ctx, languageCurrentName, languagePassive)
	}
}

// displayLoginpage is a function that displays the login page.
func (h *NativeIdPHandlers) displayLoginpage(ctx *gin.Context, languageCurrentName string, languagePassive []frontend.Language) {
	var (
		haveError    bool
		errorMessage string
		guid         = ctx.GetString(definitions.CtxGUIDKey)
		csrfToken    = ctx.GetString(definitions.CtxCSRFTokenKey)
	)

	session := sessions.Default(ctx)

	if errorMessage = ctx.Query("_error"); errorMessage != "" {
		if errorMessage == definitions.PasswordFail {
			errorMessage = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, definitions.PasswordFail)
		}

		haveError = true
	}

	// Using data structure from frontend package
	loginData := &frontend.LoginPageData{
		Title: frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login"),
		WantWelcome: func() bool {
			if h.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
				return true
			}

			return false
		}(),
		Welcome:             h.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome(),
		LogoImage:           h.deps.Cfg.GetServer().Frontend.GetDefaultLogoImage(),
		LogoImageAlt:        h.deps.Cfg.GetServer().Frontend.GetLoginPageLogoImageAlt(),
		HaveError:           haveError,
		ErrorMessage:        errorMessage,
		Login:               frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login"),
		Privacy:             frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "We'll never share your data with anyone else."),
		LoginPlaceholder:    frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your username or email address"),
		Password:            frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Password"),
		PasswordPlaceholder: frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your password"),
		Submit:              frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit"),
		Or:                  frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or"),
		Device:              frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login with WebAuthn"),
		PostLoginEndpoint:   definitions.TwoFAv1Root + h.deps.Cfg.GetServer().Frontend.TwoFactorPage,
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
		InDevelopment:       tags.IsDevelopment,
	}

	ctx.HTML(http.StatusOK, "login.html", loginData)

	level.Info(h.deps.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUriPath, definitions.TwoFAv1Root+h.deps.Cfg.GetServer().Frontend.TwoFactorPage,
	)
}

// displayTOTPpage displays the TOTP authentication page.
func (h *NativeIdPHandlers) displayTOTPpage(ctx *gin.Context, languageCurrentName string, languagePassive []frontend.Language) {
	csrfToken := ctx.GetString(definitions.CtxCSRFTokenKey)
	session := sessions.Default(ctx)

	twoFactorData := &frontend.TwoFactorData{
		Title: frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login"),
		WantWelcome: func() bool {
			if h.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
				return true
			}

			return false
		}(),
		Welcome:             h.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome(),
		LogoImage:           h.deps.Cfg.GetServer().Frontend.GetDefaultLogoImage(),
		LogoImageAlt:        h.deps.Cfg.GetServer().Frontend.GetNotifyPageLogoImageAlt(), // Corrected from totp_page_logo_image_alt
		Code:                frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP-Code"),
		Tos:                 frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Terms of service"),
		Submit:              frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit"),
		PostLoginEndpoint:   definitions.TwoFAv1Root + h.deps.Cfg.GetServer().Frontend.TwoFactorPage,
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
	}

	ctx.HTML(http.StatusOK, "totp.html", twoFactorData)
}

// getSessionTOTPSecret retrieves the TOTP secret and code from the session and the POST form, respectively.
func (h *NativeIdPHandlers) getSessionTOTPSecret(ctx *gin.Context) (string, string, string) {
	var (
		totpSecret string
		totpCode   string
		account    string
	)

	session := sessions.Default(ctx)

	if value, assertOk := session.Get(definitions.CookieTOTPSecret).(string); assertOk {
		totpSecret = value
	}

	if value, assertOk := session.Get(definitions.CookieAccount).(string); assertOk {
		account = value
	}

	totpCode = ctx.PostForm("code")

	return totpSecret, totpCode, account
}

// LoginPOST2FA handles POST requests for the '/2fa/v1/register/post' endpoint.
func (h *NativeIdPHandlers) LoginPOST2FA(ctx *gin.Context) {
	var (
		authCompleteWithOK   bool
		authCompleteWithFail bool
		guid                 = ctx.GetString(definitions.CtxGUIDKey)
	)

	authResult := h.processTOTPSecret(ctx)

	if authResult == definitions.AuthResultOK {
		authCompleteWithOK = true
	}

	if authResult == definitions.AuthResultFail {
		authCompleteWithFail = true
	}

	auth := &AuthState{
		deps: h.deps,
		Request: AuthRequest{
			HTTPClientContext: ctx,
			HTTPClientRequest: ctx.Request,
			Username:          ctx.PostForm("username"),
			Password:          ctx.PostForm("password"),
			Protocol:          config.NewProtocol(definitions.ProtoOryHydra),
		},
		Runtime: AuthRuntime{
			GUID: guid,
		},
	}

	// It might be the second call after 2FA! In this case, there does not exist any username or password.
	if auth.Request.Username != "" && !util.ValidateUsername(auth.Request.Username) {
		HandleErrWithDeps(ctx, errors.ErrInvalidUsername, h.deps)

		return
	}

	auth.SetStatusCodes(definitions.ServOryHydra)
	auth.WithDefaults(ctx).WithClientInfo(ctx).WithLocalInfo(ctx).WithUserAgent(ctx).WithXSSL(ctx)

	if reject := auth.PreproccessAuthRequest(ctx); reject {
		HandleErrWithDeps(ctx, errors.ErrBruteForceAttack, h.deps)

		return
	}

	if authResult == definitions.AuthResultUnset {
		authResult = auth.HandlePassword(ctx)

		// User does not have a TOTP secret
		if _, found := auth.GetTOTPSecretOk(); !found {
			if authResult == definitions.AuthResultOK {
				tolerate.GetTolerate().SetIPAddress(auth.Ctx(), auth.GetClientIP(), auth.GetUsername(), true)
				authCompleteWithOK = true
			}

			if authResult == definitions.AuthResultFail {
				tolerate.GetTolerate().SetIPAddress(auth.Ctx(), auth.GetClientIP(), auth.GetUsername(), false)
				authCompleteWithFail = true
			}
		}
	}

	h.processAuthResult(ctx, authResult, auth, authCompleteWithOK, authCompleteWithFail)
}

// processTOTPSecret retrieves the TOTP secret and code from the session and the POST form, respectively.
func (h *NativeIdPHandlers) processTOTPSecret(ctx *gin.Context) definitions.AuthResult {
	authResult := definitions.AuthResultUnset
	session := sessions.Default(ctx)

	totpSecret, totpCode, account := h.getSessionTOTPSecret(ctx)
	if totpSecret != "" && totpCode != "" && account != "" {
		auth := NewAuthStateWithSetupWithDeps(ctx, h.deps).(*AuthState)
		auth.SetUsername(session.Get(definitions.CookieUsername).(string))
		auth.SetAccount(account)
		auth.SetTOTPSecret(totpSecret)

		if val := session.Get(definitions.CookieUserBackend); val != nil {
			auth.Runtime.SourcePassDBBackend = definitions.Backend(val.(uint8))
		}

		// Fetch user from backend to get latest attributes (including recovery codes)
		_, _ = auth.GetBackendManager(auth.Runtime.SourcePassDBBackend, definitions.DefaultBackendName).AccountDB(auth)

		if errFail := TotpValidation(ctx, auth, totpCode, h.deps); errFail != nil {
			authResult = definitions.AuthResultFail
		} else {
			cookieValue := session.Get(definitions.CookieAuthResult)
			if cookieValue != nil {
				authResult = definitions.AuthResult(cookieValue.(uint8))
			}
		}
	}

	return authResult
}

// processAuthResult handles the authentication result by calling the respective handler functions based on the authResult value
func (h *NativeIdPHandlers) processAuthResult(ctx *gin.Context, authResult definitions.AuthResult, auth *AuthState, authCompleteWithOK bool, authCompleteWithFail bool) {
	if authResult == definitions.AuthResultOK {
		if !authCompleteWithOK {
			if err := h.saveSessionData(ctx, authResult, auth); err != nil {
				HandleErrWithDeps(ctx, err, h.deps)

				return
			}
		}

		h.processTwoFARedirect(ctx, authCompleteWithOK)
	} else if authResult == definitions.AuthResultFail {
		if !authCompleteWithFail {
			if err := h.saveSessionData(ctx, authResult, auth); err != nil {
				HandleErrWithDeps(ctx, err, h.deps)

				return
			}

			h.processTwoFARedirect(ctx, authCompleteWithFail)

			return
		}

		h.handleAuthFailureAndRedirect(ctx, auth)
	} else {
		h.handleAuthFailureAndRedirect(ctx, auth)
	}
}

// processTwoFARedirect redirects the context to the 2FA login page with the appropriate target URI.
func (h *NativeIdPHandlers) processTwoFARedirect(ctx *gin.Context, authComplete bool) {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	targetURI := definitions.TwoFAv1Root + h.deps.Cfg.GetServer().Frontend.TwoFactorPage + "/home"
	if !authComplete {
		targetURI = definitions.TwoFAv1Root + h.deps.Cfg.GetServer().Frontend.TwoFactorPage
	}

	ctx.Redirect(http.StatusFound, targetURI)

	level.Info(h.deps.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUsername, ctx.PostForm("username"),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthAccept,
		definitions.LogKeyUriPath, targetURI,
	)
}

// saveSessionData handles the authentication result by setting session variables and redirecting to the 2FA page.
func (h *NativeIdPHandlers) saveSessionData(ctx *gin.Context, authResult definitions.AuthResult, auth *AuthState) error {
	var (
		found        bool
		account      string
		uniqueUserID string
		displayName  string
		totpSecret   string
	)

	session := sessions.Default(ctx)

	if account, found = auth.GetAccountOk(); !found {
		return errors.ErrNoAccount
	}

	if totpSecret, found = auth.GetTOTPSecretOk(); found {
		session.Set(definitions.CookieHaveTOTP, true)
		session.Set(definitions.CookieTOTPSecret, totpSecret)
	} else {
		session.Set(definitions.CookieHaveTOTP, false)
	}

	if uniqueUserID, found = auth.GetUniqueUserIDOk(); found {
		session.Set(definitions.CookieUniqueUserID, uniqueUserID)
	}

	if displayName, found = auth.GetDisplayNameOk(); found {
		session.Set(definitions.CookieDisplayName, displayName)
	}

	session.Set(definitions.CookieAuthResult, uint8(authResult))
	session.Set(definitions.CookieUsername, ctx.PostForm("username"))
	session.Set(definitions.CookieAccount, account)
	session.Set(definitions.CookieUserBackend, uint8(auth.Runtime.SourcePassDBBackend))

	if err := session.Save(); err != nil {
		return err
	}

	return nil
}

// handleAuthFailureAndRedirect handles the authentication failure result by updating the brute force counter, redirecting
// the context to the 2FA page with the error message, and logging the authentication rejection information.
func (h *NativeIdPHandlers) handleAuthFailureAndRedirect(ctx *gin.Context, auth *AuthState) {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	auth.Request.ClientIP = ctx.GetString(definitions.CtxClientIPKey)

	auth.UpdateBruteForceBucketsCounter(ctx)

	h.sessionCleanupTOTP(ctx)

	ctx.Redirect(
		http.StatusFound,
		definitions.TwoFAv1Root+h.deps.Cfg.GetServer().Frontend.TwoFactorPage+"?_error="+definitions.PasswordFail,
	)

	level.Info(h.deps.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUsername, ctx.PostForm("username"),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthReject,
		definitions.LogKeyUriPath, definitions.TwoFAv1Root+h.deps.Cfg.GetServer().Frontend.TwoFactorPage+"/post",
	)
}

// sessionCleanupTOTP removes the TOTP secret and code from the current session.
func (h *NativeIdPHandlers) sessionCleanupTOTP(ctx *gin.Context) {
	session := sessions.Default(ctx)

	session.Delete(definitions.CookieTOTPSecret)
	session.Save()
}

// Register2FAHome is the handler for the '/2fa/v1/register/home' endpoint.
func (h *NativeIdPHandlers) Register2FAHome(ctx *gin.Context) {
	var haveTOTP bool

	session := sessions.Default(ctx)

	cookieValue := session.Get(definitions.CookieHaveTOTP)
	if cookieValue != nil {
		haveTOTP = cookieValue.(bool)
	}

	cookieValue = session.Get(definitions.CookieAuthResult)
	if cookieValue == nil || definitions.AuthResult(cookieValue.(uint8)) != definitions.AuthResultOK {
		HandleErrWithDeps(ctx, errors.ErrNotLoggedIn, h.deps)

		return
	}

	cookieValue = session.Get(definitions.CookieAccount)
	if cookieValue == nil {
		HandleErrWithDeps(ctx, errors.ErrNoAccount, h.deps)

		return
	}

	session.Set(definitions.CookieHome, true)
	session.Save()

	cookieValue = session.Get(definitions.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(ctx, h.deps.Cfg, definitions.TwoFAv1Root+h.deps.Cfg.GetServer().Frontend.TwoFactorPage+"/post", config.DefaultLanguageTags, languageCurrentName)

	homeData := &frontend.HomePageData{
		Title: frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Home"),
		WantWelcome: func() bool {
			if h.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
				return true
			}

			return false
		}(),
		HaveTOTP:            haveTOTP,
		Welcome:             h.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome(),
		LogoImage:           h.deps.Cfg.GetServer().Frontend.GetDefaultLogoImage(),
		LogoImageAlt:        h.deps.Cfg.GetServer().Frontend.GetNotifyPageLogoImageAlt(), // Corrected
		HomeMessage:         frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please make a selection"),
		RegisterTOTP:        frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register TOTP"),
		EndpointTOTP:        definitions.TwoFAv1Root + h.deps.Cfg.GetServer().Frontend.TwoFactorPage, // Corrected
		Or:                  frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "or"),
		RegisterWebAuthn:    frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Register WebAuthn"),
		EndpointWebAuthn:    definitions.TwoFAv1Root + h.deps.Cfg.GetServer().Frontend.TwoFactorPage + "/webauthn", // Placeholder
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		InDevelopment:       tags.IsDevelopment,
	}

	ctx.HTML(http.StatusOK, "home.html", homeData)
}

// RegisterTotpGET is the handler for the '/2fa/v1/totp' endpoint.
func (h *NativeIdPHandlers) RegisterTotpGET(ctx *gin.Context) {
	var (
		haveError    bool
		errorMessage string
		csrfToken    = ctx.GetString(definitions.CtxCSRFTokenKey)
	)

	session := sessions.Default(ctx)

	cookieValue := session.Get(definitions.CookieHaveTOTP)
	if cookieValue != nil {
		if cookieValue.(bool) {
			session.Delete(definitions.CookieAuthResult)
			session.Delete(definitions.CookieAccount)
			session.Delete(definitions.CookieHaveTOTP)

			session.Save()

			ctx.Redirect(http.StatusFound, h.deps.Cfg.GetServer().Frontend.GetNotifyPage()+"?message=You have already registered TOTP")

			return
		}
	}

	cookieValue = session.Get(definitions.CookieAuthResult)
	if cookieValue == nil || definitions.AuthResult(cookieValue.(uint8)) != definitions.AuthResultOK {
		HandleErrWithDeps(ctx, errors.ErrNotLoggedIn, h.deps)

		return
	}

	cookieValue = session.Get(definitions.CookieAccount)
	if cookieValue == nil {
		HandleErrWithDeps(ctx, errors.ErrNoAccount, h.deps)

		return
	}

	account := cookieValue.(string)

	totpURL := session.Get(definitions.CookieTOTPURL)
	if totpURL == nil {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      h.deps.Cfg.GetServer().Frontend.GetTotpIssuer(),
			AccountName: account,
		})

		if err != nil {
			HandleErrWithDeps(ctx, err, h.deps)

			return
		}

		totpURL = key.String()

		session.Set(definitions.CookieTOTPURL, totpURL.(string))
		session.Save()
	}

	cookieValue = session.Get(definitions.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(ctx, h.deps.Cfg, definitions.TwoFAv1Root+h.deps.Cfg.GetServer().Frontend.TwoFactorPage, config.DefaultLanguageTags, languageCurrentName)

	if errorMessage = ctx.Query("_error"); errorMessage != "" {
		if errorMessage == definitions.PasswordFail {
			errorMessage = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, definitions.PasswordFail)
		}

		haveError = true
	}

	totpData := frontend.TOTPPageData{
		Title: frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login"),
		WantWelcome: func() bool {
			if h.deps.Cfg.GetServer().Frontend.GetNotifyPageWelcome() != "" { // Reusing notify welcome
				return true
			}

			return false
		}(),
		Welcome:             h.deps.Cfg.GetServer().Frontend.GetNotifyPageWelcome(),
		LogoImage:           h.deps.Cfg.GetServer().Frontend.GetDefaultLogoImage(),
		LogoImageAlt:        h.deps.Cfg.GetServer().Frontend.GetNotifyPageLogoImageAlt(),
		HaveError:           haveError,
		ErrorMessage:        errorMessage,
		TOTPMessage:         frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please scan and verify the following QR code"),
		TOTPCopied:          frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Copied to clipboard!"),
		Code:                frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "OTP-Code"),
		Submit:              frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit"),
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		WantTos:             false,
		WantPolicy:          false,
		CSRFToken:           csrfToken,
		QRCode:              totpURL.(string),
		PostTOTPEndpoint:    definitions.TwoFAv1Root + h.deps.Cfg.GetServer().Frontend.TwoFactorPage,
	}

	ctx.HTML(http.StatusOK, "regtotp.html", totpData)
}

// RegisterTotpPOST is the handler for the '/2fa/v1/totp/post' endpoint.
func (h *NativeIdPHandlers) RegisterTotpPOST(ctx *gin.Context) {
	var (
		err           error
		totpKey       *otp.Key
		guid          = ctx.GetString(definitions.CtxGUIDKey)
		addTOTPSecret AddTOTPSecretFunc
	)

	session := sessions.Default(ctx)

	cookieValue := session.Get(definitions.CookieTOTPURL)
	if cookieValue == nil {
		HandleErrWithDeps(ctx, errors.ErrNoTOTPURL, h.deps)

		return
	}

	if totpKey, err = otp.NewKeyFromURL(cookieValue.(string)); err != nil {
		HandleErrWithDeps(ctx, err, h.deps)

		return
	}

	if h.deps.Cfg.GetServer().GetLog().GetLogLevel() >= definitions.LogLevelDebug && h.deps.Env.GetDevMode() {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgWebAuthn,
			definitions.LogKeyGUID, guid,
			"totp_key", fmt.Sprintf("%+v", totpKey),
		)
	}

	if !totp.Validate(ctx.PostForm("code"), totpKey.Secret()) {
		var sb strings.Builder

		sb.WriteString(definitions.TwoFAv1Root)
		sb.WriteString(h.deps.Cfg.GetServer().Frontend.TwoFactorPage)
		sb.WriteString("?_error=")
		sb.WriteString(definitions.InvalidCode)

		ctx.Redirect(http.StatusFound, sb.String())

		var sbLog strings.Builder

		sbLog.WriteString(definitions.TwoFAv1Root)
		sbLog.WriteString(h.deps.Cfg.GetServer().Frontend.TwoFactorPage)
		sbLog.WriteString("/post")

		level.Info(h.deps.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyUsername, ctx.PostForm("username"),
			definitions.LogKeyAuthStatus, definitions.LogKeyAuthReject,
			definitions.LogKeyUriPath, sbLog.String(),
		)

		return
	}

	username := session.Get(definitions.CookieUsername).(string)

	auth := &AuthState{
		deps: h.deps,
		Request: AuthRequest{
			HTTPClientContext: ctx,
			HTTPClientRequest: ctx.Request,
			Username:          username,
			Protocol:          config.NewProtocol(definitions.ProtoOryHydra),
		},
		Runtime: AuthRuntime{
			GUID: guid,
		},
	}

	sourceBackend := session.Get(definitions.CookieUserBackend)

	switch sourceBackend.(uint8) {
	case uint8(definitions.BackendLDAP):
		// We have no mapping to an optional LDAP pool!
		addTOTPSecret = NewLDAPManager(definitions.DefaultBackendName, h.deps).AddTOTPSecret
	case uint8(definitions.BackendLua):
		// We have no mapping to an optional Lua backend!
		addTOTPSecret = NewLuaManager(definitions.DefaultBackendName, h.deps).AddTOTPSecret
	default:
		HandleErrWithDeps(ctx, errors.NewDetailedError("unsupported_backend").WithDetail(
			"Database backend not supported"), h.deps)

		return
	}

	if err = addTOTPSecret(auth, NewTOTPSecret(totpKey.Secret())); err != nil {
		HandleErrWithDeps(ctx, err, h.deps)

		return
	}

	/*
		Purge user from positive redis caches
	*/
	if err = h.purgeUserPositiveCache(auth.Ctx(), username, guid); err != nil {
		HandleErrWithDeps(ctx, err, h.deps)

		return
	}

	// POST cleanup
	sessionCleaner(ctx)

	// Log out user
	session.Delete(definitions.CookieHome)
	session.Save()

	var sbRedirect strings.Builder

	sbRedirect.WriteString(h.deps.Cfg.GetServer().Frontend.GetNotifyPage())
	sbRedirect.WriteString("?message=OTP code is valid. Registration completed successfully")

	ctx.Redirect(http.StatusFound, sbRedirect.String())

	var sbLog strings.Builder

	sbLog.WriteString(definitions.TwoFAv1Root)
	sbLog.WriteString(h.deps.Cfg.GetServer().Frontend.TwoFactorPage)
	sbLog.WriteString("/post")

	level.Info(h.deps.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUsername, username,
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthAccept,
		definitions.LogKeyUriPath, sbLog.String(),
	)
}

// purgeUserPositiveCache removes the current user from the positive redis caches.
func (h *NativeIdPHandlers) purgeUserPositiveCache(ctx context.Context, username string, guid string) error {
	useCache := false
	for _, backendType := range h.deps.Cfg.GetServer().GetBackends() {
		if backendType.Get() == definitions.BackendCache {
			useCache = true

			break
		}
	}

	if !useCache {
		return nil
	}

	userKeys := config.NewStringSet()
	protocols := h.deps.Cfg.GetAllProtocols()

	accountName, err := backend.LookupUserAccountFromRedis(ctx, h.deps.Cfg, h.deps.Redis, username, definitions.ProtoOryHydra, "")
	if err != nil {
		return err
	}

	for index := range protocols {
		cacheNames := backend.GetCacheNames(h.deps.Cfg, h.deps.Channel, protocols[index], definitions.CacheAll)

		for _, cacheName := range cacheNames.GetStringSlice() {
			var sb strings.Builder

			sb.WriteString(h.deps.Cfg.GetServer().GetRedis().GetPrefix())
			sb.WriteString(definitions.RedisUserPositiveCachePrefix)
			sb.WriteString(cacheName)
			sb.WriteByte(':')
			sb.WriteString(accountName)

			userKeys.Set(sb.String())
		}
	}

	// Remove current user from cache to enforce refreshing it.
	for _, userKey := range userKeys.GetStringSlice() {
		if _, err = h.deps.Redis.GetWriteHandle().Del(ctx, userKey).Result(); err != nil {
			stats.GetMetrics().GetRedisWriteCounter().Inc()

			level.Error(h.deps.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Failed to purge user from cache",
				definitions.LogKeyError, err,
			)

			break
		} else {
			stats.GetMetrics().GetRedisWriteCounter().Inc()
		}
	}

	return nil
}
