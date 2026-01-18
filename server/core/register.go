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

//go:build hydra
// +build hydra

package core

import (
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

// sessionCleaner removes all user information from the current session.
func sessionCleaner(ctx *gin.Context) {
	session := sessions.Default(ctx)

	// Cleanup
	session.Delete(definitions.CookieAuthResult)
	session.Delete(definitions.CookieUsername)
	session.Delete(definitions.CookieAccount)
	session.Delete(definitions.CookieHaveTOTP)
	session.Delete(definitions.CookieTOTPURL)
	session.Delete(definitions.CookieUserBackend)
	session.Delete(definitions.CookieUniqueUserID)
	session.Delete(definitions.CookieDisplayName)
	session.Delete(definitions.CookieRegistration)

	session.Save()
}

// LoginGET2FAHandler Page '/2fa/v1/register'
func LoginGET2FAHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		LoginGET2FAHandlerWithDeps(ctx, deps)
	}
}

// LoginGET2FAHandlerWithDeps is the DI variant of LoginGET2FAHandler.
func LoginGET2FAHandlerWithDeps(ctx *gin.Context, deps AuthDeps) {
	session := sessions.Default(ctx)

	cookieValue := session.Get(definitions.CookieLang)
	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(ctx, deps.Cfg, definitions.TwoFAv1Root+deps.Cfg.GetServer().Frontend.TwoFactorPage, config.DefaultLanguageTags, languageCurrentName)

	totpSecret, _, _ := getSessionTOTPSecret(ctx)
	if totpSecret == "" {
		sessionCleaner(ctx)
		displayLoginpage(ctx, languageCurrentName, languagePassive, deps)
	} else {
		cookieValue = session.Get(definitions.CookieHome)
		if cookieValue != nil {
			if loggedIn, assertOk := cookieValue.(bool); assertOk && loggedIn {
				processTwoFARedirect(ctx, true, deps)

				return
			}
		}

		displayTOTPpage(ctx, languageCurrentName, languagePassive, deps)
	}
}

// displayLoginpage is a function that displays the login page.
func displayLoginpage(ctx *gin.Context, languageCurrentName string, languagePassive []frontend.Language, deps AuthDeps) {
	var (
		haveError    bool
		errorMessage string
		guid         = ctx.GetString(definitions.CtxGUIDKey)
		csrfToken    = ctx.GetString(definitions.CtxCSRFTokenKey)
	)

	session := sessions.Default(ctx)

	if errorMessage = ctx.Query("_error"); errorMessage != "" {
		if errorMessage == definitions.PasswordFail {
			errorMessage = frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, definitions.PasswordFail)
		}

		haveError = true
	}

	// Using data structure from frontend package
	loginData := &frontend.LoginPageData{
		Title: frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Login"),
		WantWelcome: func() bool {
			if deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
				return true
			}

			return false
		}(),
		Welcome:             deps.Cfg.GetServer().Frontend.GetLoginPageWelcome(),
		LogoImage:           deps.Cfg.GetServer().Frontend.GetDefaultLogoImage(),
		LogoImageAlt:        deps.Cfg.GetServer().Frontend.GetLoginPageLogoImageAlt(),
		HaveError:           haveError,
		ErrorMessage:        errorMessage,
		Login:               frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Login"),
		Privacy:             frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "We'll never share your data with anyone else."),
		LoginPlaceholder:    frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Please enter your username or email address"),
		Password:            frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Password"),
		PasswordPlaceholder: frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Please enter your password"),
		Submit:              frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Submit"),
		Or:                  frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "or"),
		Device:              frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Login with WebAuthn"),
		PostLoginEndpoint:   definitions.TwoFAv1Root + deps.Cfg.GetServer().Frontend.TwoFactorPage,
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
		InDevelopment:       tags.IsDevelopment,
	}

	ctx.HTML(http.StatusOK, "login.html", loginData)

	level.Info(deps.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUriPath, definitions.TwoFAv1Root+deps.Cfg.GetServer().Frontend.TwoFactorPage,
	)
}

// displayTOTPpage displays the TOTP authentication page.
func displayTOTPpage(ctx *gin.Context, languageCurrentName string, languagePassive []frontend.Language, deps AuthDeps) {
	csrfToken := ctx.GetString(definitions.CtxCSRFTokenKey)
	session := sessions.Default(ctx)

	twoFactorData := &frontend.TwoFactorData{
		Title: frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Login"),
		WantWelcome: func() bool {
			if deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
				return true
			}

			return false
		}(),
		Welcome:             deps.Cfg.GetServer().Frontend.GetLoginPageWelcome(),
		LogoImage:           deps.Cfg.GetServer().Frontend.GetDefaultLogoImage(),
		LogoImageAlt:        deps.Cfg.GetServer().Frontend.GetNotifyPageLogoImageAlt(), // Corrected from totp_page_logo_image_alt
		Code:                frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "OTP-Code"),
		Tos:                 frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Terms of service"),
		Submit:              frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Submit"),
		PostLoginEndpoint:   definitions.TwoFAv1Root + deps.Cfg.GetServer().Frontend.TwoFactorPage,
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
	}

	ctx.HTML(http.StatusOK, "totp.html", twoFactorData)
}

// getSessionTOTPSecret retrieves the TOTP secret and code from the session and the POST form, respectively.
// It takes a Gin context as input, and returns the TOTP secret and code as strings.
// The function initializes the variables totpSecret, totpCode, and account as empty strings.
// It retrieves the TOTP secret from the session using sessions.Default(ctx) and session.Get(definitions.CookieTOTPSecret).
// The TOTP secret is then type asserted to a string using the assertOk pattern.
// The function retrieves the TOTP code from the POST form using ctx.PostForm("code").
// Finally, it returns the variables totpSecret and totpCode as strings.
func getSessionTOTPSecret(ctx *gin.Context) (string, string, string) {
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

// LoginPOST2FAHandler Page '/2fa/v1/register/post'
func LoginPOST2FAHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		LoginPOST2FAHandlerWithDeps(ctx, deps)
	}
}

// LoginPOST2FAHandlerWithDeps is the DI variant of LoginPOST2FAHandler.
func LoginPOST2FAHandlerWithDeps(ctx *gin.Context, deps AuthDeps) {
	var (
		authCompleteWithOK   bool
		authCompleteWithFail bool
		guid                 = ctx.GetString(definitions.CtxGUIDKey)
	)

	authResult := processTOTPSecret(ctx, deps)

	if authResult == definitions.AuthResultOK {
		authCompleteWithOK = true
	}

	if authResult == definitions.AuthResultFail {
		authCompleteWithFail = true
	}

	auth := &AuthState{
		deps:              deps,
		HTTPClientContext: ctx,
		HTTPClientRequest: ctx.Request,
		GUID:              guid,
		Username:          ctx.PostForm("username"),
		Password:          ctx.PostForm("password"),
		Protocol:          config.NewProtocol(definitions.ProtoOryHydra),
	}

	// It might be the second call after 2FA! In this case, there does not exist any username or password.
	if auth.Username != "" && !util.ValidateUsername(auth.Username) {
		HandleErrWithDeps(ctx, errors.ErrInvalidUsername, deps)

		return
	}

	auth.SetStatusCodes(definitions.ServOryHydra)
	auth.WithDefaults(ctx).WithClientInfo(ctx).WithLocalInfo(ctx).WithUserAgent(ctx).WithXSSL(ctx)

	if reject := auth.PreproccessAuthRequest(ctx); reject {
		HandleErrWithDeps(ctx, errors.ErrBruteForceAttack, deps)

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

	processAuthResult(ctx, authResult, auth, authCompleteWithOK, authCompleteWithFail, deps)
}

// processTOTPSecret retrieves the TOTP secret and code from the session and the POST form, respectively.
// It takes a Gin context as input, and returns the authentication result as definitions.AuthResult.
// The function initializes the authentication result as definitions.AuthResultUnset.
// It retrieves the GUID from the Gin context using ctx.GetString(definitions.CtxGUIDKey).
// It retrieves the session using sessions.Default(ctx).
// It calls getSessionTOTPSecret(ctx) to get the TOTP secret, TOTP code, and account.
// If the TOTP secret, TOTP code, and account are not empty, it calls totpValidation(guid, totpCode, account, totpSecret)
//
//	to validate the TOTP code.
//
// If the validation fails (i.e., errFail is not nil), it sets the authentication result as definitions.AuthResultFail.
// Otherwise, it retrieves the authentication result from the session using session.Get(definitions.CookieAuthResult).
// If the authentication result is not nil (i.e., cookieValue is not nil), it sets the authentication result as the value
//
//	of cookieValue (type casted to uint8), deletes the authentication result from the session using session.Delete(global.CookieAuthResult),
//	and saves the session.
//
// Finally, it returns the authentication result.
func processTOTPSecret(ctx *gin.Context, deps AuthDeps) definitions.AuthResult {
	authResult := definitions.AuthResultUnset
	guid := ctx.GetString(definitions.CtxGUIDKey)
	session := sessions.Default(ctx)

	totpSecret, totpCode, account := getSessionTOTPSecret(ctx)
	if totpSecret != "" && totpCode != "" && account != "" {
		if errFail := totpValidation(guid, totpCode, account, totpSecret, deps); errFail != nil {
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
// ctx: The Gin context.
// authResult: The result of the authentication.
// auth: The AuthState object.
func processAuthResult(ctx *gin.Context, authResult definitions.AuthResult, auth *AuthState, authCompleteWithOK bool, authCompleteWithFail bool, deps AuthDeps) {
	if authResult == definitions.AuthResultOK {
		if !authCompleteWithOK {
			if err := saveSessionData(ctx, authResult, auth); err != nil {
				HandleErrWithDeps(ctx, err, deps)

				return
			}
		}

		processTwoFARedirect(ctx, authCompleteWithOK, deps)
	} else if authResult == definitions.AuthResultFail {
		if !authCompleteWithFail {
			if err := saveSessionData(ctx, authResult, auth); err != nil {
				HandleErrWithDeps(ctx, err, deps)

				return
			}

			processTwoFARedirect(ctx, authCompleteWithFail, deps)

			return
		}

		handleAuthFailureAndRedirect(ctx, auth, deps)
	} else {
		handleAuthFailureAndRedirect(ctx, auth, deps)
	}
}

// processTwoFARedirect redirects the context to the 2FA login page with the appropriate target URI.
// It takes the Gin context and a boolean indicating whether the authentication was completed successfully as inputs.
// It initializes the `guid` variable with the context's GUID.
// It sets the `targetURI` to the appropriate URL based on the authentication complete status.
// It redirects the context to the `targetURI` with the HTTP status of `http.StatusFound`.
// It logs the redirect information with the `guid`, username, authentication status, and URI path.
func processTwoFARedirect(ctx *gin.Context, authComplete bool, deps AuthDeps) {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	targetURI := definitions.TwoFAv1Root + deps.Cfg.GetServer().Frontend.TwoFactorPage + "/home"
	if !authComplete {
		targetURI = definitions.TwoFAv1Root + deps.Cfg.GetServer().Frontend.TwoFactorPage
	}

	ctx.Redirect(http.StatusFound, targetURI)

	level.Info(deps.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUsername, ctx.PostForm("username"),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthAccept,
		definitions.LogKeyUriPath, targetURI,
	)
}

// saveSessionData handles the authentication result by setting session variables and redirecting to the 2FA page.
// It takes the Gin context, the authentication result, and the AuthState object as inputs.
// It initializes local variables, including `found`, `account`, `uniqueUserID`, `displayName`, and `totpSecret`.
// It retrieves the default session from the Gin context.
// It checks if the `account` is found and if not, calls the `HandleErr` function with the `ErrNoAccount` error and returns.
// If the TOTP secret is found, it sets the `CookieHaveTOTP` value in the session as true.
// If the `uniqueUserID` is found, it sets the `CookieUniqueUserID` value in the session.
// If the `displayName` is found, it sets the `CookieDisplayName` value in the session.
// It sets the `CookieAuthResult`, `CookieUsername`, `CookieAccount`, and `CookieUserBackend` values in the session based on the inputs.
// It saves the session and, if there is an error, calls the `HandleErr` function with the error and returns.
// It redirects the context to the 2FA page and logs the authentication result, GUID, username, and URI path.
//
// ctx: The Gin context.
// authResult: The result of the authentication.
// auth: The AuthState object.
func saveSessionData(ctx *gin.Context, authResult definitions.AuthResult, auth *AuthState) error {
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
	session.Set(definitions.CookieUserBackend, uint8(auth.SourcePassDBBackend))

	if err := session.Save(); err != nil {
		return err
	}

	return nil
}

// handleAuthFailureAndRedirect handles the authentication failure result by updating the brute force counter, redirecting
// the context to the 2FA page with the error message, and logging the authentication rejection information.
// It takes the Gin context and the AuthState object as inputs.
//
// ctx: The Gin context.
// auth: The AuthState object.
func handleAuthFailureAndRedirect(ctx *gin.Context, auth *AuthState, deps AuthDeps) {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	auth.ClientIP = ctx.GetString(definitions.CtxClientIPKey)

	auth.UpdateBruteForceBucketsCounter(ctx)

	sessionCleanupTOTP(ctx)

	ctx.Redirect(
		http.StatusFound,
		definitions.TwoFAv1Root+deps.Cfg.GetServer().Frontend.TwoFactorPage+"?_error="+definitions.PasswordFail,
	)

	level.Info(deps.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUsername, ctx.PostForm("username"),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthReject,
		definitions.LogKeyUriPath, definitions.TwoFAv1Root+deps.Cfg.GetServer().Frontend.TwoFactorPage+"/post",
	)
}

// sessionCleanupTOTP removes the TOTP secret and code from the current session.
func sessionCleanupTOTP(ctx *gin.Context) {
	session := sessions.Default(ctx)

	session.Delete(definitions.CookieTOTPSecret)
	session.Save()
}

// totpValidation calls the totpValidation method of the ApiConfig struct to validate a TOTP code for a given account.
func totpValidation(guid string, code string, account string, totpSecret string, deps AuthDeps) error {
	a := ApiConfig{guid: guid, deps: deps}

	return a.totpValidation(code, account, totpSecret)
}

// Register2FAHomeHandler Page '/2fa/v1/register/home'
func Register2FAHomeHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		Register2FAHomeHandlerWithDeps(ctx, deps)
	}
}

// Register2FAHomeHandlerWithDeps is the DI variant of Register2FAHomeHandler.
func Register2FAHomeHandlerWithDeps(ctx *gin.Context, deps AuthDeps) {
	var haveTOTP bool

	session := sessions.Default(ctx)

	cookieValue := session.Get(definitions.CookieHaveTOTP)
	if cookieValue != nil {
		haveTOTP = cookieValue.(bool)
	}

	cookieValue = session.Get(definitions.CookieAuthResult)
	if cookieValue == nil || definitions.AuthResult(cookieValue.(uint8)) != definitions.AuthResultOK {
		HandleErrWithDeps(ctx, errors.ErrNotLoggedIn, deps)

		return
	}

	cookieValue = session.Get(definitions.CookieAccount)
	if cookieValue == nil {
		HandleErrWithDeps(ctx, errors.ErrNoAccount, deps)

		return
	}

	session.Set(definitions.CookieHome, true)
	session.Save()

	cookieValue = session.Get(definitions.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(ctx, deps.Cfg, definitions.TwoFAv1Root+deps.Cfg.GetServer().Frontend.TwoFactorPage+"/post", config.DefaultLanguageTags, languageCurrentName)

	homeData := &frontend.HomePageData{
		Title: frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Home"),
		WantWelcome: func() bool {
			if deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
				return true
			}

			return false
		}(),
		HaveTOTP:            haveTOTP,
		Welcome:             deps.Cfg.GetServer().Frontend.GetLoginPageWelcome(),
		LogoImage:           deps.Cfg.GetServer().Frontend.GetDefaultLogoImage(),
		LogoImageAlt:        deps.Cfg.GetServer().Frontend.GetNotifyPageLogoImageAlt(), // Corrected
		HomeMessage:         frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Please make a selection"),
		RegisterTOTP:        frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Register TOTP"),
		EndpointTOTP:        definitions.TwoFAv1Root + deps.Cfg.GetServer().Frontend.TwoFactorPage, // Corrected
		Or:                  frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "or"),
		RegisterWebAuthn:    frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Register WebAuthn"),
		EndpointWebAuthn:    definitions.TwoFAv1Root + deps.Cfg.GetServer().Frontend.TwoFactorPage + "/webauthn", // Placeholder
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		InDevelopment:       tags.IsDevelopment,
	}

	ctx.HTML(http.StatusOK, "home.html", homeData)
}

// RegisterTotpGETHandler Page '/2fa/v1/totp'
func RegisterTotpGETHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		RegisterTotpGETHandlerWithDeps(ctx, deps)
	}
}

// RegisterTotpGETHandlerWithDeps is the DI variant of RegisterTotpGETHandler.
func RegisterTotpGETHandlerWithDeps(ctx *gin.Context, deps AuthDeps) {
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

			ctx.Redirect(http.StatusFound, deps.Cfg.GetServer().Frontend.GetNotifyPage()+"?message=You have already registered TOTP")

			return
		}
	}

	cookieValue = session.Get(definitions.CookieAuthResult)
	if cookieValue == nil || definitions.AuthResult(cookieValue.(uint8)) != definitions.AuthResultOK {
		HandleErrWithDeps(ctx, errors.ErrNotLoggedIn, deps)

		return
	}

	cookieValue = session.Get(definitions.CookieAccount)
	if cookieValue == nil {
		HandleErrWithDeps(ctx, errors.ErrNoAccount, deps)

		return
	}

	account := cookieValue.(string)

	totpURL := session.Get(definitions.CookieTOTPURL)
	if totpURL == nil {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      deps.Cfg.GetServer().Frontend.GetTotpIssuer(),
			AccountName: account,
		})

		if err != nil {
			HandleErrWithDeps(ctx, err, deps)

			return
		}

		totpURL = key.String()

		session.Set(definitions.CookieTOTPURL, totpURL.(string))
		session.Save()
	}

	cookieValue = session.Get(definitions.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(ctx, deps.Cfg, definitions.TwoFAv1Root+deps.Cfg.GetServer().Frontend.TwoFactorPage, config.DefaultLanguageTags, languageCurrentName)

	if errorMessage = ctx.Query("_error"); errorMessage != "" {
		if errorMessage == definitions.PasswordFail {
			errorMessage = frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, definitions.PasswordFail)
		}

		haveError = true
	}

	totpData := frontend.TOTPPageData{
		Title: frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Login"),
		WantWelcome: func() bool {
			if deps.Cfg.GetServer().Frontend.GetNotifyPageWelcome() != "" { // Reusing notify welcome
				return true
			}

			return false
		}(),
		Welcome:             deps.Cfg.GetServer().Frontend.GetNotifyPageWelcome(),
		LogoImage:           deps.Cfg.GetServer().Frontend.GetDefaultLogoImage(),
		LogoImageAlt:        deps.Cfg.GetServer().Frontend.GetNotifyPageLogoImageAlt(),
		HaveError:           haveError,
		ErrorMessage:        errorMessage,
		TOTPMessage:         frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Please scan and verify the following QR code"),
		TOTPCopied:          frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Copied to clipboard!"),
		Code:                frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "OTP-Code"),
		Submit:              frontend.GetLocalized(ctx, deps.Cfg, deps.Logger, "Submit"),
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		WantTos:             false,
		WantPolicy:          false,
		CSRFToken:           csrfToken,
		QRCode:              totpURL.(string),
		PostTOTPEndpoint:    definitions.TwoFAv1Root + deps.Cfg.GetServer().Frontend.TwoFactorPage,
	}

	ctx.HTML(http.StatusOK, "regtotp.html", totpData)
}

// RegisterTotpPOSTHandler Page '/2fa/v1/totp/post'
func RegisterTotpPOSTHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		RegisterTotpPOSTHandlerWithDeps(ctx, deps)
	}
}

// RegisterTotpPOSTHandlerWithDeps is the DI variant of RegisterTotpPOSTHandler.
func RegisterTotpPOSTHandlerWithDeps(ctx *gin.Context, deps AuthDeps) {
	var (
		accountName   string
		err           error
		totpKey       *otp.Key
		guid          = ctx.GetString(definitions.CtxGUIDKey)
		addTOTPSecret AddTOTPSecretFunc
	)

	session := sessions.Default(ctx)

	cookieValue := session.Get(definitions.CookieTOTPURL)
	if cookieValue == nil {
		HandleErrWithDeps(ctx, errors.ErrNoTOTPURL, deps)

		return
	}

	if totpKey, err = otp.NewKeyFromURL(cookieValue.(string)); err != nil {
		HandleErrWithDeps(ctx, err, deps)

		return
	}

	if deps.Cfg.GetServer().GetLog().GetLogLevel() >= definitions.LogLevelDebug && deps.Env.GetDevMode() {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			deps.Cfg,
			deps.Logger,
			definitions.DbgWebAuthn,
			definitions.LogKeyGUID, guid,
			"totp_key", fmt.Sprintf("%+v", totpKey),
		)
	}

	if !totp.Validate(ctx.PostForm("code"), totpKey.Secret()) {
		var sb strings.Builder

		sb.WriteString(definitions.TwoFAv1Root)
		sb.WriteString(deps.Cfg.GetServer().Frontend.TwoFactorPage)
		sb.WriteString("?_error=")
		sb.WriteString(definitions.InvalidCode)

		ctx.Redirect(http.StatusFound, sb.String())

		var sbLog strings.Builder

		sbLog.WriteString(definitions.TwoFAv1Root)
		sbLog.WriteString(deps.Cfg.GetServer().Frontend.TwoFactorPage)
		sbLog.WriteString("/post")

		level.Info(deps.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyUsername, ctx.PostForm("username"),
			definitions.LogKeyAuthStatus, definitions.LogKeyAuthReject,
			definitions.LogKeyUriPath, sbLog.String(),
		)

		return
	}

	username := session.Get(definitions.CookieUsername).(string)

	auth := &AuthState{
		deps:              deps,
		HTTPClientContext: ctx,
		HTTPClientRequest: ctx.Request,
		GUID:              guid,
		Username:          username,
		Protocol:          config.NewProtocol(definitions.ProtoOryHydra),
	}

	sourceBackend := session.Get(definitions.CookieUserBackend)

	switch sourceBackend.(uint8) {
	case uint8(definitions.BackendLDAP):
		// We have no mapping to an optional LDAP pool!
		addTOTPSecret = NewLDAPManager(definitions.DefaultBackendName, deps).AddTOTPSecret
	case uint8(definitions.BackendLua):
		// We have no mapping to an optional Lua backend!
		addTOTPSecret = NewLuaManager(definitions.DefaultBackendName, deps).AddTOTPSecret
	default:
		HandleErrWithDeps(ctx, errors.NewDetailedError("unsupported_backend").WithDetail(
			"Database backend not supported"), deps)

		return
	}

	if err = addTOTPSecret(auth, NewTOTPSecret(totpKey.Secret())); err != nil {
		HandleErrWithDeps(ctx, err, deps)

		return
	}

	/*
		Purge user from positive redis caches
	*/

	useCache := false
	for _, backendType := range deps.Cfg.GetServer().GetBackends() {
		if backendType.Get() == definitions.BackendCache {
			useCache = true

			break
		}
	}

	if useCache {
		userKeys := config.NewStringSet()
		protocols := deps.Cfg.GetAllProtocols()

		accountName, err = backend.LookupUserAccountFromRedis(auth.Ctx(), deps.Cfg, deps.Redis, username)
		if err != nil {
			HandleErrWithDeps(ctx, err, deps)

			return
		}

		for index := range protocols {
			cacheNames := backend.GetCacheNames(deps.Cfg, deps.Channel, protocols[index], definitions.CacheAll)

			for _, cacheName := range cacheNames.GetStringSlice() {
				var sb strings.Builder

				sb.WriteString(deps.Cfg.GetServer().GetRedis().GetPrefix())
				sb.WriteString(definitions.RedisUserPositiveCachePrefix)
				sb.WriteString(cacheName)
				sb.WriteByte(':')
				sb.WriteString(accountName)

				userKeys.Set(sb.String())
			}
		}

		// Remove current user from cache to enforce refreshing it.
		for _, userKey := range userKeys.GetStringSlice() {
			if _, err = deps.Redis.GetWriteHandle().Del(auth.Ctx(), userKey).Result(); err != nil {
				stats.GetMetrics().GetRedisWriteCounter().Inc()

				level.Error(deps.Logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "Failed to purge user from cache",
					definitions.LogKeyError, err,
				)

				break
			} else {
				stats.GetMetrics().GetRedisWriteCounter().Inc()
			}
		}
	}

	// POST cleanup
	sessionCleaner(ctx)

	// Log out user
	session.Delete(definitions.CookieHome)
	session.Save()

	var sbRedirect strings.Builder

	sbRedirect.WriteString(deps.Cfg.GetServer().Frontend.GetNotifyPage())
	sbRedirect.WriteString("?message=OTP code is valid. Registration completed successfully")

	ctx.Redirect(http.StatusFound, sbRedirect.String())

	var sbLog strings.Builder

	sbLog.WriteString(definitions.TwoFAv1Root)
	sbLog.WriteString(deps.Cfg.GetServer().Frontend.TwoFactorPage)
	sbLog.WriteString("/post")

	level.Info(deps.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUsername, username,
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthAccept,
		definitions.LogKeyUriPath, sbLog.String(),
	)
}
