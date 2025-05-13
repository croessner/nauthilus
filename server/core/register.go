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
	"fmt"
	"net/http"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/tags"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/viper"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

type TOTPPageData struct {
	WantWelcome         bool
	WantPolicy          bool
	WantTos             bool
	HaveError           bool
	Title               string
	Welcome             string
	LogoImage           string
	LogoImageAlt        string
	TOTPMessage         string
	TOTPCopied          string
	Code                string
	Submit              string
	ErrorMessage        string
	CSRFToken           string
	QRCode              string
	PostTOTPEndpoint    string
	LanguageTag         string
	LanguageCurrentName string
	LanguagePassive     []Language
}

type HomePageData struct {
	InDevelopment       bool
	WantWelcome         bool
	WantPolicy          bool
	WantTos             bool
	HaveTOTP            bool
	Title               string
	Welcome             string
	LogoImage           string
	LogoImageAlt        string
	HomeMessage         string
	RegisterTOTP        string
	EndpointTOTP        string
	Or                  string
	RegisterWebAuthn    string
	EndpointWebAuthn    string
	LanguageTag         string
	LanguageCurrentName string
	LanguagePassive     []Language
}

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
func LoginGET2FAHandler(ctx *gin.Context) {
	session := sessions.Default(ctx)

	cookieValue := session.Get(definitions.CookieLang)
	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(ctx, definitions.TwoFAv1Root+viper.GetString("login_2fa_page"), config.DefaultLanguageTags, languageCurrentName)

	totpSecret, _, _ := getSessionTOTPSecret(ctx)
	if totpSecret == "" {
		sessionCleaner(ctx)
		displayLoginpage(ctx, languageCurrentName, languagePassive)
	} else {
		cookieValue = session.Get(definitions.CookieHome)
		if cookieValue != nil {
			if loggedIn, assertOk := cookieValue.(bool); assertOk && loggedIn {
				processTwoFARedirect(ctx, true)

				return
			}
		}

		displayTOTPpage(ctx, languageCurrentName, languagePassive)
	}
}

// displayLoginpage is a function that displays the login page.
func displayLoginpage(ctx *gin.Context, languageCurrentName string, languagePassive []Language) {
	var (
		haveError    bool
		errorMessage string
		guid         = ctx.GetString(definitions.CtxGUIDKey)
		csrfToken    = ctx.GetString(definitions.CtxCSRFTokenKey)
	)

	session := sessions.Default(ctx)

	if errorMessage = ctx.Query("_error"); errorMessage != "" {
		if errorMessage == definitions.PasswordFail {
			errorMessage = getLocalized(ctx, definitions.PasswordFail)
		}

		haveError = true
	}

	// Using data structure from hydra.go
	loginData := &LoginPageData{
		Title: getLocalized(ctx, "Login"),
		WantWelcome: func() bool {
			if viper.GetString("login_page_welcome") != "" {
				return true
			}

			return false
		}(),
		Welcome:             viper.GetString("login_page_welcome"),
		LogoImage:           viper.GetString("default_logo_image"),
		LogoImageAlt:        viper.GetString("login_page_logo_image_alt"),
		HaveError:           haveError,
		ErrorMessage:        errorMessage,
		Login:               getLocalized(ctx, "Login"),
		Privacy:             getLocalized(ctx, "We'll never share your data with anyone else."),
		LoginPlaceholder:    getLocalized(ctx, "Please enter your username or email address"),
		Password:            getLocalized(ctx, "Password"),
		PasswordPlaceholder: getLocalized(ctx, "Please enter your password"),
		Submit:              getLocalized(ctx, "Submit"),
		Or:                  getLocalized(ctx, "or"),
		Device:              getLocalized(ctx, "Login with WebAuthn"),
		PostLoginEndpoint:   definitions.TwoFAv1Root + viper.GetString("login_2fa_page"),
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
		InDevelopment:       tags.IsDevelopment,
	}

	ctx.HTML(http.StatusOK, "login.html", loginData)

	level.Info(log.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUriPath, definitions.TwoFAv1Root+viper.GetString("login_2fa_page"),
	)
}

// displayTOTPpage displays the TOTP authentication page.
// It takes a Gin context, the current language name, and a slice of passive languages as input.
// It retrieves the CSRF token, session, and localized messages from the context.
// It constructs a TwoFactorData struct with the necessary parameters for the TOTP page.
// Finally, it renders the TOTP page template with the TwoFactorData struct.
func displayTOTPpage(ctx *gin.Context, languageCurrentName string, languagePassive []Language) {
	csrfToken := ctx.GetString(definitions.CtxCSRFTokenKey)
	session := sessions.Default(ctx)

	twoFactorData := &TwoFactorData{
		Title: getLocalized(ctx, "Login"),
		WantWelcome: func() bool {
			if viper.GetString("login_page_welcome") != "" {
				return true
			}

			return false
		}(),
		Welcome:             viper.GetString("login_page_welcome"),
		LogoImage:           viper.GetString("default_logo_image"),
		LogoImageAlt:        viper.GetString("totp_page_logo_image_alt"),
		Code:                getLocalized(ctx, "OTP-Code"),
		Tos:                 getLocalized(ctx, "Terms of service"),
		Submit:              getLocalized(ctx, "Submit"),
		PostLoginEndpoint:   definitions.TwoFAv1Root + viper.GetString("login_2fa_page"),
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
func LoginPOST2FAHandler(ctx *gin.Context) {
	var (
		authCompleteWithOK   bool
		authCompleteWithFail bool
		guid                 = ctx.GetString(definitions.CtxGUIDKey)
	)

	authResult := processTOTPSecret(ctx)

	if authResult == definitions.AuthResultOK {
		authCompleteWithOK = true
	}

	if authResult == definitions.AuthResultFail {
		authCompleteWithFail = true
	}

	auth := &AuthState{
		HTTPClientContext: ctx.Copy(),
		GUID:              &guid,
		Username:          ctx.PostForm("username"),
		Password:          ctx.PostForm("password"),
		Protocol:          config.NewProtocol(definitions.ProtoOryHydra),
	}

	// It might be the second call after 2FA! In this case, there does not exist any username or password.
	if auth.Username != "" && !util.ValidateUsername(auth.Username) {
		HandleErr(ctx, errors.ErrInvalidUsername)

		return
	}

	auth.SetStatusCodes(definitions.ServOryHydra)
	auth.WithDefaults(ctx).WithClientInfo(ctx).WithLocalInfo(ctx).WithUserAgent(ctx).WithXSSL(ctx)

	if reject := auth.PreproccessAuthRequest(ctx); reject {
		HandleErr(ctx, errors.ErrBruteForceAttack)

		return
	}

	if authResult == definitions.AuthResultUnset {
		authResult = auth.HandlePassword(ctx)

		// User does not have a TOTP secret
		if _, found := auth.GetTOTPSecretOk(); !found {
			if authResult == definitions.AuthResultOK {
				tolerate.GetTolerate().SetIPAddress(ctx, auth.ClientIP, auth.Username, true)
				authCompleteWithOK = true
			}

			if authResult == definitions.AuthResultFail {
				tolerate.GetTolerate().SetIPAddress(ctx, auth.ClientIP, auth.Username, false)
				authCompleteWithFail = true
			}
		}
	}

	processAuthResult(ctx, authResult, auth, authCompleteWithOK, authCompleteWithFail)
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
func processTOTPSecret(ctx *gin.Context) definitions.AuthResult {
	authResult := definitions.AuthResultUnset
	guid := ctx.GetString(definitions.CtxGUIDKey)
	session := sessions.Default(ctx)

	totpSecret, totpCode, account := getSessionTOTPSecret(ctx)
	if totpSecret != "" && totpCode != "" && account != "" {
		if errFail := totpValidation(guid, totpCode, account, totpSecret); errFail != nil {
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
func processAuthResult(ctx *gin.Context, authResult definitions.AuthResult, auth *AuthState, authCompleteWithOK bool, authCompleteWithFail bool) {
	if authResult == definitions.AuthResultOK {
		if !authCompleteWithOK {
			if err := saveSessionData(ctx, authResult, auth); err != nil {
				HandleErr(ctx, err)

				return
			}
		}

		processTwoFARedirect(ctx, authCompleteWithOK)
	} else if authResult == definitions.AuthResultFail {
		if !authCompleteWithFail {
			if err := saveSessionData(ctx, authResult, auth); err != nil {
				HandleErr(ctx, err)

				return
			}

			processTwoFARedirect(ctx, authCompleteWithFail)

			return
		}

		handleAuthFailureAndRedirect(ctx, auth)
	} else {
		handleAuthFailureAndRedirect(ctx, auth)
	}
}

// processTwoFARedirect redirects the context to the 2FA login page with the appropriate target URI.
// It takes the Gin context and a boolean indicating whether the authentication was completed successfully as inputs.
// It initializes the `guid` variable with the context's GUID.
// It sets the `targetURI` to the appropriate URL based on the authentication complete status.
// It redirects the context to the `targetURI` with the HTTP status of `http.StatusFound`.
// It logs the redirect information with the `guid`, username, authentication status, and URI path.
func processTwoFARedirect(ctx *gin.Context, authComplete bool) {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	targetURI := definitions.TwoFAv1Root + viper.GetString("login_2fa_post_page")
	if !authComplete {
		targetURI = definitions.TwoFAv1Root + viper.GetString("login_2fa_page")
	}

	ctx.Redirect(http.StatusFound, targetURI)

	level.Info(log.Logger).Log(
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
func handleAuthFailureAndRedirect(ctx *gin.Context, auth *AuthState) {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	auth.ClientIP = ctx.GetString(definitions.CtxClientIPKey)

	auth.UpdateBruteForceBucketsCounter()

	sessionCleanupTOTP(ctx)

	ctx.Redirect(
		http.StatusFound,
		definitions.TwoFAv1Root+viper.GetString("login_2fa_page")+"?_error="+definitions.PasswordFail,
	)

	level.Info(log.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUsername, ctx.PostForm("username"),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthReject,
		definitions.LogKeyUriPath, definitions.TwoFAv1Root+viper.GetString("login_2fa_page")+"/post",
	)
}

// sessionCleanupTOTP removes the TOTP secret and code from the current session.
func sessionCleanupTOTP(ctx *gin.Context) {
	session := sessions.Default(ctx)

	session.Delete(definitions.CookieTOTPSecret)
	session.Save()
}

// totpValidation calls the totpValidation method of the ApiConfig struct to validate a TOTP code for a given account.
func totpValidation(guid string, code string, account string, totpSecret string) error {
	a := ApiConfig{guid: guid}

	return a.totpValidation(code, account, totpSecret)
}

// Register2FAHomeHandler Page '/2fa/v1/register/home'
func Register2FAHomeHandler(ctx *gin.Context) {
	var haveTOTP bool

	session := sessions.Default(ctx)

	cookieValue := session.Get(definitions.CookieHaveTOTP)
	if cookieValue != nil {
		haveTOTP = cookieValue.(bool)
	}

	cookieValue = session.Get(definitions.CookieAuthResult)
	if cookieValue == nil || definitions.AuthResult(cookieValue.(uint8)) != definitions.AuthResultOK {
		HandleErr(ctx, errors.ErrNotLoggedIn)

		return
	}

	cookieValue = session.Get(definitions.CookieAccount)
	if cookieValue == nil {
		HandleErr(ctx, errors.ErrNoAccount)

		return
	}

	session.Set(definitions.CookieHome, true)
	session.Save()

	cookieValue = session.Get(definitions.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(ctx, definitions.TwoFAv1Root+viper.GetString("login_2fa_post_page"), config.DefaultLanguageTags, languageCurrentName)

	homeData := &HomePageData{
		Title: getLocalized(ctx, "Home"),
		WantWelcome: func() bool {
			if viper.GetString("home_page_welcome") != "" {
				return true
			}

			return false
		}(),
		HaveTOTP:            haveTOTP,
		Welcome:             viper.GetString("home_page_welcome"),
		LogoImage:           viper.GetString("default_logo_image"),
		LogoImageAlt:        viper.GetString("home_page_logo_image_alt"),
		HomeMessage:         getLocalized(ctx, "Please make a selection"),
		RegisterTOTP:        getLocalized(ctx, "Register TOTP"),
		EndpointTOTP:        definitions.TwoFAv1Root + viper.GetString("totp_page"),
		Or:                  getLocalized(ctx, "or"),
		RegisterWebAuthn:    getLocalized(ctx, "Register WebAuthn"),
		EndpointWebAuthn:    definitions.TwoFAv1Root + viper.GetString("webauthn_page"),
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		InDevelopment:       tags.IsDevelopment,
	}

	ctx.HTML(http.StatusOK, "home.html", homeData)
}

// RegisterTotpGETHandler Page '/2fa/v1/totp'
func RegisterTotpGETHandler(ctx *gin.Context) {
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

			ctx.Redirect(http.StatusFound, viper.GetString("notify_page")+"?message=You have already registered TOTP")

			return
		}
	}

	cookieValue = session.Get(definitions.CookieAuthResult)
	if cookieValue == nil || definitions.AuthResult(cookieValue.(uint8)) != definitions.AuthResultOK {
		HandleErr(ctx, errors.ErrNotLoggedIn)

		return
	}

	cookieValue = session.Get(definitions.CookieAccount)
	if cookieValue == nil {
		HandleErr(ctx, errors.ErrNoAccount)

		return
	}

	account := cookieValue.(string)

	totpURL := session.Get(definitions.CookieTOTPURL)
	if totpURL == nil {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      viper.GetString("totp_issuer"),
			AccountName: account,
		})

		if err != nil {
			HandleErr(ctx, err)

			return
		}

		totpURL = key.String()

		session.Set(definitions.CookieTOTPURL, totpURL.(string))
		session.Save()
	}

	cookieValue = session.Get(definitions.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(ctx, definitions.TwoFAv1Root+viper.GetString("totp_page"), config.DefaultLanguageTags, languageCurrentName)

	if errorMessage = ctx.Query("_error"); errorMessage != "" {
		if errorMessage == definitions.PasswordFail {
			errorMessage = getLocalized(ctx, definitions.PasswordFail)
		}

		haveError = true
	}

	totpData := TOTPPageData{
		Title: getLocalized(ctx, "Login"),
		WantWelcome: func() bool {
			if viper.GetString("totp_page_welcome") != "" {
				return true
			}

			return false
		}(),
		Welcome:             viper.GetString("totp_page_welcome"),
		LogoImage:           viper.GetString("default_logo_image"),
		LogoImageAlt:        viper.GetString("totp_page_logo_image_alt"),
		HaveError:           haveError,
		ErrorMessage:        errorMessage,
		TOTPMessage:         getLocalized(ctx, "Please scan and verify the following QR code"),
		TOTPCopied:          getLocalized(ctx, "Copied to clipboard!"),
		Code:                getLocalized(ctx, "OTP-Code"),
		Submit:              getLocalized(ctx, "Submit"),
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		WantTos:             false,
		WantPolicy:          false,
		CSRFToken:           csrfToken,
		QRCode:              totpURL.(string),
		PostTOTPEndpoint:    definitions.TwoFAv1Root + viper.GetString("totp_page"),
	}

	ctx.HTML(http.StatusOK, "regtotp.html", totpData)
}

// RegisterTotpPOSTHandler Page '/2fa/v1/totp/post'
func RegisterTotpPOSTHandler(ctx *gin.Context) {
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
		HandleErr(ctx, errors.ErrNoTOTPURL)

		return
	}

	if totpKey, err = otp.NewKeyFromURL(cookieValue.(string)); err != nil {
		HandleErr(ctx, err)

		return
	}

	if config.GetFile().GetServer().GetLog().GetLogLevel() >= definitions.LogLevelDebug && config.GetEnvironment().GetDevMode() {
		util.DebugModule(
			definitions.DbgWebAuthn,
			definitions.LogKeyGUID, guid,
			"totp_key", fmt.Sprintf("%+v", totpKey),
		)
	}

	if !totp.Validate(ctx.PostForm("code"), totpKey.Secret()) {
		ctx.Redirect(
			http.StatusFound,
			definitions.TwoFAv1Root+viper.GetString("totp_page")+"?_error="+definitions.InvalidCode,
		)

		level.Info(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyUsername, ctx.PostForm("username"),
			definitions.LogKeyAuthStatus, definitions.LogKeyAuthReject,
			definitions.LogKeyUriPath, definitions.TwoFAv1Root+viper.GetString("totp_page")+"/post",
		)

		return
	}

	username := session.Get(definitions.CookieUsername).(string)

	auth := &AuthState{
		HTTPClientContext: ctx.Copy(),
		GUID:              &guid,
		Username:          username,
		Protocol:          config.NewProtocol(definitions.ProtoOryHydra),
	}

	sourceBackend := session.Get(definitions.CookieUserBackend)

	switch sourceBackend.(uint8) {
	case uint8(definitions.BackendLDAP):
		// We have no mapping to an optional LDAP pool!
		addTOTPSecret = NewLDAPManager(definitions.DefaultBackendName).AddTOTPSecret
	case uint8(definitions.BackendLua):
		// We have no mapping to an optional Lua backend!
		addTOTPSecret = NewLuaManager(definitions.DefaultBackendName).AddTOTPSecret
	default:
		HandleErr(ctx, errors.NewDetailedError("unsupported_backend").WithDetail(
			"Database backend not supported"))

		return
	}

	if err = addTOTPSecret(auth, NewTOTPSecret(totpKey.Secret())); err != nil {
		HandleErr(ctx, err)

		return
	}

	/*
		Purge user from positive redis caches
	*/

	useCache := false
	for _, backendType := range config.GetFile().GetServer().GetBackends() {
		if backendType.Get() == definitions.BackendCache {
			useCache = true

			break
		}
	}

	if useCache {
		userKeys := config.NewStringSet()
		protocols := config.GetFile().GetAllProtocols()

		accountName, err = backend.LookupUserAccountFromRedis(ctx, username)
		if err != nil {
			HandleErr(ctx, err)

			return
		}

		for index := range protocols {
			cacheNames := backend.GetCacheNames(protocols[index], definitions.CacheAll)

			for _, cacheName := range cacheNames.GetStringSlice() {
				userKeys.Set(config.GetFile().GetServer().GetRedis().GetPrefix() + definitions.RedisUserPositiveCachePrefix + cacheName + ":" + accountName)
			}
		}

		// Remove current user from cache to enforce refreshing it.
		for _, userKey := range userKeys.GetStringSlice() {
			if _, err = rediscli.GetClient().GetWriteHandle().Del(ctx, userKey).Result(); err != nil {
				stats.GetMetrics().GetRedisWriteCounter().Inc()

				level.Error(log.Logger).Log(definitions.LogKeyGUID, guid, definitions.LogKeyMsg, err)

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

	ctx.Redirect(http.StatusFound, viper.GetString("notify_page")+"?message=OTP code is valid. Registration completed successfully")

	level.Info(log.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeyUsername, ctx.PostForm("username"),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthAccept,
		definitions.LogKeyUriPath, definitions.TwoFAv1Root+viper.GetString("totp_page")+"/post",
	)
}
