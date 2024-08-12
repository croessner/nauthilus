package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/tags"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
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
	session.Delete(global.CookieAuthResult)
	session.Delete(global.CookieUsername)
	session.Delete(global.CookieAccount)
	session.Delete(global.CookieHaveTOTP)
	session.Delete(global.CookieTOTPURL)
	session.Delete(global.CookieUserBackend)
	session.Delete(global.CookieUniqueUserID)
	session.Delete(global.CookieDisplayName)
	session.Delete(global.CookieRegistration)

	session.Save()
}

// Page '/2fa/v1/register'
func loginGET2FAHandler(ctx *gin.Context) {
	session := sessions.Default(ctx)

	cookieValue := session.Get(global.CookieLang)
	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(ctx, global.TwoFAv1Root+viper.GetString("login_2fa_page"), config.DefaultLanguageTags, languageCurrentName)

	totpSecret, _, _ := getSessionTOTPSecret(ctx)
	if totpSecret == "" {
		sessionCleaner(ctx)
		displayLoginpage(ctx, languageCurrentName, languagePassive)
	} else {
		cookieValue = session.Get(global.CookieHome)
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
		guid         = ctx.GetString(global.CtxGUIDKey)
		csrfToken    = ctx.GetString(global.CtxCSRFTokenKey)
	)

	session := sessions.Default(ctx)

	if errorMessage = ctx.Query("_error"); errorMessage != "" {
		if errorMessage == global.PasswordFail {
			errorMessage = getLocalized(ctx, global.PasswordFail)
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
		PostLoginEndpoint:   global.TwoFAv1Root + viper.GetString("login_2fa_page"),
		LanguageTag:         session.Get(global.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
		InDevelopment:       tags.IsDevelopment,
	}

	ctx.HTML(http.StatusOK, "login.html", loginData)

	level.Info(logging.Logger).Log(
		global.LogKeyGUID, guid,
		global.LogKeyUriPath, global.TwoFAv1Root+viper.GetString("login_2fa_page"),
	)
}

// displayTOTPpage displays the TOTP authentication page.
// It takes a Gin context, the current language name, and a slice of passive languages as input.
// It retrieves the CSRF token, session, and localized messages from the context.
// It constructs a TwoFactorData struct with the necessary parameters for the TOTP page.
// Finally, it renders the TOTP page template with the TwoFactorData struct.
func displayTOTPpage(ctx *gin.Context, languageCurrentName string, languagePassive []Language) {
	csrfToken := ctx.GetString(global.CtxCSRFTokenKey)
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
		PostLoginEndpoint:   global.TwoFAv1Root + viper.GetString("login_2fa_page"),
		LanguageTag:         session.Get(global.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
	}

	ctx.HTML(http.StatusOK, "totp.html", twoFactorData)
}

// getSessionTOTPSecret retrieves the TOTP secret and code from the session and the POST form, respectively.
// It takes a Gin context as input, and returns the TOTP secret and code as strings.
// The function initializes the variables totpSecret, totpCode, and account as empty strings.
// It retrieves the TOTP secret from the session using sessions.Default(ctx) and session.Get(global.CookieTOTPSecret).
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

	if value, assertOk := session.Get(global.CookieTOTPSecret).(string); assertOk {
		totpSecret = value
	}

	if value, assertOk := session.Get(global.CookieAccount).(string); assertOk {
		account = value
	}

	totpCode = ctx.PostForm("code")

	return totpSecret, totpCode, account
}

// Page '/2fa/v1/register/post'
func loginPOST2FAHandler(ctx *gin.Context) {
	var (
		authCompleteWithOK   bool
		authCompleteWithFail bool
		err                  error
		guid                 = ctx.GetString(global.CtxGUIDKey)
	)

	authResult := processTOTPSecret(ctx)

	if authResult == global.AuthResultOK {
		authCompleteWithOK = true
	}

	if authResult == global.AuthResultFail {
		authCompleteWithFail = true
	}

	auth := &AuthState{
		HTTPClientContext: ctx.Copy(),
		GUID:              &guid,
		Username:          ctx.PostForm("username"),
		Password:          ctx.PostForm("password"),
		Protocol:          config.NewProtocol(global.ProtoOryHydra),
	}

	// It might be the second call after 2FA! In this case, there does not exist any username or password.
	if auth.Username != "" && !util.ValidateUsername(auth.Username) {
		handleErr(ctx, errors2.ErrInvalidUsername)

		return
	}

	if err = auth.setStatusCodes(global.ServOryHydra); err != nil {
		handleErr(ctx, err)

		return
	}

	auth.withDefaults(ctx).withClientInfo(ctx).withLocalInfo(ctx).withUserAgent(ctx).withXSSL(ctx)

	if found, reject := auth.preproccessAuthRequest(ctx); reject {
		handleErr(ctx, errors2.ErrBruteForceAttack)

		return
	} else if found {
		auth.withClientInfo(ctx).withLocalInfo(ctx).withUserAgent(ctx).withXSSL(ctx)
	}

	if authResult == global.AuthResultUnset {
		authResult = auth.handlePassword(ctx)

		// User does not have a TOTP secret
		if _, found := auth.getTOTPSecretOk(); !found {
			if authResult == global.AuthResultOK {
				authCompleteWithOK = true
			}

			if authResult == global.AuthResultFail {
				authCompleteWithFail = true
			}
		}
	}

	processAuthResult(ctx, authResult, auth, authCompleteWithOK, authCompleteWithFail)
}

// processTOTPSecret retrieves the TOTP secret and code from the session and the POST form, respectively.
// It takes a Gin context as input, and returns the authentication result as global.AuthResult.
// The function initializes the authentication result as global.AuthResultUnset.
// It retrieves the GUID from the Gin context using ctx.GetString(global.CtxGUIDKey).
// It retrieves the session using sessions.Default(ctx).
// It calls getSessionTOTPSecret(ctx) to get the TOTP secret, TOTP code, and account.
// If the TOTP secret, TOTP code, and account are not empty, it calls totpValidation(guid, totpCode, account, totpSecret)
//
//	to validate the TOTP code.
//
// If the validation fails (i.e., errFail is not nil), it sets the authentication result as global.AuthResultFail.
// Otherwise, it retrieves the authentication result from the session using session.Get(global.CookieAuthResult).
// If the authentication result is not nil (i.e., cookieValue is not nil), it sets the authentication result as the value
//
//	of cookieValue (type casted to uint8), deletes the authentication result from the session using session.Delete(global.CookieAuthResult),
//	and saves the session.
//
// Finally, it returns the authentication result.
func processTOTPSecret(ctx *gin.Context) global.AuthResult {
	authResult := global.AuthResultUnset
	guid := ctx.GetString(global.CtxGUIDKey)
	session := sessions.Default(ctx)

	totpSecret, totpCode, account := getSessionTOTPSecret(ctx)
	if totpSecret != "" && totpCode != "" && account != "" {
		if errFail := totpValidation(guid, totpCode, account, totpSecret); errFail != nil {
			authResult = global.AuthResultFail
		} else {
			cookieValue := session.Get(global.CookieAuthResult)
			if cookieValue != nil {
				authResult = global.AuthResult(cookieValue.(uint8))
			}
		}
	}

	return authResult
}

// processAuthResult handles the authentication result by calling the respective handler functions based on the authResult value
// ctx: The Gin context.
// authResult: The result of the authentication.
// auth: The AuthState object.
func processAuthResult(ctx *gin.Context, authResult global.AuthResult, auth *AuthState, authCompleteWithOK bool, authCompleteWithFail bool) {
	if authResult == global.AuthResultOK {
		if !authCompleteWithOK {
			if err := saveSessionData(ctx, authResult, auth); err != nil {
				handleErr(ctx, err)

				return
			}
		}

		processTwoFARedirect(ctx, authCompleteWithOK)
	} else if authResult == global.AuthResultFail {
		if !authCompleteWithFail {
			if err := saveSessionData(ctx, authResult, auth); err != nil {
				handleErr(ctx, err)

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
	guid := ctx.GetString(global.CtxGUIDKey)

	targetURI := global.TwoFAv1Root + viper.GetString("login_2fa_post_page")
	if !authComplete {
		targetURI = global.TwoFAv1Root + viper.GetString("login_2fa_page")
	}

	ctx.Redirect(http.StatusFound, targetURI)

	level.Info(logging.Logger).Log(
		global.LogKeyGUID, guid,
		global.LogKeyUsername, ctx.PostForm("username"),
		global.LogKeyAuthStatus, global.LogKeyAuthAccept,
		global.LogKeyUriPath, targetURI,
	)
}

// saveSessionData handles the authentication result by setting session variables and redirecting to the 2FA page.
// It takes the Gin context, the authentication result, and the AuthState object as inputs.
// It initializes local variables, including `found`, `account`, `uniqueUserID`, `displayName`, and `totpSecret`.
// It retrieves the default session from the Gin context.
// It checks if the `account` is found and if not, calls the `handleErr` function with the `ErrNoAccount` error and returns.
// If the TOTP secret is found, it sets the `CookieHaveTOTP` value in the session as true.
// If the `uniqueUserID` is found, it sets the `CookieUniqueUserID` value in the session.
// If the `displayName` is found, it sets the `CookieDisplayName` value in the session.
// It sets the `CookieAuthResult`, `CookieUsername`, `CookieAccount`, and `CookieUserBackend` values in the session based on the inputs.
// It saves the session and, if there is an error, calls the `handleErr` function with the error and returns.
// It redirects the context to the 2FA page and logs the authentication result, GUID, username, and URI path.
//
// ctx: The Gin context.
// authResult: The result of the authentication.
// auth: The AuthState object.
func saveSessionData(ctx *gin.Context, authResult global.AuthResult, auth *AuthState) error {
	var (
		found        bool
		account      string
		uniqueUserID string
		displayName  string
		totpSecret   string
	)

	session := sessions.Default(ctx)

	if account, found = auth.getAccountOk(); !found {
		return errors2.ErrNoAccount
	}

	if totpSecret, found = auth.getTOTPSecretOk(); found {
		session.Set(global.CookieHaveTOTP, true)
		session.Set(global.CookieTOTPSecret, totpSecret)
	}

	if uniqueUserID, found = auth.GetUniqueUserIDOk(); found {
		session.Set(global.CookieUniqueUserID, uniqueUserID)
	}

	if displayName, found = auth.GetDisplayNameOk(); found {
		session.Set(global.CookieDisplayName, displayName)
	}

	session.Set(global.CookieAuthResult, uint8(authResult))
	session.Set(global.CookieUsername, ctx.PostForm("username"))
	session.Set(global.CookieAccount, account)
	session.Set(global.CookieUserBackend, uint8(auth.SourcePassDBBackend))

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
	guid := ctx.GetString(global.CtxGUIDKey)

	auth.ClientIP = ctx.GetString(global.CtxClientIPKey)

	auth.updateBruteForceBucketsCounter()

	sessionCleanupTOTP(ctx)

	ctx.Redirect(
		http.StatusFound,
		global.TwoFAv1Root+viper.GetString("login_2fa_page")+"?_error="+global.PasswordFail,
	)

	level.Info(logging.Logger).Log(
		global.LogKeyGUID, guid,
		global.LogKeyUsername, ctx.PostForm("username"),
		global.LogKeyAuthStatus, global.LogKeyAuthReject,
		global.LogKeyUriPath, global.TwoFAv1Root+viper.GetString("login_2fa_page")+"/post",
	)
}

// sessionCleanupTOTP removes the TOTP secret and code from the current session.
func sessionCleanupTOTP(ctx *gin.Context) {
	session := sessions.Default(ctx)

	session.Delete(global.CookieTOTPSecret)
	session.Save()
}

// totpValidation calls the totpValidation method of the ApiConfig struct to validate a TOTP code for a given account.
func totpValidation(guid string, code string, account string, totpSecret string) error {
	a := ApiConfig{guid: guid}

	return a.totpValidation(code, account, totpSecret)
}

// Page '/2fa/v1/register/home'
func register2FAHomeHandler(ctx *gin.Context) {
	var haveTOTP bool

	session := sessions.Default(ctx)

	cookieValue := session.Get(global.CookieHaveTOTP)
	if cookieValue != nil {
		haveTOTP = cookieValue.(bool)
	}

	cookieValue = session.Get(global.CookieAuthResult)
	if cookieValue == nil || global.AuthResult(cookieValue.(uint8)) != global.AuthResultOK {
		handleErr(ctx, errors2.ErrNotLoggedIn)

		return
	}

	cookieValue = session.Get(global.CookieAccount)
	if cookieValue == nil {
		handleErr(ctx, errors2.ErrNoAccount)

		return
	}

	session.Set(global.CookieHome, true)
	session.Save()

	cookieValue = session.Get(global.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(ctx, global.TwoFAv1Root+viper.GetString("login_2fa_post_page"), config.DefaultLanguageTags, languageCurrentName)

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
		EndpointTOTP:        global.TwoFAv1Root + viper.GetString("totp_page"),
		Or:                  getLocalized(ctx, "or"),
		RegisterWebAuthn:    getLocalized(ctx, "Register WebAuthn"),
		EndpointWebAuthn:    global.TwoFAv1Root + viper.GetString("webauthn_page"),
		LanguageTag:         session.Get(global.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		InDevelopment:       tags.IsDevelopment,
	}

	ctx.HTML(http.StatusOK, "home.html", homeData)
}

// Page '/2fa/v1/totp'
func registerTotpGETHandler(ctx *gin.Context) {
	var (
		haveError    bool
		errorMessage string
		csrfToken    = ctx.GetString(global.CtxCSRFTokenKey)
	)

	session := sessions.Default(ctx)

	cookieValue := session.Get(global.CookieHaveTOTP)
	if cookieValue != nil {
		if cookieValue.(bool) {
			session.Delete(global.CookieAuthResult)
			session.Delete(global.CookieAccount)
			session.Delete(global.CookieHaveTOTP)

			session.Save()

			ctx.Redirect(http.StatusFound, viper.GetString("notify_page")+"?message=You have already registered TOTP")

			return
		}
	}

	cookieValue = session.Get(global.CookieAuthResult)
	if cookieValue == nil || global.AuthResult(cookieValue.(uint8)) != global.AuthResultOK {
		handleErr(ctx, errors2.ErrNotLoggedIn)

		return
	}

	cookieValue = session.Get(global.CookieAccount)
	if cookieValue == nil {
		handleErr(ctx, errors2.ErrNoAccount)

		return
	}

	account := cookieValue.(string)

	totpURL := session.Get(global.CookieTOTPURL)
	if totpURL == nil {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      viper.GetString("totp_issuer"),
			AccountName: account,
		})

		if err != nil {
			handleErr(ctx, err)

			return
		}

		totpURL = key.String()

		session.Set(global.CookieTOTPURL, totpURL.(string))
		session.Save()
	}

	cookieValue = session.Get(global.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(ctx, global.TwoFAv1Root+viper.GetString("totp_page"), config.DefaultLanguageTags, languageCurrentName)

	if errorMessage = ctx.Query("_error"); errorMessage != "" {
		if errorMessage == global.PasswordFail {
			errorMessage = getLocalized(ctx, global.PasswordFail)
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
		LanguageTag:         session.Get(global.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		WantTos:             false,
		WantPolicy:          false,
		CSRFToken:           csrfToken,
		QRCode:              totpURL.(string),
		PostTOTPEndpoint:    global.TwoFAv1Root + viper.GetString("totp_page"),
	}

	ctx.HTML(http.StatusOK, "regtotp.html", totpData)
}

// Page '/2fa/v1/totp/post'
func registerTotpPOSTHandler(ctx *gin.Context) {
	var (
		accountName   string
		err           error
		totpKey       *otp.Key
		guid          = ctx.GetString(global.CtxGUIDKey)
		addTOTPSecret AddTOTPSecretFunc
	)

	session := sessions.Default(ctx)

	cookieValue := session.Get(global.CookieTOTPURL)
	if cookieValue == nil {
		handleErr(ctx, errors2.ErrNoTOTPURL)

		return
	}

	if totpKey, err = otp.NewKeyFromURL(cookieValue.(string)); err != nil {
		handleErr(ctx, err)

		return
	}

	if config.LoadableConfig.Server.Log.Level.Level() >= global.LogLevelDebug && config.EnvConfig.DevMode {
		level.Debug(logging.Logger).Log(
			global.LogKeyGUID, guid,
			"totp_key", fmt.Sprintf("%+v", totpKey),
		)
	}

	if !totp.Validate(ctx.PostForm("code"), totpKey.Secret()) {
		ctx.Redirect(
			http.StatusFound,
			global.TwoFAv1Root+viper.GetString("totp_page")+"?_error="+global.InvalidCode,
		)

		level.Info(logging.Logger).Log(
			global.LogKeyGUID, guid,
			global.LogKeyUsername, ctx.PostForm("username"),
			global.LogKeyAuthStatus, global.LogKeyAuthReject,
			global.LogKeyUriPath, global.TwoFAv1Root+viper.GetString("totp_page")+"/post",
		)

		return
	}

	username := session.Get(global.CookieUsername).(string)

	auth := &AuthState{
		HTTPClientContext: ctx.Copy(),
		GUID:              &guid,
		Username:          username,
		Protocol:          config.NewProtocol(global.ProtoOryHydra),
	}

	sourceBackend := session.Get(global.CookieUserBackend)

	switch sourceBackend.(uint8) {
	case uint8(global.BackendLDAP):
		addTOTPSecret = ldapAddTOTPSecret
	case uint8(global.BackendLua):
		addTOTPSecret = luaAddTOTPSecret
	default:
		handleErr(ctx, errors2.NewDetailedError("unsupported_backend").WithDetail(
			"Database backend not supported"))

		return
	}

	if err = addTOTPSecret(auth, NewTOTPSecret(totpKey.Secret())); err != nil {
		handleErr(ctx, err)

		return
	}

	/*
		Purge user from positive redis caches
	*/

	useCache := false
	for _, backendType := range config.LoadableConfig.Server.Backends {
		if backendType.Get() == global.BackendCache {
			useCache = true

			break
		}
	}

	if useCache {
		userKeys := config.NewStringSet()
		protocols := config.LoadableConfig.GetAllProtocols()

		accountName, err = backend.LookupUserAccountFromRedis(username)
		if err != nil {
			handleErr(ctx, err)

			return
		} else {
			stats.RedisReadCounter.Inc()
		}

		for index := range protocols {
			cacheNames := backend.GetCacheNames(protocols[index], global.CacheAll)

			for _, cacheName := range cacheNames.GetStringSlice() {
				userKeys.Set(config.LoadableConfig.Server.Redis.Prefix + "ucp:" + cacheName + ":" + accountName)
			}
		}

		// Remove current user from cache to enforce refreshing it.
		for _, userKey := range userKeys.GetStringSlice() {
			if _, err = rediscli.WriteHandle.Del(context.Background(), userKey).Result(); err != nil {
				if errors.Is(err, redis.Nil) {
					stats.RedisWriteCounter.Inc()

					continue
				}

				level.Error(logging.Logger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)

				break
			}
		}
	}

	// POST cleanup
	sessionCleaner(ctx)

	// Log out user
	session.Delete(global.CookieHome)
	session.Save()

	ctx.Redirect(http.StatusFound, viper.GetString("notify_page")+"?message=OTP code is valid. Registration completed successfully")

	level.Info(logging.Logger).Log(
		global.LogKeyGUID, guid,
		global.LogKeyUsername, ctx.PostForm("username"),
		global.LogKeyAuthStatus, global.LogKeyAuthAccept,
		global.LogKeyUriPath, global.TwoFAv1Root+viper.GetString("totp_page")+"/post",
	)
}
