package core

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
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

// SessionCleaner removes all user information from the current session.
func SessionCleaner(ctx *gin.Context) {
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
	var (
		haveError       bool
		errorMessage    string
		languagePassive []Language
		guid            = ctx.Value(global.GUIDKey).(string)
		csrfToken       = ctx.Value(global.CSRFTokenKey).(string)
	)

	SessionCleaner(ctx)

	session := sessions.Default(ctx)

	cookieValue := session.Get(global.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))

	for _, languageTag := range config.DefaultLanguageTags {
		languageName := cases.Title(languageTag, cases.NoLower).String(display.Self.Name(languageTag))

		if languageName == languageCurrentName {
			continue
		}

		baseName, _ := languageTag.Base()

		languagePassive = append(
			languagePassive,
			Language{
				LanguageLink: global.TwoFAv1Root + viper.GetString("login_2fa_page") + "/" + baseName.String() + "?" + ctx.Request.URL.RawQuery,
				LanguageName: languageName,
			},
		)
	}

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
		WantPolicy:          false,
		WantTos:             false,
		Submit:              getLocalized(ctx, "Submit"),
		PostLoginEndpoint:   global.TwoFAv1Root + viper.GetString("login_2fa_page"),
		LanguageTag:         session.Get(global.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
	}

	ctx.HTML(http.StatusOK, "register.html", loginData)

	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, guid,
		global.LogKeyUriPath, global.TwoFAv1Root+viper.GetString("login_2fa_page"),
	)
}

// Page '/2fa/v1/register/post'
func loginPOST2FAHandler(ctx *gin.Context) {
	var (
		err        error
		authResult = global.AuthResultUnset
		guid       = ctx.Value(global.GUIDKey).(string)
	)

	auth := &Authentication{
		HTTPClientContext: ctx,
		GUID:              &guid,
		Username:          ctx.PostForm("username"),
		Password:          ctx.PostForm("password"),
		Protocol:          config.NewProtocol(global.ProtoOryHydra),
	}

	auth.WithDefaults(ctx).WithClientInfo(ctx).WithLocalInfo(ctx).WithUserAgent(ctx).WithXSSL(ctx)

	if err = auth.SetStatusCode(global.ServOryHydra); err != nil {
		handleErr(ctx, err)

		return
	}

	session := sessions.Default(ctx)

	auth.UsernameOrig = auth.Username

	authResult = auth.HandlePassword(ctx)

	if authResult == global.AuthResultOK {
		var (
			found        bool
			account      string
			uniqueUserID string
			displayName  string
		)

		if account, found = auth.GetAccountOk(); !found {
			handleErr(ctx, errors2.ErrNoAccount)

			return
		}

		if _, found = auth.GetTOTPSecretOk(); found {
			session.Set(global.CookieHaveTOTP, true)
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

		err = session.Save()
		if err != nil {
			handleErr(ctx, err)

			return
		}

		ctx.Redirect(
			http.StatusFound,
			global.TwoFAv1Root+viper.GetString("login_2fa_post_page"),
		)

		level.Info(logging.DefaultLogger).Log(
			global.LogKeyGUID, guid,
			global.LogKeyUsername, ctx.PostForm("username"),
			global.LogKeyAuthStatus, global.LogKeyAuthAccept,
			global.LogKeyUriPath, global.TwoFAv1Root+viper.GetString("login_2fa_page")+"/post",
		)

		return
	}

	auth.ClientIP = ctx.Value(global.ClientIPKey).(string)

	auth.UpdateBruteForceBucketsCounter()

	ctx.Redirect(
		http.StatusFound,
		global.TwoFAv1Root+viper.GetString("login_2fa_page")+"?_error="+global.PasswordFail,
	)

	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, guid,
		global.LogKeyUsername, ctx.PostForm("username"),
		global.LogKeyAuthStatus, global.LogKeyAuthReject,
		global.LogKeyUriPath, global.TwoFAv1Root+viper.GetString("login_2fa_page")+"/post",
	)
}

// Page '/2fa/v1/register/home'
func register2FAHomeHandler(ctx *gin.Context) {
	var (
		haveTOTP        bool
		languagePassive []Language
	)

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

	cookieValue = session.Get(global.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))

	for _, languageTag := range config.DefaultLanguageTags {
		languageName := cases.Title(languageTag, cases.NoLower).String(display.Self.Name(languageTag))

		if languageName == languageCurrentName {
			continue
		}

		baseName, _ := languageTag.Base()

		languagePassive = append(
			languagePassive,
			Language{
				LanguageLink: global.TwoFAv1Root + viper.GetString("totp_page") + "/" + baseName.String() + "?" + ctx.Request.URL.RawQuery,
				LanguageName: languageName,
			},
		)
	}

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
		WantTos:             false,
		WantPolicy:          false,
	}

	ctx.HTML(http.StatusOK, "home.html", homeData)
}

// Page '/2fa/v1/totp'
func registerTotpGETHandler(ctx *gin.Context) {
	var (
		haveError       bool
		errorMessage    string
		languagePassive []Language
		csrfToken       = ctx.Value(global.CSRFTokenKey).(string)
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

	for _, languageTag := range config.DefaultLanguageTags {
		languageName := cases.Title(languageTag, cases.NoLower).String(display.Self.Name(languageTag))

		if languageName == languageCurrentName {
			continue
		}

		baseName, _ := languageTag.Base()

		languagePassive = append(
			languagePassive,
			Language{
				LanguageLink: global.TwoFAv1Root + viper.GetString("totp_page") + "/" + baseName.String() + "?" + ctx.Request.URL.RawQuery,
				LanguageName: languageName,
			},
		)
	}

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
		guid          = ctx.Value(global.GUIDKey).(string)
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

	if config.EnvConfig.Verbosity.Level() >= global.LogLevelDebug && config.EnvConfig.DevMode {
		level.Debug(logging.DefaultLogger).Log(
			global.LogKeyGUID, guid,
			"totp_key", fmt.Sprintf("%+v", totpKey),
		)
	}

	if !totp.Validate(ctx.PostForm("code"), totpKey.Secret()) {
		ctx.Redirect(
			http.StatusFound,
			global.TwoFAv1Root+viper.GetString("totp_page")+"?_error="+global.InvalidCode,
		)

		level.Info(logging.DefaultLogger).Log(
			global.LogKeyGUID, guid,
			global.LogKeyUsername, ctx.PostForm("username"),
			global.LogKeyAuthStatus, global.LogKeyAuthReject,
			global.LogKeyUriPath, global.TwoFAv1Root+viper.GetString("totp_page")+"/post",
		)

		return
	}

	username := session.Get(global.CookieUsername).(string)

	auth := &Authentication{
		HTTPClientContext: ctx,
		GUID:              &guid,
		Username:          username,
		Protocol:          config.NewProtocol(global.ProtoOryHydra),
	}

	sourceBackend := session.Get(global.CookieUserBackend)

	switch sourceBackend.(uint8) {
	case uint8(global.BackendLDAP):
		addTOTPSecret = LDAPAddTOTPSecret
	case uint8(global.BackendMySQL), uint8(global.BackendPostgres), uint8(global.BackendSQL):
		addTOTPSecret = SQLAddTOTPSecret
	case uint8(global.BackendLua):
		addTOTPSecret = LuaAddTOTPSecret
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
	for _, passDB := range config.EnvConfig.PassDBs {
		if passDB.Get() == global.BackendCache {
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
		}

		for index := range protocols {
			cacheNames := backend.GetCacheNames(protocols[index], global.CacheAll)

			for _, cacheName := range cacheNames.GetStringSlice() {
				userKeys.Set(config.EnvConfig.RedisPrefix + "ucp:" + cacheName + ":" + accountName)
			}
		}

		// Remove current user from cache to enforce refreshing it.
		for _, userKey := range userKeys.GetStringSlice() {
			if _, err = backend.RedisHandle.Del(backend.RedisHandle.Context(), userKey).Result(); err != nil {
				if errors.Is(err, redis.Nil) {
					continue
				}

				level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)

				break
			}
		}
	}

	// POST cleanup
	SessionCleaner(ctx)

	ctx.Redirect(http.StatusFound, viper.GetString("notify_page")+"?message=OTP code is valid. Registration completed successfully")

	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, guid,
		global.LogKeyUsername, ctx.PostForm("username"),
		global.LogKeyAuthStatus, global.LogKeyAuthAccept,
		global.LogKeyUriPath, global.TwoFAv1Root+viper.GetString("totp_page")+"/post",
	)
}
