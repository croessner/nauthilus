package core

// See the markdown documentation for the login-, two-factor-, consent- and logout pages for a brief description.

import (
	"crypto/tls"
	"errors"
	"fmt"
	logStdLib "log"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/justinas/nosurf"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	openapi "github.com/ory/hydra-client-go/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/spf13/viper"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
	_ "golang.org/x/text/message/catalog"
)

type Scope struct {
	ScopeName        string
	ScopeDescription string
}

type Language struct {
	LanguageLink string
	LanguageName string
}

type LoginPageData struct {
	WantWelcome         bool
	WantPolicy          bool
	WantTos             bool
	WantAbout           bool
	HaveError           bool
	Title               string
	Welcome             string
	LogoImage           string
	LogoImageAlt        string
	ApplicationName     string
	Login               string
	LoginPlaceholder    string
	Privacy             string
	Password            string
	PasswordPlaceholder string
	Policy              string
	PolicyUri           string
	Tos                 string
	TosUri              string
	About               string
	AboutUri            string
	Remember            string
	Submit              string
	ErrorMessage        string
	Or                  string
	Device              string
	CSRFToken           string
	LoginChallenge      string
	PostLoginEndpoint   string
	DeviceLoginEndpoint string
	LanguageTag         string
	LanguageCurrentName string
	LanguagePassive     []Language
}

type TwoFactorData struct {
	WantWelcome         bool
	WantPolicy          bool
	WantTos             bool
	WantAbout           bool
	Title               string
	Welcome             string
	LogoImage           string
	LogoImageAlt        string
	ApplicationName     string
	Code                string
	Policy              string
	PolicyUri           string
	Tos                 string
	TosUri              string
	About               string
	AboutUri            string
	Submit              string
	CSRFToken           string
	LoginChallenge      string
	User                string
	PostLoginEndpoint   string
	LanguageTag         string
	LanguageCurrentName string
	LanguagePassive     []Language
}

type LogoutPageData struct {
	WantWelcome         bool
	Title               string
	Welcome             string
	LogoutMessage       string
	AcceptSubmit        string
	RejectSubmit        string
	CSRFToken           string
	LogoutChallenge     string
	PostLogoutEndpoint  string
	LanguageTag         string
	LanguageCurrentName string
	LanguagePassive     []Language
}

type ConsentPageData struct {
	WantWelcome         bool
	WantPolicy          bool
	WantTos             bool
	WantAbout           bool
	Title               string
	Welcome             string
	LogoImage           string
	LogoImageAlt        string
	ConsentMessage      string
	ApplicationName     string
	Policy              string
	PolicyUri           string
	Tos                 string
	TosUri              string
	About               string
	AboutUri            string
	Remember            string
	AcceptSubmit        string
	RejectSubmit        string
	CSRFToken           string
	ConsentChallenge    string
	PostConsentEndpoint string
	LanguageTag         string
	LanguageCurrentName string
	Scopes              []Scope
	LanguagePassive     []Language
}

type NotifyPageData struct {
	WantWelcome         bool
	WantPolicy          bool
	WantTos             bool
	Title               string
	Welcome             string
	LogoImage           string
	LogoImageAlt        string
	NotifyMessage       string
	LanguageTag         string
	LanguageCurrentName string
	LanguagePassive     []Language
}

// handleErr is a helper that prints a log line for a given error and sets the HTTP error handler.
func handleErr(ctx *gin.Context, err error) {
	var detailedError *errors2.DetailedError

	guid := ctx.Value(decl.GUIDKey).(string)
	buf := make([]byte, 1<<20)
	stackLen := runtime.Stack(buf, false)

	if errors.As(err, &detailedError) {
		level.Error(logging.DefaultErrLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeyError, detailedError.Error(),
			decl.LogKeyErrorDetails, detailedError.GetDetails(),
			decl.LogKeyClientIP, ctx.Request.RemoteAddr,
		)
	} else {
		level.Error(logging.DefaultErrLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeyError, err,
			decl.LogKeyClientIP, ctx.Request.RemoteAddr,
		)
	}

	logStdLib.Printf("=== guid=%s\n*** goroutine dump...\n%s\n*** end\n", guid, buf[:stackLen])

	SessionCleaner(ctx)

	ctx.Set("failure", true)
	ctx.Set("message", err)

	notifyGETHandler(ctx)
}

func notifyGETHandler(ctx *gin.Context) {
	var (
		found           bool
		msg             string
		value           any
		languagePassive []Language
		httpStatusCode  = http.StatusOK
	)

	statusTitle := getLocalized(ctx, "Information")

	if value, found = ctx.Get("failure"); found {
		if value.(bool) {
			httpStatusCode = http.StatusBadRequest
			statusTitle = getLocalized(ctx, "Bad Request")
		}
	}

	if value, found = ctx.Get("message"); found {
		msg = getLocalized(ctx, "An error occurred:") + " " + value.(error).Error()
	} else {
		msg = getLocalized(ctx, ctx.Query("message"))
	}

	// Fallback for non-localized messages
	if msg == "" {
		msg = ctx.Query("message")
	}

	session := sessions.Default(ctx)
	cookieValue := session.Get(decl.CookieLang)

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
				LanguageLink: viper.GetString("notify_page") + "/" + baseName.String() + "?" + ctx.Request.URL.RawQuery,
				LanguageName: languageName,
			},
		)
	}

	notifyData := NotifyPageData{
		Title: statusTitle,
		WantWelcome: func() bool {
			if viper.GetString("notify_page_welcome") != "" {
				return true
			}

			return false
		}(),
		Welcome:             viper.GetString("notify_page_welcome"),
		LogoImage:           viper.GetString("default_logo_image"),
		LogoImageAlt:        viper.GetString("notify_page_logo_image_alt"),
		NotifyMessage:       msg,
		LanguageTag:         session.Get(decl.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		WantTos:             false,
		WantPolicy:          false,
	}

	ctx.HTML(httpStatusCode, "notify.html", notifyData)
}

func getLocalized(ctx *gin.Context, messageID string) string {
	localizer := ctx.Value(decl.LocalizedKey).(*i18n.Localizer)

	localizeConfig := i18n.LocalizeConfig{
		MessageID: messageID,
	}
	localization, err := localizer.Localize(&localizeConfig)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(
			decl.LogKeyGUID, ctx.Value(decl.GUIDKey).(string),
			"message_id", messageID, decl.LogKeyError, err.Error(),
		)
	}

	return localization
}

func handleHydraErr(ctx *gin.Context, err error, httpResponse *http.Response) {
	if httpResponse != nil {
		switch httpResponse.StatusCode {
		case http.StatusNotFound:
			handleErr(ctx, errors2.ErrUnknownJSON)
		case http.StatusGone:
			handleErr(ctx, errors2.ErrHTTPRequestGone)
		default:
			handleErr(ctx, err)
		}
	} else {
		handleErr(ctx, err)
	}
}

func withLanguageMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			needRedirect   bool
			needCookie     bool
			lang           string
			langFromURL    string
			langFromCookie string
		)

		guid := ctx.Value(decl.GUIDKey).(string)

		// Try to get language tag from URL
		langFromURL = ctx.Param("languageTag")

		// Try to get language tag from cookie
		session := sessions.Default(ctx)
		cookieValue := session.Get(decl.CookieLang)

		if cookieValue != nil {
			langFromCookie, _ = cookieValue.(string)
		}

		if langFromURL == "" && langFromCookie == "" {
			// 1. No language from URL and no cookie is set
			needCookie = true
			needRedirect = true
		} else if langFromURL == "" && langFromCookie != "" {
			// 2. No language from URL, but a cookie is set
			lang = langFromCookie
			needRedirect = true
		} else if langFromURL != "" && langFromCookie == "" {
			// 3. Language from URL and no cookie
			lang = langFromURL
			needCookie = true
		} else if langFromURL != "" && langFromCookie != "" {
			if langFromURL != langFromCookie {
				// 4. Langauge given from URL and cookie, but both differ
				needCookie = true
			}

			lang = langFromURL
		}

		accept := ctx.Request.Header.Get("Accept-Language")
		tag, _ := language.MatchStrings(config.Matcher, lang, accept)
		baseName, _ := tag.Base()

		util.DebugModule(
			decl.DbgHydra,
			decl.LogKeyGUID, guid,
			"accept", accept,
			"language", lang,
			"language_tag", fmt.Sprintf("%v", baseName.String()),
		)

		// Language not found in catalog
		if lang != "" && lang != baseName.String() {
			ctx.AbortWithError(http.StatusNotFound, errors2.ErrLanguageNotFound)

			return
		}

		localizer := i18n.NewLocalizer(LangBundle, lang, accept)

		if needCookie {
			session.Set(decl.CookieLang, baseName.String())
			session.Save()
		}

		ctx.Set(decl.CSRFTokenKey, nosurf.Token(ctx.Request))
		ctx.Set(decl.LocalizedKey, localizer)

		if needRedirect {
			ctx.Redirect(
				http.StatusFound,
				ctx.Request.URL.Path+"/"+baseName.String()+"?"+ctx.Request.URL.RawQuery,
			)

			return
		}

		ctx.Next()
	}
}

// Page '/login'
func loginGETHandler(ctx *gin.Context) {
	var (
		wantAbout       bool
		wantPolicy      bool
		wantTos         bool
		haveError       bool
		pre2FA          bool
		policyUri       string
		tosUri          string
		clientUri       string
		imageUri        string
		errorMessage    string
		languagePassive []Language
		err             error
		clientId        *string
		userData        map[string]any
		guid            = ctx.Value(decl.GUIDKey).(string)
		csrfToken       = ctx.Value(decl.CSRFTokenKey).(string)
		loginRequest    *openapi.OAuth2LoginRequest
		acceptRequest   *openapi.OAuth2RedirectTo
		httpResponse    *http.Response
	)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("http_client_skip_tls_verify")},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	loginChallenge := ctx.Query("login_challenge")
	if loginChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	configuration := openapi.NewConfiguration()
	configuration.HTTPClient = httpClient
	configuration.Servers = []openapi.ServerConfiguration{
		{
			URL: viper.GetString("hydra_admin_uri"), // Admin API
		},
	}

	apiClient := openapi.NewAPIClient(configuration)

	loginRequest, httpResponse, err = apiClient.OAuth2Api.GetOAuth2LoginRequest(ctx).LoginChallenge(
		loginChallenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	oauth2Client := loginRequest.GetClient()

	clientIdFound := false
	if clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		handleErr(ctx, errors2.ErrHydraNoClientId)

		return
	}

	clientName := oauth2Client.GetClientName()

	if !loginRequest.GetSkip() {
		util.DebugModule(decl.DbgHydra, decl.LogKeyGUID, guid, decl.LogKeyMsg, "login_skip false")

		imageUri = oauth2Client.GetLogoUri()
		if imageUri == "" {
			imageUri = viper.GetString("default_logo_image")
		}

		if policyUri = oauth2Client.GetPolicyUri(); policyUri != "" {
			wantPolicy = true
		}

		if tosUri = oauth2Client.GetTosUri(); tosUri != "" {
			wantTos = true
		}

		if clientUri = oauth2Client.GetClientUri(); clientUri != "" {
			wantAbout = true
		}

		applicationName := oauth2Client.GetClientName()
		session := sessions.Default(ctx)

		cookieValue := session.Get(decl.CookieLang)

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
					LanguageLink: viper.GetString("login_page") + "/" + baseName.String() + "?" + ctx.Request.URL.RawQuery,
					LanguageName: languageName,
				},
			)
		}

		userData = make(map[string]any, 2)

		if cookieValue = session.Get(decl.CookieUsername); cookieValue != nil {
			userData[decl.CookieUsername] = cookieValue.(string)
		}

		if cookieValue = session.Get(decl.CookieAuthStatus); cookieValue != nil {
			userData[decl.CookieAuthStatus] = decl.AuthResult(cookieValue.(uint8))
			pre2FA = true
		}

		// Handle TOTP request
		if pre2FA && userData[decl.CookieAuthStatus] != decl.AuthResultUnset {
			twoFactorData := &TwoFactorData{
				Title: getLocalized(ctx, "Login"),
				WantWelcome: func() bool {
					if viper.GetString("login_page_welcome") != "" {
						return true
					}

					return false
				}(),
				Welcome:             viper.GetString("login_page_welcome"),
				ApplicationName:     applicationName,
				WantAbout:           wantAbout,
				About:               getLocalized(ctx, "Get further information about this application..."),
				AboutUri:            clientUri,
				LogoImage:           imageUri,
				LogoImageAlt:        viper.GetString("login_page_logo_image_alt"),
				WantPolicy:          wantPolicy,
				Code:                getLocalized(ctx, "OTP-Code"),
				Policy:              getLocalized(ctx, "Privacy policy"),
				PolicyUri:           policyUri,
				WantTos:             wantTos,
				Tos:                 getLocalized(ctx, "Terms of service"),
				TosUri:              tosUri,
				Submit:              getLocalized(ctx, "Submit"),
				PostLoginEndpoint:   viper.GetString("login_page"),
				LanguageTag:         session.Get(decl.CookieLang).(string),
				LanguageCurrentName: languageCurrentName,
				LanguagePassive:     languagePassive,
				CSRFToken:           csrfToken,
				LoginChallenge:      loginChallenge,
			}

			ctx.HTML(http.StatusOK, "totp.html", twoFactorData)

			util.DebugModule(
				decl.DbgHydra,
				decl.LogKeyGUID, guid,
				decl.LogKeyMsg, "Two factor authentication",
				decl.LogKeyUsername, userData[decl.CookieUsername].(string),
			)

			return
		}

		if errorMessage = ctx.Query("_error"); errorMessage != "" {
			if errorMessage == decl.PasswordFail {
				errorMessage = getLocalized(ctx, decl.PasswordFail)
			}

			haveError = true
		}

		loginData := &LoginPageData{
			Title: getLocalized(ctx, "Login"),
			WantWelcome: func() bool {
				if viper.GetString("login_page_welcome") != "" {
					return true
				}

				return false
			}(),
			Welcome:             viper.GetString("login_page_welcome"),
			ApplicationName:     applicationName,
			WantAbout:           wantAbout,
			About:               getLocalized(ctx, "Get further information about this application..."),
			AboutUri:            clientUri,
			LogoImage:           imageUri,
			LogoImageAlt:        viper.GetString("login_page_logo_image_alt"),
			HaveError:           haveError,
			ErrorMessage:        errorMessage,
			Login:               getLocalized(ctx, "Login"),
			Privacy:             getLocalized(ctx, "We'll never share your data with anyone else."),
			LoginPlaceholder:    getLocalized(ctx, "Please enter your username or email address"),
			Password:            getLocalized(ctx, "Password"),
			PasswordPlaceholder: getLocalized(ctx, "Please enter your password"),
			WantPolicy:          wantPolicy,
			Policy:              getLocalized(ctx, "Privacy policy"),
			PolicyUri:           policyUri,
			WantTos:             wantTos,
			Tos:                 getLocalized(ctx, "Terms of service"),
			TosUri:              tosUri,
			Remember:            getLocalized(ctx, "Remember me"),
			Submit:              getLocalized(ctx, "Submit"),
			Or:                  getLocalized(ctx, "or"),
			Device:              getLocalized(ctx, "Login with WebAuthn"),
			PostLoginEndpoint:   viper.GetString("login_page"),
			DeviceLoginEndpoint: viper.GetString("device_page"),
			LanguageTag:         session.Get(decl.CookieLang).(string),
			LanguageCurrentName: languageCurrentName,
			LanguagePassive:     languagePassive,
			CSRFToken:           csrfToken,
			LoginChallenge:      loginChallenge,
		}

		ctx.HTML(http.StatusOK, "login.html", loginData)

		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeySkip, false,
			decl.LogKeyClientID, *clientId,
			decl.LogKeyClientName, clientName,
			decl.LogKeyAuthChallenge, loginChallenge,
			decl.LogKeyUriPath, viper.GetString("login_page"),
		)
	} else {
		var claims map[string]any

		util.DebugModule(decl.DbgHydra, decl.LogKeyGUID, guid, decl.LogKeyMsg, "login_skip true")

		auth := &Authentication{
			HTTPClientContext: ctx,
			NoAuth:            true,
			Protocol:          config.NewProtocol(decl.ProtoOryHydra),
		}

		auth.WithDefaults(ctx).WithClientInfo(ctx).WithLocalInfo(ctx).WithUserAgent(ctx).WithXSSL(ctx)

		auth.Username = loginRequest.GetSubject()
		auth.UsernameOrig = loginRequest.GetSubject()

		if err := auth.SetStatusCode(decl.ServOryHydra); err != nil {
			handleErr(ctx, err)

			return
		}

		if authStatus := auth.HandlePassword(ctx); authStatus == decl.AuthResultOK {
			if config.LoadableConfig.Oauth2 != nil {
				_, claims = auth.GetOauth2SubjectAndClaims(oauth2Client)
			}
		} else {
			auth.ClientIP = ctx.Value(decl.ClientIPKey).(string)

			auth.UpdateBruteForceBucketsCounter()
			ctx.AbortWithError(http.StatusInternalServerError, errors2.ErrUnknownCause)

			return
		}

		acceptLoginRequest := apiClient.OAuth2Api.AcceptOAuth2LoginRequest(ctx).AcceptOAuth2LoginRequest(
			openapi.AcceptOAuth2LoginRequest{
				Subject: loginRequest.GetSubject(),
				Context: claims,
			})

		acceptRequest, httpResponse, err = acceptLoginRequest.LoginChallenge(loginChallenge).Execute()
		if err != nil {
			handleHydraErr(ctx, err, httpResponse)

			return
		}

		ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeySkip, true,
			decl.LogKeyClientID, *clientId,
			decl.LogKeyClientName, clientName,
			decl.LogKeyAuthSubject, loginRequest.GetSubject(),
			decl.LogKeyAuthChallenge, loginChallenge,
			decl.LogKeyAuthStatus, decl.LogKeyAuthAccept,
			decl.LogKeyUriPath, viper.GetString("login_page"),
			decl.LogKeyRedirectTo, acceptRequest.GetRedirectTo(),
		)
	}
}

// Page '/login/post'
func loginPOSTHandler(ctx *gin.Context) {
	var (
		post2FA         bool
		rememberPost2FA string
		recentSubject   string
		err             error
		clientId        *string
		cookieValue     any
		authResult      = decl.AuthResultUnset
		guid            = ctx.Value(decl.GUIDKey).(string)
		loginRequest    *openapi.OAuth2LoginRequest
		acceptRequest   *openapi.OAuth2RedirectTo
		httpResponse    *http.Response
	)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("http_client_skip_tls_verify")},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	loginChallenge := ctx.PostForm("ory.hydra.login_challenge")
	if loginChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	configuration := openapi.NewConfiguration()
	configuration.HTTPClient = httpClient
	configuration.Servers = []openapi.ServerConfiguration{
		{
			URL: viper.GetString("hydra_admin_uri"), // Admin API
		},
	}

	apiClient := openapi.NewAPIClient(configuration)
	auth := &Authentication{
		HTTPClientContext: ctx,
		Username:          ctx.PostForm("username"),
		Password:          ctx.PostForm("password"),
		Protocol:          config.NewProtocol(decl.ProtoOryHydra),
	}

	auth.WithDefaults(ctx).WithClientInfo(ctx).WithLocalInfo(ctx).WithUserAgent(ctx).WithXSSL(ctx)

	if err := auth.SetStatusCode(decl.ServOryHydra); err != nil {
		handleErr(ctx, err)

		return
	}

	session := sessions.Default(ctx)

	// Restore authentication data from first call to login.html
	if cookieValue = session.Get(decl.CookieUsername); cookieValue != nil {
		if cookieValue.(string) != "" {
			auth.Username = cookieValue.(string)
			auth.NoAuth = true
		}

		session.Delete(decl.CookieUsername)
	}

	if cookieValue = session.Get(decl.CookieAuthStatus); cookieValue != nil {
		authResult = decl.AuthResult(cookieValue.(uint8))
		if authResult != decl.AuthResultUnset {
			post2FA = true
		}

		session.Delete(decl.CookieAuthStatus)
	}

	if cookieValue = session.Get(decl.CookieSubject); cookieValue != nil {
		recentSubject = cookieValue.(string)

		session.Delete(decl.CookieSubject)
	}

	if cookieValue = session.Get(decl.CookieRemember); cookieValue != nil {
		rememberPost2FA = cookieValue.(string)

		session.Delete(decl.CookieRemember)
	}

	err = session.Save()
	if err != nil {
		handleErr(ctx, err)

		return
	}

	auth.UsernameOrig = auth.Username

	loginRequest, httpResponse, err = apiClient.OAuth2Api.GetOAuth2LoginRequest(ctx).LoginChallenge(
		loginChallenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	oauth2Client := loginRequest.GetClient()

	clientIdFound := false
	if clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		handleErr(ctx, errors2.ErrHydraNoClientId)

		return
	}

	clientName := oauth2Client.GetClientName()

	if authResult == decl.AuthResultUnset || authResult == decl.AuthResultOK {
		authResult = auth.HandlePassword(ctx)
	}

	switch authResult {
	case decl.AuthResultOK:
		var (
			found      bool
			account    string
			subject    string
			totpSecret string
			claims     map[string]any
		)

		if account, found = auth.GetAccountOk(); !found {
			handleErr(ctx, errors2.ErrNoAccount)

			return
		}

		if config.LoadableConfig.Oauth2 != nil {
			subject, claims = auth.GetOauth2SubjectAndClaims(oauth2Client)
		}

		if subject == "" {
			subject = account

			level.Warn(logging.DefaultLogger).Log(
				decl.LogKeyGUID, guid,
				decl.LogKeyMsg, fmt.Sprintf("Empty 'subject', using '%s' as value", account),
			)
		}

		// Call totp.html for second factor
		if !post2FA {
			if !config.GetSkipTOTP(*clientId) {
				if _, found = auth.GetTOTPSecretOk(); found {
					session.Set(decl.CookieAuthStatus, uint8(authResult))
					session.Set(decl.CookieUsername, ctx.Request.Form.Get("username"))
					session.Set(decl.CookieSubject, subject)
					session.Set(decl.CookieRemember, ctx.Request.Form.Get("remember"))

					err = session.Save()
					if err != nil {
						handleErr(ctx, err)

						return
					}

					ctx.Redirect(
						http.StatusFound,
						viper.GetString("login_page")+"?login_challenge="+loginChallenge,
					)

					return
				}
			}
		} else {
			var key *otp.Key

			if recentSubject != subject {
				handleErr(ctx, errors2.ErrNoAccount)

				return
			}

			code := ctx.PostForm("code")

			// No code given
			if code == "" {
				break
			}

			if totpSecret, found = auth.GetTOTPSecretOk(); found {
				var (
					codeValid     bool
					urlComponents []string
				)

				urlComponents = append(urlComponents, "otpauth://totp/")
				urlComponents = append(urlComponents, url.QueryEscape(viper.GetString("totp_issuer")))
				urlComponents = append(urlComponents, ":")
				urlComponents = append(urlComponents, account)
				urlComponents = append(urlComponents, "?secret=")
				urlComponents = append(urlComponents, totpSecret)
				urlComponents = append(urlComponents, "&issuer=")
				urlComponents = append(urlComponents, url.QueryEscape(viper.GetString("totp_issuer")))
				urlComponents = append(urlComponents, "&algorithm=SHA1")
				urlComponents = append(urlComponents, "&digits=6")
				urlComponents = append(urlComponents, "&period=30")

				totpURL := strings.Join(urlComponents, "")

				if key, err = otp.NewKeyFromURL(totpURL); err != nil {
					handleErr(ctx, err)

					return
				}

				if config.EnvConfig.Verbosity.Level() >= decl.LogLevelDebug && config.EnvConfig.DevMode {
					util.DebugModule(
						decl.DbgHydra,
						decl.LogKeyGUID, guid,
						"totp_key", fmt.Sprintf("%+v", key),
					)
				}

				codeValid, err = totp.ValidateCustom(code, key.Secret(), time.Now(), totp.ValidateOpts{
					Period:    30,
					Skew:      viper.GetUint("totp_skew"),
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
				})

				if !codeValid {
					break
				}
			} else {
				break
			}
		}

		rememberFor := int64(viper.GetInt("login_remember_for"))
		remember := false

		if post2FA {
			if rememberPost2FA == "on" {
				remember = true
			}
		} else if ctx.PostForm("remember") == "on" {
			remember = true
		}

		acceptLoginRequest := apiClient.OAuth2Api.AcceptOAuth2LoginRequest(ctx).AcceptOAuth2LoginRequest(
			openapi.AcceptOAuth2LoginRequest{
				Context:     claims,
				Subject:     subject,
				Remember:    &remember,
				RememberFor: &rememberFor,
			})

		acceptRequest, httpResponse, err = acceptLoginRequest.LoginChallenge(loginChallenge).Execute()
		if err != nil {
			handleHydraErr(ctx, err, httpResponse)

			return
		}

		ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeyClientID, *clientId,
			decl.LogKeyClientName, clientName,
			decl.LogKeyAuthSubject, subject,
			decl.LogKeyAuthChallenge, loginChallenge,
			decl.LogKeyUsername, ctx.PostForm("username"),
			decl.LogKeyAuthStatus, decl.LogKeyAuthAccept,
			decl.LogKeyUriPath, viper.GetString("login_page")+"/post",
			decl.LogKeyRedirectTo, acceptRequest.GetRedirectTo(),
		)

		return

	case decl.AuthResultFail, decl.AuthResultEmptyUsername, decl.AuthResultEmptyPassword:
		if !post2FA {
			if !config.GetSkipTOTP(*clientId) {
				if _, found := auth.GetTOTPSecretOk(); found {
					session.Set(decl.CookieAuthStatus, uint8(authResult))
					session.Set(decl.CookieUsername, ctx.Request.Form.Get("username"))

					session.Save()
					if err != nil {
						handleErr(ctx, err)

						return
					}

					ctx.Redirect(
						http.StatusFound,
						viper.GetString("login_page")+"?login_challenge="+loginChallenge,
					)

					return
				}
			}
		}
	}

	auth.ClientIP = ctx.Value(decl.ClientIPKey).(string)

	auth.UpdateBruteForceBucketsCounter()

	ctx.Redirect(
		http.StatusFound,
		viper.GetString("login_page")+"?login_challenge="+loginChallenge+"&_error="+decl.PasswordFail,
	)

	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyGUID, guid,
		decl.LogKeyClientID, *clientId,
		decl.LogKeyClientName, clientName,
		decl.LogKeyAuthChallenge, loginChallenge,
		decl.LogKeyUsername, ctx.PostForm("username"),
		decl.LogKeyAuthStatus, decl.LogKeyAuthReject,
		decl.LogKeyUriPath, viper.GetString("login_page")+"/post",
	)
}

// Page '/device'
func deviceGETHandler(ctx *gin.Context) {
	var (
		wantAbout       bool
		wantPolicy      bool
		wantTos         bool
		haveError       bool
		policyUri       string
		tosUri          string
		clientUri       string
		imageUri        string
		errorMessage    string
		languagePassive []Language
		err             error
		clientId        *string
		userData        map[string]any
		guid            = ctx.Value(decl.GUIDKey).(string)
		csrfToken       = ctx.Value(decl.CSRFTokenKey).(string)
		loginRequest    *openapi.OAuth2LoginRequest
		httpResponse    *http.Response
	)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("http_client_skip_tls_verify")},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	loginChallenge := ctx.Query("login_challenge")
	if loginChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	configuration := openapi.NewConfiguration()
	configuration.HTTPClient = httpClient
	configuration.Servers = []openapi.ServerConfiguration{
		{
			URL: viper.GetString("hydra_admin_uri"), // Admin API
		},
	}

	apiClient := openapi.NewAPIClient(configuration)

	loginRequest, httpResponse, err = apiClient.OAuth2Api.GetOAuth2LoginRequest(ctx).LoginChallenge(
		loginChallenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	oauth2Client := loginRequest.GetClient()

	clientIdFound := false
	if clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		handleErr(ctx, errors2.ErrHydraNoClientId)

		return
	}

	clientName := oauth2Client.GetClientName()

	imageUri = oauth2Client.GetLogoUri()
	if imageUri == "" {
		imageUri = viper.GetString("default_logo_image")
	}

	if policyUri = oauth2Client.GetPolicyUri(); policyUri != "" {
		wantPolicy = true
	}

	if tosUri = oauth2Client.GetTosUri(); tosUri != "" {
		wantTos = true
	}

	if clientUri = oauth2Client.GetClientUri(); clientUri != "" {
		wantAbout = true
	}

	applicationName := oauth2Client.GetClientName()
	session := sessions.Default(ctx)

	cookieValue := session.Get(decl.CookieLang)

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
				LanguageLink: viper.GetString("device_page") + "/" + baseName.String() + "?" + ctx.Request.URL.RawQuery,
				LanguageName: languageName,
			},
		)
	}

	userData = make(map[string]any, 2)

	if cookieValue = session.Get(decl.CookieUsername); cookieValue != nil {
		userData[decl.CookieUsername] = cookieValue.(string)
	}

	if cookieValue = session.Get(decl.CookieAuthStatus); cookieValue != nil {
		userData[decl.CookieAuthStatus] = decl.AuthResult(cookieValue.(uint8))
	}

	loginData := &LoginPageData{
		Title: getLocalized(ctx, "Login"),
		WantWelcome: func() bool {
			if viper.GetString("login_page_welcome") != "" {
				return true
			}

			return false
		}(),
		Welcome:             viper.GetString("login_page_welcome"),
		ApplicationName:     applicationName,
		WantAbout:           wantAbout,
		About:               getLocalized(ctx, "Get further information about this application..."),
		AboutUri:            clientUri,
		LogoImage:           imageUri,
		LogoImageAlt:        viper.GetString("login_page_logo_image_alt"),
		HaveError:           haveError,
		ErrorMessage:        errorMessage,
		Login:               getLocalized(ctx, "Login"),
		Privacy:             getLocalized(ctx, "We'll never share your data with anyone else."),
		LoginPlaceholder:    getLocalized(ctx, "Please enter your username or email address"),
		WantPolicy:          wantPolicy,
		Policy:              getLocalized(ctx, "Privacy policy"),
		PolicyUri:           policyUri,
		WantTos:             wantTos,
		Tos:                 getLocalized(ctx, "Terms of service"),
		TosUri:              tosUri,
		Submit:              getLocalized(ctx, "Submit"),
		PostLoginEndpoint:   viper.GetString("device_page"),
		DeviceLoginEndpoint: viper.GetString("device_page"),
		LanguageTag:         session.Get(decl.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
		LoginChallenge:      loginChallenge,
	}

	ctx.HTML(http.StatusOK, "device.html", loginData)

	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyGUID, guid,
		decl.LogKeySkip, false,
		decl.LogKeyClientID, *clientId,
		decl.LogKeyClientName, clientName,
		decl.LogKeyAuthChallenge, loginChallenge,
		decl.LogKeyUriPath, viper.GetString("device_page"),
	)
}

// Page '/device/post'
func devicePOSTHandler(ctx *gin.Context) {
	handleErr(ctx, errors.New("not implemented yet"))
}

// Page '/consent'
func consentGETHandler(ctx *gin.Context) {
	var (
		wantAbout       bool
		wantPolicy      bool
		wantTos         bool
		skipConsent     bool
		policyUri       string
		tosUri          string
		clientUri       string
		imageUri        string
		languagePassive []Language
		err             error
		clientId        *string
		guid            = ctx.Value(decl.GUIDKey).(string)
		csrfToken       = ctx.Value(decl.CSRFTokenKey).(string)
		consentRequest  *openapi.OAuth2ConsentRequest
		acceptRequest   *openapi.OAuth2RedirectTo
		httpResponse    *http.Response
	)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("http_client_skip_tls_verify")},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	consentChallenge := ctx.Query("consent_challenge")
	if consentChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	configuration := openapi.NewConfiguration()
	configuration.HTTPClient = httpClient
	configuration.Servers = []openapi.ServerConfiguration{
		{
			URL: viper.GetString("hydra_admin_uri"), // Admin API
		},
	}

	apiClient := openapi.NewAPIClient(configuration)

	consentRequest, httpResponse, err = apiClient.OAuth2Api.GetOAuth2ConsentRequest(ctx).ConsentChallenge(
		consentChallenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	oauth2Client := consentRequest.GetClient()

	clientIdFound := false
	if clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		handleErr(ctx, errors2.ErrHydraNoClientId)

		return
	}

	clientName := oauth2Client.GetClientName()

	util.DebugModule(
		decl.DbgHydra,
		decl.LogKeyGUID, guid,
		"skip_hydra", fmt.Sprintf("%v", consentRequest.GetSkip()),
		"skip_config", fmt.Sprintf("%v", skipConsent),
	)

	if !(consentRequest.GetSkip() || config.GetSkipConsent(*clientId)) {
		var (
			scopes           []Scope
			scopeDescription string
		)

		requestedScopes := consentRequest.GetRequestedScope()

		session := sessions.Default(ctx)
		cookieValue := session.Get(decl.CookieLang)

		for index := range requestedScopes {
			switch requestedScopes[index] {
			case decl.ScopeOpenId:
				scopeDescription = getLocalized(ctx, "Allow access to identity information")
			case decl.ScopeOfflineAccess:
				scopeDescription = getLocalized(ctx, "Allow an application access to private data without your personal presence")
			case decl.ScopeProfile:
				scopeDescription = getLocalized(ctx, "Allow access to personal profile data")
			case decl.ScopeEmail:
				scopeDescription = getLocalized(ctx, "Allow access to your email address")
			case decl.ScopeAddress:
				scopeDescription = getLocalized(ctx, "Allow access to your home address")
			case decl.ScopePhone:
				scopeDescription = getLocalized(ctx, "Allow access to your phone number")
			case decl.ScopeGroups:
				scopeDescription = getLocalized(ctx, "Allow access to group memberships")
			default:
				scopeDescription = ""

				if config.LoadableConfig.Oauth2 != nil {
					for customScopeIndex := range config.LoadableConfig.Oauth2.CustomScopes {
						if config.LoadableConfig.Oauth2.CustomScopes[customScopeIndex].Name != requestedScopes[index] {
							continue
						}

						scopeDescription = config.LoadableConfig.Oauth2.CustomScopes[customScopeIndex].Description

						if len(config.LoadableConfig.Oauth2.CustomScopes[customScopeIndex].Other) > 0 {
							lang := cookieValue.(string)

							if value, assertOk := config.LoadableConfig.Oauth2.CustomScopes[customScopeIndex].Other["description_"+lang]; assertOk {
								scopeDescription = value.(string)
							}
						}

						break
					}
				}

				if scopeDescription == "" {
					scopeDescription = getLocalized(ctx, "Allow access to a specific scope")
				}
			}

			scopes = append(scopes, Scope{ScopeName: requestedScopes[index], ScopeDescription: scopeDescription})
		}

		imageUri = oauth2Client.GetLogoUri()
		if imageUri == "" {
			imageUri = viper.GetString("default_logo_image")
		}

		if policyUri = oauth2Client.GetPolicyUri(); policyUri != "" {
			wantPolicy = true
		}

		if tosUri = oauth2Client.GetTosUri(); tosUri != "" {
			wantTos = true
		}

		if clientUri = oauth2Client.GetClientUri(); clientUri != "" {
			wantAbout = true
		}

		applicationName := oauth2Client.GetClientName()

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
					LanguageLink: viper.GetString("consent_page") + "/" + baseName.String() + "?" + ctx.Request.URL.RawQuery,
					LanguageName: languageName,
				},
			)
		}

		consentData := &ConsentPageData{
			Title: getLocalized(ctx, "Consent"),
			WantWelcome: func() bool {
				if viper.GetString("login_page_welcome") != "" {
					return true
				}

				return false
			}(),
			Welcome:             viper.GetString("consent_page_welcome"),
			LogoImage:           imageUri,
			LogoImageAlt:        viper.GetString("consent_page_logo_image_alt"),
			ConsentMessage:      getLocalized(ctx, "An application requests access to your data"),
			ApplicationName:     applicationName,
			WantAbout:           wantAbout,
			About:               getLocalized(ctx, "Get further information about this application..."),
			AboutUri:            clientUri,
			Scopes:              scopes,
			WantPolicy:          wantPolicy,
			Policy:              getLocalized(ctx, "Privacy policy"),
			PolicyUri:           policyUri,
			WantTos:             wantTos,
			Tos:                 getLocalized(ctx, "Terms of service"),
			TosUri:              tosUri,
			Remember:            getLocalized(ctx, "Do not ask me again"),
			AcceptSubmit:        getLocalized(ctx, "Accept access"),
			RejectSubmit:        getLocalized(ctx, "Deny access"),
			LanguageTag:         session.Get(decl.CookieLang).(string),
			LanguageCurrentName: languageCurrentName,
			LanguagePassive:     languagePassive,
			CSRFToken:           csrfToken,
			ConsentChallenge:    consentChallenge,
			PostConsentEndpoint: viper.GetString("consent_page"),
		}

		ctx.HTML(http.StatusOK, "consent.html", consentData)

		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeySkip, false,
			decl.LogKeyClientID, *clientId,
			decl.LogKeyClientName, clientName,
			decl.LogKeyAuthSubject, consentRequest.GetSubject(),
			decl.LogKeyAuthChallenge, consentChallenge,
			decl.LogKeyUriPath, viper.GetString("consent_page"),
		)
	} else {
		var session *openapi.AcceptOAuth2ConsentRequestSession

		consentContext := consentRequest.GetContext()
		acceptedScopes := consentRequest.GetRequestedScope()
		rememberFor := int64(viper.GetInt("login_remember_for"))

		util.DebugModule(
			decl.DbgHydra,
			decl.LogKeyGUID, guid,
			"accepted_scopes", fmt.Sprintf("%+v", acceptedScopes),
		)

		needClaims := false

		for index := range acceptedScopes {
			if acceptedScopes[index] != decl.ScopeOpenId {
				continue
			}

			needClaims = true

			break
		}

		if needClaims {
			util.DebugModule(
				decl.DbgHydra,
				decl.LogKeyGUID, guid,
				decl.LogKeyMsg, "Scope 'openid' found, need claims",
			)

			session = getClaimsFromConsentContext(guid, acceptedScopes, consentContext)
		}

		acceptConsentRequest := apiClient.OAuth2Api.AcceptOAuth2ConsentRequest(ctx).AcceptOAuth2ConsentRequest(
			openapi.AcceptOAuth2ConsentRequest{
				GrantAccessTokenAudience: consentRequest.GetRequestedAccessTokenAudience(),
				GrantScope:               acceptedScopes,
				Remember: func() *bool {
					if skipConsent {
						remember := false

						return &remember
					}

					return consentRequest.Skip
				}(),
				RememberFor: &rememberFor,
				Session:     session,
			})

		acceptRequest, httpResponse, err = acceptConsentRequest.ConsentChallenge(consentChallenge).Execute()
		if err != nil {
			handleHydraErr(ctx, err, httpResponse)

			return
		}

		ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeySkip, true,
			decl.LogKeyClientID, *clientId,
			decl.LogKeyClientName, clientName,
			decl.LogKeyAuthSubject, consentRequest.GetSubject(),
			decl.LogKeyAuthChallenge, consentChallenge,
			decl.LogKeyAuthStatus, decl.LogKeyAuthAccept,
			decl.LogKeyUriPath, viper.GetString("consent_page"),
			decl.LogKeyRedirectTo, acceptRequest.GetRedirectTo(),
		)
	}
}

// Page '/consent/post'
func consentPOSTHandler(ctx *gin.Context) {
	var (
		err            error
		clientId       *string
		guid           = ctx.Value(decl.GUIDKey).(string)
		consentRequest *openapi.OAuth2ConsentRequest
		acceptRequest  *openapi.OAuth2RedirectTo
		rejectRequest  *openapi.OAuth2RedirectTo
		httpResponse   *http.Response
	)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("http_client_skip_tls_verify")},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	consentChallenge := ctx.PostForm("ory.hydra.consent_challenge")
	if consentChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	configuration := openapi.NewConfiguration()
	configuration.HTTPClient = httpClient
	configuration.Servers = []openapi.ServerConfiguration{
		{
			URL: viper.GetString("hydra_admin_uri"), // Admin API
		},
	}

	apiClient := openapi.NewAPIClient(configuration)

	consentRequest, httpResponse, err = apiClient.OAuth2Api.GetOAuth2ConsentRequest(ctx).ConsentChallenge(
		consentChallenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	oauth2Client := consentRequest.GetClient()

	clientIdFound := false
	if clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		handleErr(ctx, errors2.ErrHydraNoClientId)

		return
	}

	clientName := oauth2Client.GetClientName()

	if ctx.Request.Form.Get("submit") == "accept" {
		var (
			session        *openapi.AcceptOAuth2ConsentRequestSession
			acceptedScopes []string
		)

		requestedScopes := consentRequest.GetRequestedScope()
		consentContext := consentRequest.GetContext()

		// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
		for index := range requestedScopes {
			if ctx.PostForm(requestedScopes[index]) == "on" {
				acceptedScopes = append(acceptedScopes, requestedScopes[index])
			}
		}

		util.DebugModule(
			decl.DbgHydra,
			decl.LogKeyGUID, guid,
			"accepted_scopes", fmt.Sprintf("%+v", acceptedScopes),
		)

		needClaims := false

		for index := range acceptedScopes {
			if acceptedScopes[index] != decl.ScopeOpenId {
				continue
			}

			needClaims = true

			break
		}

		if needClaims {
			util.DebugModule(decl.DbgHydra, decl.LogKeyGUID, guid, decl.LogKeyMsg, "Scope 'openid' found, need claims")

			session = getClaimsFromConsentContext(guid, acceptedScopes, consentContext)
		}

		rememberFor := int64(viper.GetInt("login_remember_for"))
		remember := false

		if ctx.PostForm("remember") == "on" {
			remember = true
		}

		acceptConsentRequest := apiClient.OAuth2Api.AcceptOAuth2ConsentRequest(ctx).AcceptOAuth2ConsentRequest(
			openapi.AcceptOAuth2ConsentRequest{
				GrantAccessTokenAudience: consentRequest.GetRequestedAccessTokenAudience(),
				GrantScope:               acceptedScopes,
				Remember:                 &remember,
				RememberFor:              &rememberFor,
				Session:                  session,
			})

		acceptRequest, httpResponse, err = acceptConsentRequest.ConsentChallenge(consentChallenge).Execute()
		if err != nil {
			handleHydraErr(ctx, err, httpResponse)

			return
		}

		ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeyClientID, *clientId,
			decl.LogKeyClientName, clientName,
			decl.LogKeyAuthSubject, consentRequest.GetSubject(),
			decl.LogKeyAuthChallenge, consentChallenge,
			decl.LogKeyAuthStatus, decl.LogKeyAuthAccept,
			decl.LogKeyUriPath, viper.GetString("consent_page")+"/post",
			decl.LogKeyRedirectTo, acceptRequest.GetRedirectTo(),
		)
	} else {
		var (
			redirectTo *string
			isSet      bool
		)

		errorDescription := "Access denied by user"
		statusCode := int64(http.StatusForbidden)

		rejectConsentRequest := apiClient.OAuth2Api.RejectOAuth2ConsentRequest(ctx).RejectOAuth2Request(
			openapi.RejectOAuth2Request{
				ErrorDescription: &errorDescription,
				ErrorHint:        nil,
				StatusCode:       &statusCode,
			})

		rejectRequest, httpResponse, err = rejectConsentRequest.ConsentChallenge(consentChallenge).Execute()
		if err != nil {
			handleHydraErr(ctx, err, httpResponse)

			return
		}

		if redirectTo, isSet = rejectRequest.GetRedirectToOk(); isSet {
			ctx.Redirect(http.StatusFound, *redirectTo)
		} else {
			redirectToValue := "unknown"
			redirectTo = &redirectToValue

			ctx.String(http.StatusForbidden, decl.PasswordFail)
		}

		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeyClientID, *clientId,
			decl.LogKeyClientName, clientName,
			decl.LogKeyAuthSubject, consentRequest.GetSubject(),
			decl.LogKeyAuthChallenge, consentChallenge,
			decl.LogKeyAuthStatus, decl.LogKeyAuthReject,
			decl.LogKeyUriPath, viper.GetString("consent_page")+"/post",
			decl.LogKeyRedirectTo, *redirectTo,
		)
	}
}

// Page '/logout'
func logoutGETHandler(ctx *gin.Context) {
	var (
		languagePassive []Language
		err             error
		guid            = ctx.Value(decl.GUIDKey).(string)
		csrfToken       = ctx.Value(decl.CSRFTokenKey).(string)
		logoutRequest   *openapi.OAuth2LogoutRequest
		httpResponse    *http.Response
	)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("http_client_skip_tls_verify")},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	postLogout := ctx.Query("logout")
	if postLogout == "1" {
		redirectTo := viper.GetString("homepage")
		if redirectTo != "" {
			ctx.Redirect(http.StatusFound, redirectTo)
		} else {
			ctx.AbortWithStatus(http.StatusOK)
		}

		return
	}

	logoutChallenge := ctx.Query("logout_challenge")
	if logoutChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	configuration := openapi.NewConfiguration()
	configuration.HTTPClient = httpClient
	configuration.Servers = []openapi.ServerConfiguration{
		{
			URL: viper.GetString("hydra_admin_uri"), // Admin API
		},
	}

	apiClient := openapi.NewAPIClient(configuration)

	logoutRequest, httpResponse, err = apiClient.OAuth2Api.GetOAuth2LogoutRequest(ctx).LogoutChallenge(
		logoutChallenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	if logoutRequest.GetRpInitiated() {
		// We could skip the UI
		util.DebugModule(decl.DbgHydra, decl.LogKeyGUID, guid, decl.LogKeyMsg, "rp_initiated==true")
	}

	session := sessions.Default(ctx)
	cookieValue := session.Get(decl.CookieLang)

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
				LanguageLink: viper.GetString("logout_page") + "/" + baseName.String() + "?" + ctx.Request.URL.RawQuery,
				LanguageName: languageName,
			},
		)
	}

	logoutData := &LogoutPageData{
		Title: getLocalized(ctx, "Logout"),
		WantWelcome: func() bool {
			if viper.GetString("login_page_welcome") != "" {
				return true
			}

			return false
		}(),
		Welcome:             viper.GetString("logout_page_welcome"),
		LogoutMessage:       getLocalized(ctx, "Do you really want to log out?"),
		AcceptSubmit:        getLocalized(ctx, "Yes"),
		RejectSubmit:        getLocalized(ctx, "No"),
		LanguageTag:         session.Get(decl.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
		LogoutChallenge:     logoutChallenge,
		PostLogoutEndpoint:  viper.GetString("logout_page"),
	}

	ctx.HTML(http.StatusOK, "logout.html", logoutData)

	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyGUID, guid,
		decl.LogKeyAuthSubject, logoutRequest.GetSubject(),
		decl.LogKeyAuthChallenge, logoutChallenge,
		decl.LogKeyUriPath, viper.GetString("logout_page"),
	)
}

// Page '/logout/post'
func logoutPOSTHandler(ctx *gin.Context) {
	var (
		err           error
		guid          = ctx.Value(decl.GUIDKey).(string)
		logoutRequest *openapi.OAuth2LogoutRequest
		acceptRequest *openapi.OAuth2RedirectTo
		httpResponse  *http.Response
	)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("http_client_skip_tls_verify")},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	logoutChallenge := ctx.PostForm("ory.hydra.logout_challenge")
	if logoutChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	configuration := openapi.NewConfiguration()
	configuration.HTTPClient = httpClient
	configuration.Servers = []openapi.ServerConfiguration{
		{
			URL: viper.GetString("hydra_admin_uri"), // Admin API
		},
	}

	apiClient := openapi.NewAPIClient(configuration)

	logoutRequest, httpResponse, err = apiClient.OAuth2Api.GetOAuth2LogoutRequest(ctx).LogoutChallenge(
		logoutChallenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	if ctx.PostForm("submit") == "accept" {
		acceptLogoutRequest := apiClient.OAuth2Api.AcceptOAuth2LogoutRequest(ctx)

		acceptRequest, httpResponse, err = acceptLogoutRequest.LogoutChallenge(logoutChallenge).Execute()
		if err != nil {
			handleHydraErr(ctx, err, httpResponse)

			return
		}

		ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeyAuthSubject, logoutRequest.GetSubject(),
			decl.LogKeyAuthChallenge, logoutChallenge,
			decl.LogKeyAuthStatus, decl.LogKeyAuthAccept,
			decl.LogKeyUriPath, viper.GetString("logout_page")+"/post",
			decl.LogKeyRedirectTo, acceptRequest.GetRedirectTo(),
		)
	} else {
		rejectLogoutRequest := apiClient.OAuth2Api.RejectOAuth2LogoutRequest(ctx)

		httpResponse, err = rejectLogoutRequest.LogoutChallenge(logoutChallenge).Execute()
		if err != nil {
			handleHydraErr(ctx, err, httpResponse)

			return
		}

		redirectTo := viper.GetString("homepage")
		if redirectTo != "" {
			ctx.Redirect(http.StatusFound, redirectTo)
		} else {
			redirectTo = "unknown"
			ctx.AbortWithStatus(http.StatusOK)
		}

		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeyAuthSubject, logoutRequest.GetSubject(),
			decl.LogKeyAuthChallenge, logoutChallenge,
			decl.LogKeyAuthStatus, decl.LogKeyAuthReject,
			decl.LogKeyUriPath, viper.GetString("logout_page")+"/post",
			decl.LogKeyRedirectTo, redirectTo,
		)
	}
}

func getClaimsFromConsentContext(guid string, acceptedScopes []string, consentContext any) (
	session *openapi.AcceptOAuth2ConsentRequestSession,
) {
	var (
		assertOk  bool
		claimDict map[string]any
	)

	if claimDict, assertOk = consentContext.(map[string]any); !assertOk {
		return
	}

	claims := make(map[string]any)

	for index := range acceptedScopes {
		if acceptedScopes[index] == decl.ScopeProfile {
			if value, found := claimDict[decl.ClaimName].(string); found {
				claims[decl.ClaimName] = value
			}

			if value, found := claimDict[decl.ClaimGivenName].(string); found {
				claims[decl.ClaimGivenName] = value
			}

			if value, found := claimDict[decl.ClaimFamilyName].(string); found {
				claims[decl.ClaimFamilyName] = value
			}

			if value, found := claimDict[decl.ClaimMiddleName].(string); found {
				claims[decl.ClaimMiddleName] = value
			}

			if value, found := claimDict[decl.ClaimNickName].(string); found {
				claims[decl.ClaimNickName] = value
			}

			if value, found := claimDict[decl.ClaimPreferredUserName].(string); found {
				claims[decl.ClaimPreferredUserName] = value
			}

			if value, found := claimDict[decl.ClaimProfile].(string); found {
				claims[decl.ClaimProfile] = value
			}

			if value, found := claimDict[decl.ClaimWebsite].(string); found {
				claims[decl.ClaimWebsite] = value
			}

			if value, found := claimDict[decl.ClaimPicture].(string); found {
				claims[decl.ClaimPicture] = value
			}

			if value, found := claimDict[decl.ClaimGender].(string); found {
				claims[decl.ClaimGender] = value
			}

			if value, found := claimDict[decl.ClaimBirtDate].(string); found {
				claims[decl.ClaimBirtDate] = value
			}

			if value, found := claimDict[decl.ClaimZoneInfo].(string); found {
				claims[decl.ClaimZoneInfo] = value
			}

			if value, found := claimDict[decl.ClaimLocale].(string); found {
				claims[decl.ClaimLocale] = value
			}

			if value, found := claimDict[decl.ClaimUpdatedAt].(float64); found {
				claims[decl.ClaimUpdatedAt] = value
			}
		}

		if acceptedScopes[index] == decl.ScopeEmail {
			if value, found := claimDict[decl.ClaimEmail].(string); found {
				claims[decl.ClaimEmail] = value
			}

			if value, found := claimDict[decl.ClaimEmailVerified].(bool); found {
				claims[decl.ClaimEmailVerified] = value
			}
		}

		if acceptedScopes[index] == decl.ScopeAddress {
			claims[decl.ClaimAddress] = claimDict[decl.ClaimAddress]
		}

		if acceptedScopes[index] == decl.ScopePhone {
			if value, found := claimDict[decl.ClaimPhoneNumber].(string); found {
				claims[decl.ClaimPhoneNumber] = value
			}

			if value, found := claimDict[decl.ClaimPhoneNumberVerified].(bool); found {
				claims[decl.ClaimPhoneNumberVerified] = value
			}
		}

		if acceptedScopes[index] == decl.ScopeGroups {
			util.DebugModule(
				decl.DbgHydra,
				decl.LogKeyGUID, guid,
				"groups", fmt.Sprintf("%#v", claimDict[decl.ClaimGroups]),
			)

			if value, found := claimDict[decl.ClaimGroups].([]any); found {
				var stringSlice []string

				for anyIndex := range value {
					if arg, assertOk := value[anyIndex].(string); assertOk {
						stringSlice = append(stringSlice, arg)
					}
				}

				claims[decl.ClaimGroups] = value
			}
		}

		for scopeIndex := range config.LoadableConfig.Oauth2.CustomScopes {
			customScope := config.LoadableConfig.Oauth2.CustomScopes[scopeIndex]

			if acceptedScopes[index] != customScope.Name {
				continue
			}

			for claimIndex := range customScope.Claims {
				customClaimName := customScope.Claims[claimIndex].Name
				customClaimType := customScope.Claims[claimIndex].Type
				valueTypeMatch := false

				util.DebugModule(
					decl.DbgHydra,
					decl.LogKeyGUID, guid,
					"custom_claim_name", customClaimName,
					"custom_claim_type", customClaimType,
					"value", fmt.Sprintf("%#v", claimDict[customClaimName]),
				)

				if customClaimType == decl.ClaimTypeString {
					if value, found := claimDict[customClaimName].(string); found {
						claims[customClaimName] = value
						valueTypeMatch = true
					}
				} else if customClaimType == decl.ClaimTypeFloat {
					if value, found := claimDict[customClaimName].(float64); found {
						claims[customClaimName] = value
						valueTypeMatch = true
					}
				} else if customClaimType == decl.ClaimTypeInteger {
					if value, found := claimDict[customClaimName].(int64); found {
						claims[customClaimName] = value
						valueTypeMatch = true
					} else if value, found := claimDict[customClaimName].(float64); found {
						// XXX: It may happen that the integer is represented as exponential value :-/
						claims[customClaimName] = int64(value)
						valueTypeMatch = true
					}
				} else if customClaimType == decl.ClaimTypeBoolean {
					if value, found := claimDict[customClaimName].(bool); found {
						claims[customClaimName] = value
						valueTypeMatch = true
					}
				}

				if !valueTypeMatch {
					level.Error(logging.DefaultErrLogger).Log(
						decl.LogKeyGUID, guid,
						"custom_claim_name", customClaimName,
						decl.LogKeyError, fmt.Sprintf("Unknown type '%s'", customClaimType),
					)
				}
			}

			break
		}
	}

	util.DebugModule(decl.DbgHydra, decl.LogKeyGUID, guid, "claims", fmt.Sprintf("%+v", claims))

	session = &openapi.AcceptOAuth2ConsentRequestSession{
		IdToken: claims,
	}

	return
}
