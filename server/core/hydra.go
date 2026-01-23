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

// See the markdown documentation for the login-, two-factor-, consent- and logout pages for a brief description.

import (
	"context"
	stderrors "errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/frontend"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/tags"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/sessions"

	"github.com/gin-gonic/gin"
	"github.com/justinas/nosurf"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	openapi "github.com/ory/hydra-client-go/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
	_ "golang.org/x/text/message/catalog"
)

// httpClient is a pre-configured instance of http.Client with custom timeout and TLS settings for making HTTP requests.
var httpClient *http.Client

// InitHTTPClient initializes the global httpClient variable with a pre-configured instance from util.NewHTTPClient.
func InitHTTPClient(cfg config.File) {
	httpClient = util.NewHTTPClientWithCfg(cfg)
}

// ApiConfig is a struct that encapsulates configuration and parameters for
// HTTP communication with OAuth2 OpenID-Connect server via OpenAPI. This includes
// configurations for HTTP client, authorization parameters, and request context.
type ApiConfig struct {
	// deps holds the authentication dependencies.
	deps AuthDeps

	// httpClient is a configured HTTP client used to establish connections to the OAuth2 OpenID-connect server.
	httpClient *http.Client

	// apiClient holds the client information to interact with the OpenAPI.
	apiClient *openapi.APIClient

	// ctx provides context for HTTP request made against Gin framework.
	ctx *gin.Context

	// loginRequest is used to store parameters required for OAuth2LoginRequest.
	loginRequest *openapi.OAuth2LoginRequest

	// consentRequest is used to store parameters required for OAuth2ConsentRequest.
	consentRequest *openapi.OAuth2ConsentRequest

	// logoutRequest is used to store parameters required for OAuth2LogoutRequest.
	logoutRequest *openapi.OAuth2LogoutRequest

	// clientId holds client identification which is unique for each application.
	clientId *string

	// guid is a unique identifier for a specific message or request.
	guid string

	// csrfToken is used to prevent Cross-Site Request Forgery.
	csrfToken string

	// clientName holds the name of the client application.
	clientName string

	// challenge is a unique string used in the authorization process.
	challenge string
}

// HandleErr handles an error by logging the error details and printing a goroutine dump.
func (h *HydraHandlers) HandleErr(ctx *gin.Context, err error) {
	HandleHydraErrWithDeps(ctx, err, h.deps)
}

// HandleHydraErrWithDeps is the Hydra specific error handler.
func HandleHydraErrWithDeps(ctx *gin.Context, err error, deps AuthDeps) {
	processErrorLogging(ctx, err, deps)
	sessionCleaner(ctx)
	ctx.Set(definitions.CtxFailureKey, true)
	ctx.Set(definitions.CtxMessageKey, err)

	h := NewHydraHandlers(deps)
	h.NotifyGETHandler(ctx)
}

// processErrorLogging logs the error details and prints a goroutine dump.
func processErrorLogging(ctx *gin.Context, err error, deps AuthDeps) {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	logError(ctx, err, deps)

	if deps.Cfg.GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug && deps.Env.GetDevMode() {
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, false)

		fmt.Printf("=== guid=%s\n*** goroutine dump...\n%s\n*** end\n", guid, buf[:stackLen])
	}
}

// logError logs the error details along with the corresponding GUID, client IP, and error message.
func logError(ctx *gin.Context, err error, deps AuthDeps) {
	var detailedError *errors.DetailedError

	guid := ctx.GetString(definitions.CtxGUIDKey)

	if stderrors.As(err, &detailedError) {
		level.Error(deps.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, (*detailedError).GetDetails(),
			definitions.LogKeyError, (*detailedError).Error(),
			definitions.LogKeyClientIP, ctx.Request.RemoteAddr,
		)
	} else {
		level.Error(deps.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "An error occurred",
			definitions.LogKeyError, err,
			definitions.LogKeyClientIP, ctx.Request.RemoteAddr,
		)
	}
}

// handleHydraErr handles an error by checking the status code of the http response.
func handleHydraErr(ctx *gin.Context, err error, httpResponse *http.Response, deps AuthDeps) {
	if httpResponse != nil {
		switch httpResponse.StatusCode {
		case http.StatusNotFound:
			HandleHydraErrWithDeps(ctx, errors.ErrUnknownJSON, deps)
		case http.StatusGone:
			HandleHydraErrWithDeps(ctx, errors.ErrHTTPRequestGone, deps)
		default:
			HandleHydraErrWithDeps(ctx, err, deps)
		}
	} else {
		HandleHydraErrWithDeps(ctx, err, deps)
	}
}

// setLanguageDetails determines the language details based on the provided langFromURL and langFromCookie parameters.
// It returns the selected lang, needCookie, and needRedirect values.
// The algorithm for determining the values is as follows:
//
// 1. If there is no language from the URL and no cookie is set, set needCookie and needRedirect to true.
// 2. If there is no language from the URL but a cookie is set, set lang to langFromCookie and needRedirect to true.
// 3. If there is a language from the URL and no cookie, set lang to langFromURL and needCookie to true.
// 4. If there is a language from both the URL and the cookie, and they differ, set lang to langFromURL and needCookie to true.
//
// The function returns lang, needCookie, and needRedirect.
//
//goland:noinspection GoDfaConstantCondition
func (h *HydraHandlers) setLanguageDetails(langFromURL string, langFromCookie string) (lang string, needCookie bool, needRedirect bool) {
	switch {
	case langFromURL == "" && langFromCookie == "":
		// 1. No language from URL and no cookie is set
		lang = h.deps.Cfg.GetServer().Frontend.GetDefaultLanguage()
		needCookie = true
		needRedirect = true
	case langFromURL == "" && langFromCookie != "":
		// 2. No language from URL, but a cookie is set
		lang = langFromCookie
		needRedirect = true
	case langFromURL != "" && langFromCookie == "":
		// 3. Language from URL and no cookie
		lang = langFromURL
		needCookie = true
	case langFromURL != "" && langFromCookie != "":
		// 4. Langauge given from URL and cookie, but both differ
		if langFromURL != langFromCookie {
			needCookie = true
		}

		lang = langFromURL
	}

	return lang, needCookie, needRedirect
}

// WithLanguageMiddleware is a middleware function that handles the language setup for the application.
func WithLanguageMiddleware(deps AuthDeps) gin.HandlerFunc {
	h := NewHydraHandlers(deps)

	return h.WithLanguageMiddleware()
}

// WithLanguageMiddleware is a middleware function that handles the language setup for the application.
// It tries to get the language tag from the URL and the cookie.
// It sets the language details and creates a localizer based on the selected language.
// It also handles CSRF token and localization in the context.
// If the language is not found in the catalog, it aborts the request with a "Language Not Found" error.
// If the language needs to be saved in a cookie or redirection is required, it does so accordingly.
// Finally, it calls the next handler in the chain.
func (h *HydraHandlers) WithLanguageMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			langFromURL    string
			langFromCookie string
		)

		guid := ctx.GetString(definitions.CtxGUIDKey)

		// Try to get language tag from URL
		langFromURL = ctx.Param("languageTag")

		// Try to get language tag from cookie
		session := sessions.Default(ctx)

		cookieValue := session.Get(definitions.CookieLang)
		if cookieValue != nil {
			langFromCookie, _ = cookieValue.(string)
		}

		lang, needCookie, needRedirect := h.setLanguageDetails(langFromURL, langFromCookie)
		accept := ctx.GetHeader("Accept-Language")
		tag, _ := language.MatchStrings(config.Matcher, lang, accept)
		baseName, _ := tag.Base()

		util.DebugModuleWithCfg(
			ctx,
			h.deps.Cfg,
			h.deps.Logger,
			definitions.DbgHydra,
			definitions.LogKeyGUID, guid,
			"accept", accept,
			"language", lang,
			"language_tag", fmt.Sprintf("%v", baseName.String()),
		)

		// Language not found in catalog
		if lang != "" && lang != baseName.String() {
			ctx.AbortWithError(http.StatusNotFound, errors.ErrLanguageNotFound)

			return
		}

		localizer := i18n.NewLocalizer(LangBundle, lang, accept)

		if needCookie {
			session.Set(definitions.CookieLang, baseName.String())
			err := session.Save()
			if err != nil {
				level.Error(h.deps.Logger).Log(
					definitions.LogKeyGUID, guid,
					definitions.LogKeyMsg, "Failed to save session",
					definitions.LogKeyError, err,
				)
			}
		}

		ctx.Set(definitions.CtxCSRFTokenKey, nosurf.Token(ctx.Request))
		ctx.Set(definitions.CtxLocalizedKey, localizer)

		if needRedirect {
			var sb strings.Builder

			sb.WriteString(ctx.Request.URL.Path)
			sb.WriteByte('/')
			sb.WriteString(baseName.String())
			sb.WriteByte('?')
			sb.WriteString(ctx.Request.URL.RawQuery)

			ctx.Redirect(http.StatusFound, sb.String())

			return
		}

		ctx.Next()
	}
}

// createConfiguration returns a new instance of the openapi.Configuration struct with the provided httpClient and server configuration.
// The httpClient parameter is used as the underlying HTTP client for API calls made by the openapi.client.
// The server configuration is read from the "hydra_admin_uri" configuration value using viper.GetString() function.
func createConfiguration(cfg config.File, httpClient *http.Client) *openapi.Configuration {
	return &openapi.Configuration{
		HTTPClient: httpClient,
		Servers:    []openapi.ServerConfiguration{{URL: cfg.GetServer().Frontend.GetHydraAdminUri()}},
	}
}

// initialize sets up the `ApiConfig` object by initializing the HTTP client, GUID, and API client.
// Must be called before using any other methods on `ApiConfig`.
//
// Example usage:
//
//	apiConfig := &ApiConfig{ctx: ctx}
//	apiConfig.initialize()
//
//	// Use the initialized `ApiConfig` object
//	apiConfig.handleLogin(apiConfig.loginRequest.GetSkip())
//
// Dependencies:
// - `createHttpClient` function
// - `createConfiguration` function
//
// Note: This method assumes that the `ApiConfig` object is properly initialized with the `ctx` field set.
func (a *ApiConfig) initialize() {
	a.httpClient = httpClient
	a.guid = a.ctx.GetString(definitions.CtxGUIDKey)
	configuration := createConfiguration(a.deps.Cfg, a.httpClient)
	a.apiClient = openapi.NewAPIClient(configuration)
}

// handleLogin handles the login process based on the value of `skip`.
//
// If `skip` is true, it calls the `handleLoginSkip` method.
// If `skip` is false, it calls the `handleLoginNoSkip` method.
//
// Example usage:
//
//	apiConfig := &ApiConfig{ctx: ctx}
//	apiConfig.initialize()
//	apiConfig.handleLogin(apiConfig.loginRequest.GetSkip())
//
// Dependencies:
// - `handleLoginSkip` method
// - `handleLoginNoSkip` method
func (a *ApiConfig) handleLogin(ctx *gin.Context, skip bool) {
	util.DebugModuleWithCfg(ctx.Request.Context(), a.deps.Cfg, a.deps.Logger, definitions.DbgHydra, definitions.LogKeyGUID, a.guid, definitions.LogKeyMsg, fmt.Sprintf("%s is %v", definitions.LogKeyLoginSkip, skip))

	if skip {
		a.handleLoginSkip(ctx)
	} else {
		a.handleLoginNoSkip()
	}
}

// handleLoginSkip processes the login request when skip is true.
func (a *ApiConfig) handleLoginSkip(ctx *gin.Context) {
	var (
		err           error
		acceptRequest *openapi.OAuth2RedirectTo
		httpResponse  *http.Response
		subject       string
		claims        map[string]any
	)

	util.DebugModuleWithCfg(a.ctx.Request.Context(), a.deps.Cfg, a.deps.Logger, definitions.DbgHydra, definitions.LogKeyGUID, a.guid, definitions.LogKeyMsg, fmt.Sprintf("%s is %v", definitions.LogKeyLoginSkip, true))

	oauth2Client := a.loginRequest.GetClient()

	auth := NewAuthStateFromContextWithDeps(a.ctx, a.deps)

	auth.SetNoAuth(true)
	auth.SetProtocol(config.NewProtocol(definitions.ProtoOryHydra))
	auth.WithDefaults(a.ctx).WithClientInfo(a.ctx).WithLocalInfo(a.ctx).WithUserAgent(a.ctx).WithXSSL(a.ctx).InitMethodAndUserAgent()
	auth.SetUsername(a.loginRequest.GetSubject())
	auth.SetStatusCodes(definitions.ServOryHydra)

	if authStatus := auth.HandlePassword(a.ctx); authStatus == definitions.AuthResultOK {
		if a.deps.Cfg.GetOauth2() != nil {
			subject, claims = auth.GetOauth2SubjectAndClaims(oauth2Client)
		}
	} else {
		auth.SetClientIP(a.ctx.GetString(definitions.CtxClientIPKey))

		auth.UpdateBruteForceBucketsCounter(ctx)
		a.ctx.AbortWithError(http.StatusInternalServerError, errors.ErrUnknownCause)

		return
	}

	if subject == "" {
		subject = a.loginRequest.GetSubject()
	}

	acceptLoginRequest := a.apiClient.OAuth2API.AcceptOAuth2LoginRequest(a.ctx).AcceptOAuth2LoginRequest(
		openapi.AcceptOAuth2LoginRequest{
			Subject: subject,
			Context: claims,
		})

	acceptRequest, httpResponse, err = acceptLoginRequest.LoginChallenge(a.challenge).Execute()
	if err != nil {
		handleHydraErr(a.ctx, err, httpResponse, a.deps)

		return
	}

	a.ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

	a.logInfoLoginSkip()
}

// handleLoginNoSkip handles the login process when skip is false.
//
// It retrieves the necessary information from the OAuth2 client, such as image URI, policy URI,
// terms of service URI, and client URI. It also retrieves the application name from the client and
// creates the user data and language information.
//
// If the pre2FA flag is set and the user has already authenticated, it handles the TOTP (Time-based
// One-Time Password) request and returns the HTML response to the client with two factor authentication data.
//
// If the _error query parameter is not empty, it sets the haveError flag and retrieves the error message.
//
// Finally, it constructs the login page data and returns the HTML response to the client with the login data.
//
// Dependencies:
// - getLocalized function
// - createLanguagePassive function
// - TwoFactorData struct
// - LoginPageData struct
func (a *ApiConfig) handleLoginNoSkip() {
	var (
		wantAbout    bool
		wantPolicy   bool
		wantTos      bool
		haveError    bool
		policyUri    string
		tosUri       string
		clientUri    string
		imageUri     string
		errorMessage string
	)

	util.DebugModuleWithCfg(a.ctx.Request.Context(), a.deps.Cfg, a.deps.Logger, definitions.DbgHydra, definitions.LogKeyGUID, a.guid, definitions.LogKeyMsg, fmt.Sprintf("%s is %v", definitions.LogKeyLoginSkip, false))

	oauth2Client := a.loginRequest.GetClient()

	imageUri = oauth2Client.GetLogoUri()
	if imageUri == "" {
		imageUri = a.deps.Cfg.GetServer().Frontend.GetDefaultLogoImage()
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
	session := sessions.Default(a.ctx)

	cookieValue := session.Get(definitions.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(a.ctx, a.deps.Cfg, a.deps.Cfg.GetServer().Frontend.GetLoginPage(), config.DefaultLanguageTags, languageCurrentName)

	userData := frontend.CreateUserdata(session, definitions.CookieUsername, definitions.CookieAuthResult)

	// Handle TOTP request
	if authResult, found := userData[definitions.CookieAuthResult]; found {
		if authResult != definitions.AuthResultUnset {
			twoFactorData := &frontend.TwoFactorData{
				Title: frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Login"),
				WantWelcome: func() bool {
					if a.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
						return true
					}

					return false
				}(),
				Welcome:             a.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome(),
				ApplicationName:     applicationName,
				WantAbout:           wantAbout,
				About:               frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Get further information about this application..."),
				AboutUri:            clientUri,
				LogoImage:           imageUri,
				LogoImageAlt:        a.deps.Cfg.GetServer().Frontend.GetLoginPageLogoImageAlt(),
				WantPolicy:          wantPolicy,
				Code:                frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "OTP-Code"),
				Policy:              frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Privacy policy"),
				PolicyUri:           policyUri,
				WantTos:             wantTos,
				Tos:                 frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Terms of service"),
				TosUri:              tosUri,
				Submit:              frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Submit"),
				PostLoginEndpoint:   a.deps.Cfg.GetServer().Frontend.GetLoginPage(),
				LanguageTag:         session.Get(definitions.CookieLang).(string),
				LanguageCurrentName: languageCurrentName,
				LanguagePassive:     languagePassive,
				CSRFToken:           a.csrfToken,
				LoginChallenge:      a.challenge,
			}

			a.ctx.HTML(http.StatusOK, "totp.html", twoFactorData)

			util.DebugModuleWithCfg(
				a.ctx.Request.Context(),
				a.deps.Cfg,
				a.deps.Logger,
				definitions.DbgHydra,
				definitions.LogKeyGUID, a.guid,
				definitions.LogKeyMsg, "Two factor authentication",
				definitions.LogKeyUsername, userData[definitions.CookieUsername].(string),
				definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
			)

			return
		}
	}

	if errorMessage = a.ctx.Query("_error"); errorMessage != "" {
		if errorMessage == definitions.PasswordFail {
			errorMessage = frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, definitions.PasswordFail)
		}

		haveError = true
	}

	loginData := &frontend.LoginPageData{
		Title: frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Login"),
		WantWelcome: func() bool {
			if a.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
				return true
			}

			return false
		}(),
		Welcome:             a.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome(),
		ApplicationName:     applicationName,
		WantAbout:           wantAbout,
		About:               frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Get further information about this application..."),
		AboutUri:            clientUri,
		LogoImage:           imageUri,
		LogoImageAlt:        a.deps.Cfg.GetServer().Frontend.GetLoginPageLogoImageAlt(),
		HaveError:           haveError,
		ErrorMessage:        errorMessage,
		Login:               frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Login"),
		Privacy:             frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "We'll never share your data with anyone else."),
		LoginPlaceholder:    frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Please enter your username or email address"),
		Password:            frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Password"),
		PasswordPlaceholder: frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Please enter your password"),
		WantPolicy:          wantPolicy,
		Policy:              frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Privacy policy"),
		PolicyUri:           policyUri,
		WantTos:             wantTos,
		Tos:                 frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Terms of service"),
		TosUri:              tosUri,
		Remember:            frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Remember me"),
		Submit:              frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Submit"),
		Or:                  frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "or"),
		Device:              frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Login with WebAuthn"),
		PostLoginEndpoint:   a.deps.Cfg.GetServer().Frontend.GetLoginPage(),
		DeviceLoginEndpoint: a.deps.Cfg.GetServer().Frontend.GetDevicePage(),
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           a.csrfToken,
		LoginChallenge:      a.challenge,
		WantRemember:        true,
		InDevelopment:       tags.IsDevelopment,
	}

	a.ctx.HTML(http.StatusOK, "login.html", loginData)

	a.logInfoLoginNoSkip()
}

// logInfoLoginSkip logs the login skip event with the provided details.
func (a *ApiConfig) logInfoLoginSkip() {
	level.Info(a.deps.Logger).Log(
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeySkip, true,
		definitions.LogKeyClientID, *a.clientId,
		definitions.LogKeyClientName, a.clientName,
		definitions.LogKeyAuthSubject, a.loginRequest.GetSubject(),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthAccept,
		definitions.LogKeyUriPath, a.deps.Cfg.GetServer().Frontend.GetLoginPage(),
		definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
	)
}

// logInfoLoginNoSkip logs information about the login operation without skipping any step.
func (a *ApiConfig) logInfoLoginNoSkip() {
	level.Info(a.deps.Logger).Log(
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeySkip, false,
		definitions.LogKeyClientID, *a.clientId,
		definitions.LogKeyClientName, a.clientName,
		definitions.LogKeyUriPath, a.deps.Cfg.GetServer().Frontend.GetLoginPage(),
		definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
	)
}

// --- Login Block ---

// LoginGETHandler Page '/login'
func (h *HydraHandlers) LoginGETHandler(ctx *gin.Context) {
	var (
		err          error
		httpResponse *http.Response
	)

	loginChallenge := ctx.Query("login_challenge")
	if loginChallenge == "" {
		HandleHydraErrWithDeps(ctx, errors.ErrNoLoginChallenge, h.deps)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx, deps: h.deps}

	apiConfig.initialize()

	apiConfig.challenge = loginChallenge
	apiConfig.csrfToken = ctx.GetString(definitions.CtxCSRFTokenKey)

	apiConfig.loginRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2LoginRequest(ctx).LoginChallenge(
		apiConfig.challenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse, h.deps)

		return
	}

	oauth2Client := apiConfig.loginRequest.GetClient()

	clientIdFound := false
	if apiConfig.clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		HandleHydraErrWithDeps(ctx, errors.ErrHydraNoClientId, h.deps)

		return
	}

	apiConfig.clientName = oauth2Client.GetClientName()

	apiConfig.handleLogin(ctx, apiConfig.loginRequest.GetSkip())
}

// LoginGETHandler Page '/login' (legacy)
func LoginGETHandler(deps AuthDeps) gin.HandlerFunc {
	InitHTTPClient(deps.Cfg)

	return func(ctx *gin.Context) {
		h := NewHydraHandlers(deps)
		h.LoginGETHandler(ctx)
	}
}

// initializeAuthLogin initializes the AuthState struct with the necessary information for logging in.
func (h *HydraHandlers) initializeAuthLogin(ctx *gin.Context) (State, error) {
	auth := NewAuthStateFromContextWithDeps(ctx, h.deps)

	auth.SetProtocol(config.NewProtocol(definitions.ProtoOryHydra))
	auth.SetUsername(ctx.PostForm("username"))
	auth.SetPassword(ctx.PostForm("password"))

	// It might be the second call after 2FA! In this case, there does not exist any username or password.
	if auth.GetUsername() != "" && !util.ValidateUsername(auth.GetUsername()) {
		return nil, errors.ErrInvalidUsername
	}

	auth.SetStatusCodes(definitions.ServOryHydra)
	auth.WithDefaults(ctx).WithClientInfo(ctx).WithLocalInfo(ctx).WithUserAgent(ctx).WithXSSL(ctx).InitMethodAndUserAgent()

	if a, ok := auth.(*AuthState); ok {
		logProcessingRequest(ctx, a)
	}

	if reject := auth.PreproccessAuthRequest(ctx); reject {
		return nil, errors.ErrBruteForceAttack
	}

	return auth, nil
}

// handleSessionDataLogin retrieves session data related to the login process and populates the provided `auth` variable with the values.
//
// Parameters:
// - ctx: The gin context object.
// - auth: Pointer to an AuthState struct to populate with retrieved values.
//
// Returns:
// - authResult: The result of the authentication process (definitions.AuthResult enum).
// - recentSubject: The recently used subject value.
// - rememberPost2FA: The remember value after the second factor authentication.
// - post2FA: A bool indicating if a second factor authentication is required.
// - err: An error object if saving the session failed, or nil otherwise.
func handleSessionDataLogin(ctx *gin.Context, auth State) (
	authResult definitions.AuthResult, recentSubject string, rememberPost2FA string, post2FA bool, err error,
) {
	var cookieValue any

	session := sessions.Default(ctx)

	// Restore authentication data from first call to login.html
	if cookieValue = session.Get(definitions.CookieUsername); cookieValue != nil {
		if cookieValue.(string) != "" {
			auth.SetUsername(cookieValue.(string))
			auth.SetNoAuth(true)
		}

		session.Delete(definitions.CookieUsername)
	}

	if cookieValue = session.Get(definitions.CookieAuthResult); cookieValue != nil {
		authResult = definitions.AuthResult(cookieValue.(uint8))
		if authResult != definitions.AuthResultUnset {
			post2FA = true
		}

		session.Delete(definitions.CookieAuthResult)
	}

	if cookieValue = session.Get(definitions.CookieSubject); cookieValue != nil {
		recentSubject = cookieValue.(string)

		session.Delete(definitions.CookieSubject)
	}

	if cookieValue = session.Get(definitions.CookieRemember); cookieValue != nil {
		rememberPost2FA = cookieValue.(string)

		session.Delete(definitions.CookieRemember)
	}

	err = session.Save()
	if err != nil {
		return
	}

	return
}

// processAuthOkLogin processes the successful login authentication flow.
//
// Params:
// - auth: the AuthState object containing the authentication data
// - authResult: the AuthResult code indicating the authentication result
// - rememberPost2FA: a string indicating whether to remember the user after 2FA
// - recentSubject: the subject of the recent login attempt
// - post2FA: a boolean indicating whether this is a post-2FA login attempt
//
// Returns:
// - err: an error if any occurred during the process
func (a *ApiConfig) processAuthOkLogin(ctx *gin.Context, auth State, oldAuthResult definitions.AuthResult, rememberPost2FA string, recentSubject string, post2FA bool, needLuaFilterAndPost bool) (authResult definitions.AuthResult, err error) {
	var redirectFlag bool

	account, found := auth.GetAccountOk()
	if !found {
		return oldAuthResult, errors.ErrNoAccount
	}

	subject, claims := a.getSubjectAndClaims(account, auth)

	if post2FA {
		if recentSubject != subject {
			return oldAuthResult, errors.ErrNoAccount
		}

		err = a.handlePost2FA(auth, account)
		if err != nil {
			return oldAuthResult, err
		}
	} else {
		session := sessions.Default(a.ctx)

		redirectFlag, err = a.handleNonPost2FA(auth, session, oldAuthResult, subject)
		if err != nil {
			return oldAuthResult, err
		}

		if redirectFlag {
			return oldAuthResult, nil
		}

		if needLuaFilterAndPost {
			authResult = runLuaFilterAndPost(ctx, auth, oldAuthResult)

			if oldAuthResult != authResult {
				return authResult, nil
			}
		}
	}

	remember := a.isRemember(rememberPost2FA, post2FA)
	if _, err = a.acceptLogin(claims, subject, remember); err != nil {
		return oldAuthResult, err
	}

	a.logInfoLoginAccept(subject, auth)

	return oldAuthResult, nil
}

// getSubjectAndClaims retrieves the subject and claims for a given account and authentication object.
// If available, it uses the OAuth2 client to get the subject and claims from the authentication object.
// If the OAuth2 client is not available or the subject is empty, it uses the account as the subject.
// If the subject is empty, it logs a warning message using the `guid` field from the `ApiConfig` object and the account value.
// It returns the subject and claims as a string and map respectively.
func (a *ApiConfig) getSubjectAndClaims(account string, auth State) (string, map[string]any) {
	var (
		subject string
		claims  map[string]any
	)

	oauth2Client := a.loginRequest.GetClient()
	if a.deps.Cfg.GetOauth2() != nil {
		subject, claims = auth.GetOauth2SubjectAndClaims(oauth2Client)
	}

	if subject == "" {
		subject = account

		level.Warn(a.deps.Logger).Log(
			definitions.LogKeyGUID, a.guid,
			definitions.LogKeyMsg, fmt.Sprintf("Empty 'subject', using '%s' as value", account),
		)
	}

	return subject, claims
}

// handleNonPost2FA handles the logic for non-post 2FA authentication.
// It checks if 2FA authentication is skipped for the client, if not it checks if the TOTP secret exists.
// If the TOTP secret exists, it sets the session variables for authentication and redirects the request to the login page.
// Returns true if the redirection is performed, otherwise returns false.
// If an error occurs, it will be returned.
//
// Params:
// - auth: The AuthState object.
// - session: The session object.
// - authResult: The authentication result.
// - subject: The authentication subject.
//
// Returns:
// - bool: Indicates whether redirection is performed or not.
// - error: The error if any occurs.
func (a *ApiConfig) handleNonPost2FA(auth State, session sessions.Session, authResult definitions.AuthResult, subject string) (bool, error) {
	if a.deps.Cfg.GetSkipTOTP(*a.clientId) {
		return false, nil
	}

	if _, found := auth.GetTOTPSecretOk(); found {
		if err := a.setSessionVariablesForAuth(session, authResult, subject); err != nil {
			return false, err
		}

		var sb strings.Builder

		sb.WriteString(a.deps.Cfg.GetServer().Frontend.GetLoginPage())
		sb.WriteString("?login_challenge=")
		sb.WriteString(a.challenge)

		a.ctx.Redirect(http.StatusFound, sb.String())

		return true, nil
	}

	return false, nil
}

// handlePost2FA handles the post-2FA authentication process.
// It retrieves the TOTP code from the POST form and checks for its presence.
// Then, it gets the TOTP secret from the authentication object and checks for its presence.
// If both the code and secret are present, it performs TOTP validation using the code, account, and secret.
// If the validation is successful, it returns nil.
// Otherwise, it returns an error, specifically ErrNoTOTPCode if either the code or secret is missing.
func (a *ApiConfig) handlePost2FA(auth State, account string) error {
	code := a.ctx.PostForm("code")
	if code == "" {
		return errors.ErrNoTOTPCode
	}

	totpSecret, found := auth.GetTOTPSecretOk()
	if !found {
		return errors.ErrNoTOTPCode
	}

	err := totpValidation(a.ctx, a.guid, code, account, totpSecret, a.deps)
	if err != nil {
		return err
	}

	return nil
}

// isRemember checks if the user wants to be remembered for future logins.
// It takes two arguments:
// - rememberPost2FA: a string indicating if the user wants to be remembered after 2FA authentication.
//   - If it is "on", remember will be set to true.
//
// - post2FA: a boolean indicating if the authentication is done after 2FA.
//   - If it is true, remember will be set to true only if rememberPost2FA is "on".
//   - If it is false, remember will be set to true if the "remember" field in the ctx PostForm is set to "on".
//
// It returns a boolean indicating if the user wants to be remembered.
//
// Example usage:
//
//	remember := a.isRemember(rememberPost2FA, post2FA)
//
// Dependencies:
// - None
func (a *ApiConfig) isRemember(rememberPost2FA string, post2FA bool) bool {
	remember := false
	if post2FA {
		if rememberPost2FA == "on" {
			remember = true
		}
	} else if a.ctx.PostForm("remember") == "on" {
		remember = true
	}

	return remember
}

// acceptLogin accepts the OAuth2 login request and redirects the user to the appropriate page.
//
// Parameters:
// - claims: A map containing context information for the login request.
// - subject: The subject of the login request.
// - remember: Boolean value indicating whether the user should be remembered or not.
//
// Returns:
// - redirectTo: The URL where the user should be redirected.
// - err: An error, if any.
//
// Example Usage:
//
//	redirectTo, err := apiConfig.acceptLogin(claims, subject, remember)
func (a *ApiConfig) acceptLogin(claims map[string]any, subject string, remember bool) (redirectTo string, err error) {
	var acceptRequest *openapi.OAuth2RedirectTo

	rememberFor := int64(a.deps.Cfg.GetServer().Frontend.GetLoginRememberFor())
	acceptLoginRequest := a.apiClient.OAuth2API.AcceptOAuth2LoginRequest(a.ctx).AcceptOAuth2LoginRequest(
		openapi.AcceptOAuth2LoginRequest{
			Context:     claims,
			Subject:     subject,
			Remember:    &remember,
			RememberFor: &rememberFor,
		})

	acceptRequest, _, err = acceptLoginRequest.LoginChallenge(a.challenge).Execute()
	if err != nil {
		return
	}

	redirectTo = acceptRequest.GetRedirectTo()

	a.ctx.Redirect(http.StatusFound, redirectTo)

	return
}

// logInfoLoginAccept logs the information for an authentication event with the given subject and redirect URL.
func (a *ApiConfig) logInfoLoginAccept(subject string, auth State) {
	logs := []any{
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeyClientID, *a.clientId,
		definitions.LogKeyClientName, a.clientName,
		definitions.LogKeyAuthSubject, subject,
		definitions.LogKeyUsername, a.ctx.PostForm("username"),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthAccept,
		definitions.LogKeyUriPath, a.deps.Cfg.GetServer().Frontend.GetLoginPage() + "/post",
		definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
	}

	additionalLogs := auth.GetAdditionalLogs()
	if len(additionalLogs) > 0 && len(additionalLogs)%2 == 0 {
		logs = append(logs, additionalLogs...)
	}

	level.Info(a.deps.Logger).Log(logs...)
}

// totpValidation validates the time-based one-time password (TOTP) code against the provided account and TOTP secret.
// It constructs the TOTP URL and generates the key from the URL. It then validates the code using the key and additional options.
//
// Parameters:
// - code: The TOTP code to validate.
// - account: The account associated with the TOTP code.
// - totpSecret: The TOTP secret used to generate the TOTP code.
//
// Returns:
// - error: If the TOTP code is invalid or if there was an error generating the key.
//
// Example usage:
//
//	err := apiConfig.totpValidation(code, account, totpSecret)
//	if err != nil {
//		// Handle the error
//	}
//
// Dependencies:
// - viper.GetString("totp_issuer"): The issuer used in the TOTP URL.
// - url.QueryEscape(): A function to escape special characters in the URL components.
// - strings.Join(): A function to join the URL components into a single string.
// - otp.NewKeyFromURL(): A function to generate the key from the TOTP URL.
// - totp.ValidateCustom(): A function to validate the TOTP code using the key and additional options.
//
// Note: This method assumes that the `ApiConfig` object is properly initialized with the `guid` field set.

// setSessionVariablesForAuth sets the necessary session variables for authentication.
// It takes a `sessions.Session` object, `authResult` of type `definitions.AuthResult`, and the `subject` string as parameters.
// It sets the following session variables:
// - `definitions.CookieAuthResult`: uint8 value of `authResult`
// - `definitions.CookieUsername`: value of `username` field from the request form
// - `definitions.CookieSubject`: value of `subject`
// - `definitions.CookieRemember`: value of `remember` field from the request form
// It returns an `error` if there is any error saving the session.
//
// Example usage:
//
//	session := sessions.Default(ctx)
//	err := setSessionVariablesForAuth(session, authResult, subject)
//	if err != nil {
//	    // Handle error
//	}
func (a *ApiConfig) setSessionVariablesForAuth(session sessions.Session, authResult definitions.AuthResult, subject string) error {
	session.Set(definitions.CookieAuthResult, uint8(authResult))
	session.Set(definitions.CookieUsername, a.ctx.Request.Form.Get("username"))
	session.Set(definitions.CookieSubject, subject)
	session.Set(definitions.CookieRemember, a.ctx.Request.Form.Get("remember"))

	if err := session.Save(); err != nil {
		return err
	}

	return nil
}

// processAuthFailLogin handles the processing of a failed login authentication.
// It saves the authentication result and username in the session cookie,
// if post2FA is false and the TOTP secret is found.
//
// Parameters:
// - auth: the AuthState object for the failed login
// - authResult: the result of the authentication
// - post2FA: flag indicating if it is a post-2FA login
//
// Returns:
// - err: any error that occurred during processing
//
// Dependencies:
// - session.Default(): function for session management
// - config.GetSkipTOTP(): function to check if TOTP should be skipped for a given clientID
// - auth.getTOTPSecretOk(): method to get the TOTP secret for the authentication
//
// Note: This method assumes that the ApiConfig object is properly initialized with the ctx field set.
func (a *ApiConfig) processAuthFailLogin(auth State, authResult definitions.AuthResult, post2FA bool) (have2FA bool, err error) {
	session := sessions.Default(a.ctx)

	if !post2FA {
		if !a.deps.Cfg.GetSkipTOTP(*a.clientId) {
			if _, found := auth.GetTOTPSecretOk(); found {
				session.Set(definitions.CookieAuthResult, uint8(authResult))
				session.Set(definitions.CookieUsername, a.ctx.Request.Form.Get("username"))

				err = session.Save()
				if err != nil {
					return false, err
				}

				return true, nil
			}
		}
	}

	return false, nil
}

// logFailedLoginAndRedirect logs a failed login attempt and redirects the user to a login page with an error message.
func (a *ApiConfig) logFailedLoginAndRedirect(ctx *gin.Context, auth State) {
	loginChallenge := a.ctx.PostForm("ory.hydra.login_challenge")
	auth.SetClientIP(a.ctx.GetString(definitions.CtxClientIPKey))

	auth.UpdateBruteForceBucketsCounter(ctx)

	var sb strings.Builder

	sb.WriteString(a.deps.Cfg.GetServer().Frontend.GetLoginPage())
	sb.WriteString("?login_challenge=")
	sb.WriteString(loginChallenge)
	sb.WriteString("&_error=")
	sb.WriteString(definitions.PasswordFail)

	a.ctx.Redirect(http.StatusFound, sb.String())

	var sbLog strings.Builder

	sbLog.WriteString(a.deps.Cfg.GetServer().Frontend.GetLoginPage())
	sbLog.WriteString("/post")

	logs := []any{
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeyClientID, *a.clientId,
		definitions.LogKeyClientName, a.clientName,
		definitions.LogKeyUsername, a.ctx.PostForm("username"),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthReject,
		definitions.LogKeyUriPath, sbLog.String(),
		definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
	}

	additionalLogs := auth.GetAdditionalLogs()
	if len(additionalLogs) > 0 && len(additionalLogs)%2 == 0 {
		logs = append(logs, additionalLogs...)
	}

	level.Info(a.deps.Logger).Log(logs...)
}

// runLuaFilterAndPost filters and executes post-action Lua scripts based on the given post-2FA authentication result.
func runLuaFilterAndPost(ctx *gin.Context, auth State, authResult definitions.AuthResult) definitions.AuthResult {
	var (
		userFound bool
		err       error
	)

	if authResult == definitions.AuthResultOK && auth.IsMasterUser() {
		userFound = true
	} else {
		userFound, err = auth.userExists()
		if err != nil {
			if !stderrors.Is(err, redis.Nil) {
				level.Error(auth.GetLogger()).Log(
					definitions.LogKeyGUID, auth.GetGUID(),
					definitions.LogKeyMsg, "Error checking if user exists",
					definitions.LogKeyError, err,
					definitions.LogKeyClientIP, ctx.Request.RemoteAddr,
				)
			}
		}
	}

	accountField := auth.GetAccountField()
	totpSecretField := auth.GetTOTPSecretField()
	totpRecoveryField := auth.GetTOTPRecoveryField()
	uniqueUserIDField := auth.GetUniqueUserIDField()
	displayNameField := auth.GetDisplayNameField()

	passDBResult := GetPassDBResultFromPool()

	passDBResult.Authenticated = func() bool {
		if authResult == definitions.AuthResultOK {
			return true
		}

		return false
	}()

	passDBResult.UserFound = userFound
	passDBResult.AccountField = accountField
	passDBResult.TOTPSecretField = totpSecretField
	passDBResult.TOTPRecoveryField = totpRecoveryField
	passDBResult.UniqueUserIDField = uniqueUserIDField
	passDBResult.DisplayNameField = displayNameField
	passDBResult.Backend = auth.GetUsedPassDBBackend()
	// Avoid sharing internal map by value; hand over a deep copy instead
	passDBResult.Attributes = auth.GetAttributesCopy()

	authResult = auth.FilterLua(ctx, passDBResult)

	auth.PostLuaAction(ctx, passDBResult)
	PutPassDBResultToPool(passDBResult)

	return authResult
}

// LoginPOSTHandler Page '/login/post'
func (h *HydraHandlers) LoginPOSTHandler(ctx *gin.Context) {
	var (
		post2FA         bool
		authResult      definitions.AuthResult
		recentSubject   string
		rememberPost2FA string
		httpResponse    *http.Response
	)

	loginChallenge := ctx.PostForm("ory.hydra.login_challenge")
	if loginChallenge == "" {
		HandleHydraErrWithDeps(ctx, errors.ErrNoLoginChallenge, h.deps)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx, deps: h.deps}

	apiConfig.initialize()

	apiConfig.challenge = loginChallenge

	auth, err := h.initializeAuthLogin(ctx)
	if err != nil {
		HandleHydraErrWithDeps(ctx, err, h.deps)

		return
	}

	authResult, recentSubject, rememberPost2FA, post2FA, err = handleSessionDataLogin(ctx, auth)
	if err != nil {
		HandleHydraErrWithDeps(ctx, err, h.deps)

		return
	}

	apiConfig.loginRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2LoginRequest(ctx).LoginChallenge(
		apiConfig.challenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse, h.deps)

		return
	}

	oauth2Client := apiConfig.loginRequest.GetClient()

	clientIdFound := false
	if apiConfig.clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		HandleHydraErrWithDeps(ctx, errors.ErrHydraNoClientId, h.deps)

		return
	}

	apiConfig.clientName = oauth2Client.GetClientName()

	if authResult == definitions.AuthResultUnset || authResult == definitions.AuthResultOK {
		authResult = auth.HandlePassword(ctx)
	}

	oldAuthResult := authResult

	needLuaFilterAndPost := true
	if post2FA {
		authResult = runLuaFilterAndPost(ctx, auth, authResult)
		oldAuthResult = authResult
		needLuaFilterAndPost = false
	}

	for {
		switch authResult {
		case definitions.AuthResultOK:
			tolerate.GetTolerate().SetIPAddress(ctx, auth.GetClientIP(), auth.GetUsername(), true)

			authResult, err = apiConfig.processAuthOkLogin(ctx, auth, oldAuthResult, rememberPost2FA, recentSubject, post2FA, needLuaFilterAndPost)
			if err != nil {
				HandleHydraErrWithDeps(ctx, err, h.deps)
			}

			// If auth-results have changed, filters must have ran. Do not run them again...
			if oldAuthResult != authResult {
				oldAuthResult = authResult
				needLuaFilterAndPost = false

				continue
			}

			return
		case definitions.AuthResultFail, definitions.AuthResultEmptyUsername, definitions.AuthResultEmptyPassword:
			var have2FA bool

			tolerate.GetTolerate().SetIPAddress(ctx, auth.GetClientIP(), auth.GetUsername(), false)

			have2FA, err = apiConfig.processAuthFailLogin(auth, oldAuthResult, post2FA)
			if err != nil {
				HandleHydraErrWithDeps(ctx, err, h.deps)

				return
			}

			if !have2FA && needLuaFilterAndPost {
				authResult = runLuaFilterAndPost(ctx, auth, oldAuthResult)

				if oldAuthResult != authResult {
					oldAuthResult = authResult
					needLuaFilterAndPost = false

					continue
				}
			}

			apiConfig.logFailedLoginAndRedirect(ctx, auth)

			return
		default:
			HandleHydraErrWithDeps(ctx, errors.ErrUnknownCause, h.deps)
			ctx.AbortWithStatus(http.StatusInternalServerError)

			return
		}
	}
}

// LoginPOSTHandler Page '/login/post' (legacy)
func LoginPOSTHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := NewHydraHandlers(deps)
		h.LoginPOSTHandler(ctx)
	}
}

// DeviceGETHandler Page '/device'
func (h *HydraHandlers) DeviceGETHandler(ctx *gin.Context) {
	var (
		wantAbout    bool
		wantPolicy   bool
		wantTos      bool
		haveError    bool
		policyUri    string
		tosUri       string
		clientUri    string
		imageUri     string
		errorMessage string
		err          error
		clientId     *string
		guid         = ctx.GetString(definitions.CtxGUIDKey)
		csrfToken    = ctx.GetString(definitions.CtxCSRFTokenKey)
		loginRequest *openapi.OAuth2LoginRequest
		httpResponse *http.Response
	)

	loginChallenge := ctx.Query("login_challenge")
	if loginChallenge == "" {
		HandleHydraErrWithDeps(ctx, errors.ErrNoLoginChallenge, h.deps)

		return
	}

	configuration := createConfiguration(h.deps.Cfg, httpClient)
	apiClient := openapi.NewAPIClient(configuration)

	loginRequest, httpResponse, err = apiClient.OAuth2API.GetOAuth2LoginRequest(ctx).LoginChallenge(
		loginChallenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse, h.deps)

		return
	}

	oauth2Client := loginRequest.GetClient()

	clientIdFound := false
	if clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		HandleHydraErrWithDeps(ctx, errors.ErrHydraNoClientId, h.deps)

		return
	}

	clientName := oauth2Client.GetClientName()

	imageUri = oauth2Client.GetLogoUri()
	if imageUri == "" {
		imageUri = h.deps.Cfg.GetServer().Frontend.GetDefaultLogoImage()
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

	cookieValue := session.Get(definitions.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(ctx, h.deps.Cfg, h.deps.Cfg.GetServer().Frontend.GetDevicePage(), config.DefaultLanguageTags, languageCurrentName)

	loginData := &frontend.LoginPageData{
		Title: frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login"),
		WantWelcome: func() bool {
			if h.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
				return true
			}

			return false
		}(),
		Welcome:             h.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome(),
		ApplicationName:     applicationName,
		WantAbout:           wantAbout,
		About:               frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Get further information about this application..."),
		AboutUri:            clientUri,
		LogoImage:           imageUri,
		LogoImageAlt:        h.deps.Cfg.GetServer().Frontend.GetLoginPageLogoImageAlt(),
		HaveError:           haveError,
		ErrorMessage:        errorMessage,
		Login:               frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Login"),
		Privacy:             frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "We'll never share your data with anyone else."),
		LoginPlaceholder:    frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Please enter your username or email address"),
		WantPolicy:          wantPolicy,
		Policy:              frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Privacy policy"),
		PolicyUri:           policyUri,
		WantTos:             wantTos,
		Tos:                 frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Terms of service"),
		TosUri:              tosUri,
		Submit:              frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Submit"),
		PostLoginEndpoint:   h.deps.Cfg.GetServer().Frontend.GetDevicePage(),
		DeviceLoginEndpoint: h.deps.Cfg.GetServer().Frontend.GetDevicePage(),
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
		LoginChallenge:      loginChallenge,
	}

	ctx.HTML(http.StatusOK, "device.html", loginData)

	level.Info(h.deps.Logger).Log(
		definitions.LogKeyGUID, guid,
		definitions.LogKeySkip, false,
		definitions.LogKeyClientID, *clientId,
		definitions.LogKeyClientName, clientName,
		definitions.LogKeyUriPath, h.deps.Cfg.GetServer().Frontend.GetDevicePage(),
		definitions.LogKeyClientIP, ctx.Request.RemoteAddr,
	)
}

// DeviceGETHandler Page '/device' (legacy)
func DeviceGETHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := NewHydraHandlers(deps)
		h.DeviceGETHandler(ctx)
	}
}

// DevicePOSTHandler Page '/device/post'
func (h *HydraHandlers) DevicePOSTHandler(ctx *gin.Context) {
	HandleHydraErrWithDeps(ctx, stderrors.New("not implemented yet"), h.deps)
}

// handleRequestedScopes is a function that analyzes requested scopes from the user in a session.
// It then finds the corresponding descriptions for these scope requests and encapsulates them within a 'Scope' entity
// to be returned in a list.
//
// Parameters
// * ctx: It is the gin.Context object that encapsulates all functionalities for handling HTTP requests and responses.
// * requestedScopes: It is the slice of string that contains all requested scopes.
// * session: It is the sessions.Session object where the session data is saved.
// * guid: It is a string parameter that uniquely identifies a specific session.
//
// Returns
// It returns a slice of Scope; each Scope contains a scope name along with its corresponding description.
//
// Usage
// This function is typically used to gather all scopes a user requested in a particular session identified by 'guid' parameter.
func (a *ApiConfig) handleRequestedScopes(ctx *gin.Context, requestedScopes []string, session sessions.Session) []frontend.Scope {
	var (
		scopes           []frontend.Scope
		scopeDescription string
	)

	cookieValue := session.Get(definitions.CookieLang)

	for _, requestedScope := range requestedScopes {
		scopeDescription = a.getScopeDescription(ctx, requestedScope, cookieValue)
		scopes = append(scopes, frontend.Scope{ScopeName: requestedScope, ScopeDescription: scopeDescription})
	}

	return scopes
}

// getScopeDescription function acquires a descriptive string correspondent to
// the type of OAuth scope requested. The 'ctx' argument must be a gin Context
// and the 'requestedScope' must be a string defining a specific OAuth scope.
// While the 'cookieValue' is used when requesting for a custom scope.
// Predefined scopes provide standard access to user's data like email, address,
// phone number, identity information etc. For scopes that do not match with
// predefined ones, a custom scope is sought.
//
// Parameters:
// ctx : Pointer to gin.Context: A context of gin framework for handling HTTP requests
// requestedScope: String: Type of OAuth scope requested.
// cookieValue: any: Data to be used for custom scope requests.
//
// Returns:
// String: A string corresponding to the type of OAuth scope requested
func (a *ApiConfig) getScopeDescription(ctx *gin.Context, requestedScope string, cookieValue any) string {
	switch requestedScope {
	case definitions.ScopeOpenId:
		return frontend.GetLocalized(ctx, a.deps.Cfg, a.deps.Logger, "Allow access to identity information")
	case definitions.ScopeOfflineAccess:
		return frontend.GetLocalized(ctx, a.deps.Cfg, a.deps.Logger, "Allow an application access to private data without your personal presence")
	case definitions.ScopeProfile:
		return frontend.GetLocalized(ctx, a.deps.Cfg, a.deps.Logger, "Allow access to personal profile data")
	case definitions.ScopeEmail:
		return frontend.GetLocalized(ctx, a.deps.Cfg, a.deps.Logger, "Allow access to your email address")
	case definitions.ScopeAddress:
		return frontend.GetLocalized(ctx, a.deps.Cfg, a.deps.Logger, "Allow access to your home address")
	case definitions.ScopePhone:
		return frontend.GetLocalized(ctx, a.deps.Cfg, a.deps.Logger, "Allow access to your phone number")
	case definitions.ScopeGroups:
		return frontend.GetLocalized(ctx, a.deps.Cfg, a.deps.Logger, "Allow access to group memberships")
	default:
		return a.getCustomScopeDescription(ctx, requestedScope, cookieValue)
	}
}

// getCustomScopeDescription is a method that retrieves the description of a custom OAuth2 scope.
// It takes three arguments; a gin context, the name of the requested scope, and a cookie value.
//
// It iterates over the list of custom scopes defined in the loaded configuration. If it finds a match with the requested scope,
// it fetches the description associated with it. If the custom scope object has 'Other' values and these contain a localized
// description, this is used instead. This localization is defined based on the value provided in the cookie.
//
// If no custom scope matching the requested name can be found, or the custom scope has no description, the method returns the
// default localized message "Allow access to a specific scope".
//
// Parameters:
// ctx: The Gin context from which the function is called.
// requestedScope: The requested OAuth2 scope. The function uses this value to find the corresponding custom scope in the loaded configuration.
// cookieValue: A value derived from a cookie. This is used to determine which localization to use if localized descriptions are available.
//
// Returns:
// It returns a string representing the description of the requested scope.
func (a *ApiConfig) getCustomScopeDescription(ctx *gin.Context, requestedScope string, cookieValue any) string {
	var scopeDescription string

	if a.deps.Cfg.GetOauth2() != nil {
		for scopeIndex := range a.deps.Cfg.GetOauth2().CustomScopes {
			customScope := a.deps.Cfg.GetOauth2().CustomScopes[scopeIndex]
			if customScope.Name != requestedScope {
				continue
			}

			scopeDescription = customScope.Description
			if len(customScope.Other) > 0 {
				lang := cookieValue.(string)
				if value, assertOk := customScope.Other["description_"+lang]; assertOk {
					scopeDescription = value.(string)
				}
			}

			break
		}
	}

	if scopeDescription == "" {
		scopeDescription = frontend.GetLocalized(ctx, a.deps.Cfg, a.deps.Logger, "Allow access to a specific scope")
	}

	return scopeDescription
}

// HandleConsentSkip handles the consent skipping logic.
// If the consent request skip flag is false and the skip consent config flag is false, it processes the consent.
// Otherwise, it redirects with consent.
//
// Example usage:
//
//	apiConfig := &ApiConfig{ctx: ctx}
//	apiConfig.initialize()
//	apiConfig.HandleConsentSkip()
//
// Dependencies:
//   - a.consentRequest.GetSkip() (from initialize)
//   - config.GetSkipConsent(*a.clientId) (from initialize)
//
// Note: This method assumes that the ApiConfig object is properly initialized with the ctx field set.
func (a *ApiConfig) HandleConsentSkip() {
	if !(a.consentRequest.GetSkip() || a.deps.Cfg.GetSkipConsent(*a.clientId)) {
		a.processConsent()
	} else {
		a.redirectWithConsent()
	}
}

// processConsent handles the processing and rendering of the consent page.
//
// This method retrieves and handles data needed for rendering the consent page, such as the client's requested scopes,
// logo image URI, policy URI, terms of service URI, application name, language settings, and consent page messages.
// It then creates a ConsentPageData struct with the necessary data and passes it to the consent.html template for rendering.
//
// Note: This method assumes that all necessary dependencies and configurations have been properly set up before calling it.
// It also assumes that all required templates exist and are properly configured.
//
// Example usage:
// a.processConsent()
func (a *ApiConfig) processConsent() {
	var (
		wantAbout  bool
		wantPolicy bool
		wantTos    bool
		policyUri  string
		tosUri     string
		clientUri  string
		imageUri   string
	)

	// Get session
	session := sessions.Default(a.ctx)

	// Handle scopes
	scopes := a.handleRequestedScopes(a.ctx, a.consentRequest.GetRequestedScope(), session)

	oauth2Client := a.consentRequest.GetClient()

	imageUri = oauth2Client.GetLogoUri()
	if imageUri == "" {
		imageUri = a.deps.Cfg.GetServer().Frontend.GetDefaultLogoImage()
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

	languageCurrentTag := language.MustParse(session.Get(definitions.CookieLang).(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(a.ctx, a.deps.Cfg, a.deps.Cfg.GetServer().Frontend.GetConsentPage(), config.DefaultLanguageTags, languageCurrentName)

	consentData := &frontend.ConsentPageData{
		Title: frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Consent"),
		WantWelcome: func() bool {
			if a.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
				return true
			}

			return false
		}(),
		Welcome:             a.deps.Cfg.GetServer().Frontend.GetConsentPageWelcome(),
		LogoImage:           imageUri,
		LogoImageAlt:        a.deps.Cfg.GetServer().Frontend.GetConsentPageLogoImageAlt(),
		ConsentMessage:      frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "An application requests access to your data"),
		ApplicationName:     applicationName,
		WantAbout:           wantAbout,
		About:               frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Get further information about this application..."),
		AboutUri:            clientUri,
		Scopes:              scopes,
		WantPolicy:          wantPolicy,
		Policy:              frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Privacy policy"),
		PolicyUri:           policyUri,
		WantTos:             wantTos,
		Tos:                 frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Terms of service"),
		TosUri:              tosUri,
		Remember:            frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Do not ask me again"),
		AcceptSubmit:        frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Accept access"),
		RejectSubmit:        frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Deny access"),
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           a.csrfToken,
		ConsentChallenge:    a.challenge,
		PostConsentEndpoint: a.deps.Cfg.GetServer().Frontend.GetConsentPage(),
	}

	a.ctx.HTML(http.StatusOK, "consent.html", consentData)

	a.logInfoConsent()
}

// redirectWithConsent is a method of the ApiConfig struct.
//
// The method helps to redirect the user with an OAuth2 consent.
// It starts by initializing the session and then retrieving the context and the requested scope from the consent request.
// It also prepares the interval for which the consent should be remembered using "login_remember_for" configuration.
//
// Then, based on the requested scopes, it checks if the scope 'openid' is included among the others
// and if so, it indicates that claims are needed and retrieves the claims from the consent context.
//
// The method proceeds to prepare a structured data (openapi.AcceptOAuth2ConsentRequest) for accepting an OAuth2 consent request,
// which includes details such as the Access Token audience, granted scopes, whether to remember the consent,
// duration for remembering the consent, and the session information if 'openid' scope was requested.
//
// Finally, it submits the prepared consent request to be processed and in case of success, it triggers a redirect response to the client with the redirected URL.
// If an error occurs while executing the consent request, it is handled by the 'handleHydraErr' function.
//
// redirectWithConsent logs the redirected URL using the 'logInfoRedirectWithConsent' method.
//
// Remember: All the error handling and debug information/reporting is done internally within the method.
func (a *ApiConfig) redirectWithConsent() {
	var session *openapi.AcceptOAuth2ConsentRequestSession

	consentContext := a.consentRequest.GetContext()
	acceptedScopes := a.consentRequest.GetRequestedScope()
	rememberFor := int64(a.deps.Cfg.GetServer().Frontend.GetLoginRememberFor())

	util.DebugModuleWithCfg(
		a.ctx.Request.Context(),
		a.deps.Cfg,
		a.deps.Logger,
		definitions.DbgHydra,
		definitions.LogKeyGUID, a.guid,
		"accepted_scopes", fmt.Sprintf("%+v", acceptedScopes),
	)

	needClaims := false

	for index := range acceptedScopes {
		if acceptedScopes[index] != definitions.ScopeOpenId {
			continue
		}

		needClaims = true

		break
	}

	if needClaims {
		util.DebugModuleWithCfg(
			a.ctx.Request.Context(),
			a.deps.Cfg,
			a.deps.Logger,
			definitions.DbgHydra,
			definitions.LogKeyGUID, a.guid,
			definitions.LogKeyMsg, "Scope 'openid' found, need claims",
		)

		session = getClaimsFromConsentContext(a.guid, acceptedScopes, consentContext, a.deps)
	}

	acceptConsentRequest := a.apiClient.OAuth2API.AcceptOAuth2ConsentRequest(a.ctx).AcceptOAuth2ConsentRequest(
		openapi.AcceptOAuth2ConsentRequest{
			GrantAccessTokenAudience: a.consentRequest.GetRequestedAccessTokenAudience(),
			GrantScope:               acceptedScopes,
			Remember: func() *bool {
				if a.deps.Cfg.GetSkipConsent(*a.clientId) {
					remember := true

					return &remember
				}

				return a.consentRequest.Skip
			}(),
			RememberFor: &rememberFor,
			Session:     session,
		})

	acceptRequest, httpResponse, err := acceptConsentRequest.ConsentChallenge(a.challenge).Execute()
	if err != nil {
		handleHydraErr(a.ctx, err, httpResponse, a.deps)

		return
	}

	a.ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

	a.logInfoRedirectWithConsent()
}

// logInfoConsent logs information about the consent request.
func (a *ApiConfig) logInfoConsent() {
	level.Info(a.deps.Logger).Log(
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeySkip, false,
		definitions.LogKeyClientID, *a.clientId,
		definitions.LogKeyClientName, a.clientName,
		definitions.LogKeyAuthSubject, a.consentRequest.GetSubject(),
		definitions.LogKeyUriPath, a.deps.Cfg.GetServer().Frontend.GetConsentPage(),
		definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
	)
}

// logInfoRedirectWithConsent logs an info level message with the given parameters
// to the default logger.
func (a *ApiConfig) logInfoRedirectWithConsent() {
	level.Info(a.deps.Logger).Log(
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeySkip, true,
		definitions.LogKeyClientID, *a.clientId,
		definitions.LogKeyClientName, a.clientName,
		definitions.LogKeyAuthSubject, a.consentRequest.GetSubject(),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthAccept,
		definitions.LogKeyUriPath, a.deps.Cfg.GetServer().Frontend.GetConsentPage(),
		definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
	)
}

// ConsentGETHandler Page '/consent'
func (h *HydraHandlers) ConsentGETHandler(ctx *gin.Context) {
	var (
		err          error
		httpResponse *http.Response
	)

	consentChallenge := ctx.Query("consent_challenge")
	if consentChallenge == "" {
		HandleHydraErrWithDeps(ctx, errors.ErrNoLoginChallenge, h.deps)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx, deps: h.deps}

	apiConfig.initialize()

	apiConfig.challenge = consentChallenge
	apiConfig.csrfToken = ctx.GetString(definitions.CtxCSRFTokenKey)

	apiConfig.consentRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2ConsentRequest(ctx).ConsentChallenge(
		apiConfig.challenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse, h.deps)

		return
	}

	oauth2Client := apiConfig.consentRequest.GetClient()

	clientIdFound := false
	if apiConfig.clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		HandleHydraErrWithDeps(ctx, errors.ErrHydraNoClientId, h.deps)

		return
	}

	apiConfig.clientName = oauth2Client.GetClientName()

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		h.deps.Cfg,
		h.deps.Logger,
		definitions.DbgHydra,
		definitions.LogKeyGUID, apiConfig.guid,
		"skip_hydra", fmt.Sprintf("%v", apiConfig.consentRequest.GetSkip()),
		"skip_config", fmt.Sprintf("%v", h.deps.Cfg.GetSkipConsent(*apiConfig.clientId)),
	)

	apiConfig.HandleConsentSkip()
}

// ConsentGETHandler Page '/consent' (legacy)
func ConsentGETHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := NewHydraHandlers(deps)
		h.ConsentGETHandler(ctx)
	}
}

// handleConsentSubmit processes the form submission for the consent page.
// If the submit value is "accept", it calls the processConsentAccept method.
// Otherwise, it calls the processConsentReject method.
//
// Example usage:
//
//	apiConfig := &ApiConfig{ctx: ctx}
//	apiConfig.initialize()
//
//	// Use the initialized ApiConfig object
//	apiConfig.handleConsentSubmit()
//
// Dependencies:
// - processConsentAccept method
// - processConsentReject method
func (a *ApiConfig) handleConsentSubmit() {
	if a.ctx.Request.Form.Get("submit") == "accept" {
		a.processConsentAccept()
	} else {
		a.processConsentReject()
	}
}

// processConsentAccept processes the consent acceptance request.
// It retrieves the requested scopes and consent context from the consent request.
// It then checks which scopes the user has accepted and creates a list of accepted scopes.
// The scopes that the user has accepted are determined based on the POST form data.
// If the "openid" scope is among the accepted scopes, it indicates that claims are needed.
// If claims are needed, it calls the getClaimsFromConsentContext function to retrieve the claims from the consent context.
// It then retrieves the remember and rememberFor values from the POST form data.
// Finally, it calls the AcceptOAuth2ConsentRequest function of the API client to accept the consent request and redirects the user to the appropriate page.
//
// Example usage:
//
//	apiConfig.handleConsentSubmit()
//
// Dependencies:
//
//	getClaimsFromConsentContext function
//	handleHydraErr function
//
// Note: This method assumes that the `ApiConfig` object is properly initialized with the `ctx`, `consentRequest`, `apiClient`, and `challenge` fields set.
func (a *ApiConfig) processConsentAccept() {
	var (
		session        *openapi.AcceptOAuth2ConsentRequestSession
		acceptedScopes []string
	)

	requestedScopes := a.consentRequest.GetRequestedScope()
	consentContext := a.consentRequest.GetContext()

	// https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
	for index := range requestedScopes {
		if a.ctx.PostForm(requestedScopes[index]) == "on" {
			acceptedScopes = append(acceptedScopes, requestedScopes[index])
		}
	}

	util.DebugModuleWithCfg(
		a.ctx.Request.Context(),
		a.deps.Cfg,
		a.deps.Logger,
		definitions.DbgHydra,
		definitions.LogKeyGUID, a.guid,
		"accepted_scopes", fmt.Sprintf("%+v", acceptedScopes),
	)

	needClaims := false

	for index := range acceptedScopes {
		if acceptedScopes[index] != definitions.ScopeOpenId {
			continue
		}

		needClaims = true

		break
	}

	if needClaims {
		util.DebugModuleWithCfg(a.ctx.Request.Context(), a.deps.Cfg, a.deps.Logger, definitions.DbgHydra, definitions.LogKeyGUID, a.guid, definitions.LogKeyMsg, "Scope 'openid' found, need claims")

		session = getClaimsFromConsentContext(a.guid, acceptedScopes, consentContext, a.deps)
	}

	rememberFor := int64(a.deps.Cfg.GetServer().Frontend.GetLoginRememberFor())
	remember := false

	if a.ctx.PostForm("remember") == "on" {
		remember = true
	}

	acceptConsentRequest := a.apiClient.OAuth2API.AcceptOAuth2ConsentRequest(a.ctx).AcceptOAuth2ConsentRequest(
		openapi.AcceptOAuth2ConsentRequest{
			GrantAccessTokenAudience: a.consentRequest.GetRequestedAccessTokenAudience(),
			GrantScope:               acceptedScopes,
			Remember:                 &remember,
			RememberFor:              &rememberFor,
			Session:                  session,
		})

	acceptRequest, httpResponse, err := acceptConsentRequest.ConsentChallenge(a.challenge).Execute()
	if err != nil {
		handleHydraErr(a.ctx, err, httpResponse, a.deps)

		return
	}

	a.ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

	a.logInfoConsentAccept()
}

// processConsentReject processes the rejection of the OAuth2 consent request.
// It sends a reject request to the OAuth2 API and handles the response.
//
// Example usage:
//
//	apiConfig := &ApiConfig{ctx: ctx}
//	apiConfig.processConsentReject()
//
// Dependencies:
//   - a.apiClient: The API client for making requests to the OAuth2 API.
//   - a.challenge: The challenge value for the consent request.
//   - handleHydraErr: A function for handling Hydra errors.
//   - definitions.PasswordFail: A constant for the password failure message.
//
// Dependencies:
// - handleHydraErr function
// - definitions.PasswordFail constant
//
// Note: This method assumes that the `ApiConfig` object is properly initialized with the `ctx`, `apiClient`, and `challenge` fields set.
func (a *ApiConfig) processConsentReject() {
	var (
		redirectTo *string
		isSet      bool
	)

	errorDescription := "Access denied by user"
	statusCode := int64(http.StatusForbidden)

	rejectConsentRequest := a.apiClient.OAuth2API.RejectOAuth2ConsentRequest(a.ctx).RejectOAuth2Request(
		openapi.RejectOAuth2Request{
			ErrorDescription: &errorDescription,
			ErrorHint:        nil,
			StatusCode:       &statusCode,
		})

	rejectRequest, httpResponse, err := rejectConsentRequest.ConsentChallenge(a.challenge).Execute()
	if err != nil {
		handleHydraErr(a.ctx, err, httpResponse, a.deps)

		return
	}

	if redirectTo, isSet = rejectRequest.GetRedirectToOk(); isSet {
		a.ctx.Redirect(http.StatusFound, *redirectTo)
	} else {
		a.ctx.String(http.StatusForbidden, definitions.PasswordFail)
	}

	a.logInfoConsentReject()
}

// logInfoConsentAccept logs an info level log message for accepting the consent and redirects to the specified URL.
func (a *ApiConfig) logInfoConsentAccept() {
	level.Info(a.deps.Logger).Log(
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeyClientID, *a.clientId,
		definitions.LogKeyClientName, a.clientName,
		definitions.LogKeyAuthSubject, a.consentRequest.GetSubject(),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthAccept,
		definitions.LogKeyUriPath, a.deps.Cfg.GetServer().Frontend.GetConsentPage()+"/post",
	)
}

// logInfoConsentReject logs the information about a rejected consent request.
func (a *ApiConfig) logInfoConsentReject() {
	level.Info(a.deps.Logger).Log(
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeyClientID, *a.clientId,
		definitions.LogKeyClientName, a.clientName,
		definitions.LogKeyAuthSubject, a.consentRequest.GetSubject(),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthReject,
		definitions.LogKeyUriPath, a.deps.Cfg.GetServer().Frontend.GetConsentPage()+"/post",
		definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
	)
}

// ConsentPOSTHandler Page '/consent/post'
func (h *HydraHandlers) ConsentPOSTHandler(ctx *gin.Context) {
	var (
		err          error
		httpResponse *http.Response
	)

	consentChallenge := ctx.PostForm("ory.hydra.consent_challenge")
	if consentChallenge == "" {
		HandleHydraErrWithDeps(ctx, errors.ErrNoLoginChallenge, h.deps)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx, deps: h.deps}

	apiConfig.initialize()

	apiConfig.challenge = consentChallenge

	apiConfig.consentRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2ConsentRequest(ctx).ConsentChallenge(
		apiConfig.challenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse, h.deps)

		return
	}

	oauth2Client := apiConfig.consentRequest.GetClient()

	clientIdFound := false
	if apiConfig.clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		HandleHydraErrWithDeps(ctx, errors.ErrHydraNoClientId, h.deps)

		return
	}

	apiConfig.clientName = oauth2Client.GetClientName()

	apiConfig.handleConsentSubmit()
}

// ConsentPOSTHandler Page '/consent/post' (legacy)
func ConsentPOSTHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := NewHydraHandlers(deps)
		h.ConsentPOSTHandler(ctx)
	}
}

// handleLogout handles the logout functionality of the API.
// It retrieves the session and gets the value of the language cookie.
// It then parses the language value into a language tag and builds the language name.
// It creates the LogoutPageData struct with the necessary fields for the logout page template.
// Finally, it renders the logout.html template with the logoutData and logs the logout event.
//
// Example usage:
// apiConfig.handleLogout()
func (a *ApiConfig) handleLogout() {
	session := sessions.Default(a.ctx)
	cookieValue := session.Get(definitions.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := frontend.CreateLanguagePassive(a.ctx, a.deps.Cfg, a.deps.Cfg.GetServer().Frontend.GetLogoutPage(), config.DefaultLanguageTags, languageCurrentName)

	logoutData := &frontend.LogoutPageData{
		Title: frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Logout"),
		WantWelcome: func() bool {
			if a.deps.Cfg.GetServer().Frontend.GetLoginPageWelcome() != "" {
				return true
			}

			return false
		}(),
		Welcome:             a.deps.Cfg.GetServer().Frontend.GetLogoutPageWelcome(),
		LogoutMessage:       frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Do you really want to log out?"),
		AcceptSubmit:        frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "Yes"),
		RejectSubmit:        frontend.GetLocalized(a.ctx, a.deps.Cfg, a.deps.Logger, "No"),
		LanguageTag:         session.Get(definitions.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           a.csrfToken,
		LogoutChallenge:     a.challenge,
		PostLogoutEndpoint:  a.deps.Cfg.GetServer().Frontend.GetLogoutPage(),
	}

	a.ctx.HTML(http.StatusOK, "logout.html", logoutData)

	a.logInfoLogout()
}

// logInfoLogout logs information about a logout action.
func (a *ApiConfig) logInfoLogout() {
	level.Info(a.deps.Logger).Log(
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeyAuthSubject, a.logoutRequest.GetSubject(),
		definitions.LogKeyUriPath, a.deps.Cfg.GetServer().Frontend.GetLogoutPage(),
		definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
	)
}

// LogoutGETHandler Page '/logout'
func (h *HydraHandlers) LogoutGETHandler(ctx *gin.Context) {
	var (
		err          error
		httpResponse *http.Response
	)

	// Skip logout request, if there does not exist any session for the user
	postLogout := ctx.Query("logout")
	if postLogout == "1" {
		redirectTo := h.deps.Cfg.GetServer().Frontend.GetHomepage()
		if redirectTo != "" {
			ctx.Redirect(http.StatusFound, redirectTo)
		} else {
			ctx.Set(definitions.CtxMessageKey, "No active session for user found")
			h.NotifyGETHandler(ctx)
		}

		return
	}

	logoutChallenge := ctx.Query("logout_challenge")
	if logoutChallenge == "" {
		HandleHydraErrWithDeps(ctx, errors.ErrNoLoginChallenge, h.deps)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx, deps: h.deps}

	apiConfig.initialize()

	apiConfig.challenge = logoutChallenge
	apiConfig.csrfToken = ctx.GetString(definitions.CtxCSRFTokenKey)

	apiConfig.logoutRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2LogoutRequest(ctx).LogoutChallenge(
		logoutChallenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse, h.deps)

		return
	}

	if apiConfig.logoutRequest.GetRpInitiated() {
		// We could skip the UI
		util.DebugModuleWithCfg(ctx.Request.Context(), h.deps.Cfg, h.deps.Logger, definitions.DbgHydra, definitions.LogKeyGUID, apiConfig.guid, definitions.LogKeyMsg, "rp_initiated==true")
	}

	apiConfig.handleLogout()
}

// LogoutGETHandler Page '/logout' (legacy)
func LogoutGETHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := NewHydraHandlers(deps)
		h.LogoutGETHandler(ctx)
	}
}

// handleLogoutSubmit handles the logout submit action.
// If the "submit" value in the request's post form is "accept", it calls the acceptLogout function.
// Otherwise, it calls the rejectLogout function.
//
// Example usage:
//
//	apiConfig.handleLogoutSubmit()
//
// Dependencies:
// - None
//
// Note: This method assumes that the `ApiConfig` object is properly initialized with the `ctx` field set.
func (a *ApiConfig) handleLogoutSubmit() {
	if a.ctx.PostForm("submit") == "accept" {
		a.acceptLogout()
	} else {
		a.rejectLogout()
	}
}

// acceptLogout sends an accept request for a logout challenge
//
// This method initiates the logout process by sending an accept request to the OAuth2 API with the specified logout challenge.
// If the request is successful, the user will be redirected to the returned redirect URL.
//
// Dependencies:
// - `a.apiClient`: An initialized instance of the `openapi.APIClient` struct.
//
// Parameters:
// - `a.challenge`: The logout challenge string.
//
// Returns:
// - None.
//
// Example usage:
// ```
// apiConfig.acceptLogout()
// ```
//
// Note: This method assumes that the `ApiConfig` object is properly initialized with the `a.apiClient` field set.
//
// Note: This method logs information about the accept process, including the redirect URL.
func (a *ApiConfig) acceptLogout() {
	var (
		err           error
		acceptRequest *openapi.OAuth2RedirectTo
		httpResponse  *http.Response
	)

	acceptLogoutRequest := a.apiClient.OAuth2API.AcceptOAuth2LogoutRequest(a.ctx)

	acceptRequest, httpResponse, err = acceptLogoutRequest.LogoutChallenge(a.challenge).Execute()
	if err != nil {
		handleHydraErr(a.ctx, err, httpResponse, a.deps)

		return
	}

	a.ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

	a.logInfoLogoutAccept()
}

// rejectLogout rejects the logout request by sending a request to the OAuth2API endpoint of the API client.
// If the request is successful, it redirects the user to the specified homepage or aborts the request with a status of 200 OK.
// If the request encounters an error, it handles the error and returns.
func (a *ApiConfig) rejectLogout() {
	rejectLogoutRequest := a.apiClient.OAuth2API.RejectOAuth2LogoutRequest(a.ctx)

	httpResponse, err := rejectLogoutRequest.LogoutChallenge(a.challenge).Execute()
	if err != nil {
		handleHydraErr(a.ctx, err, httpResponse, a.deps)

		return
	}

	redirectTo := a.deps.Cfg.GetServer().Frontend.GetHomepage()
	if redirectTo != "" {
		a.ctx.Redirect(http.StatusFound, redirectTo)
	} else {
		a.ctx.AbortWithStatus(http.StatusOK)
	}

	a.logInfoLogoutReject()
}

// logInfoLogoutAccept logs information about the logout request acceptance.
func (a *ApiConfig) logInfoLogoutAccept() {
	level.Info(a.deps.Logger).Log(
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeyAuthSubject, a.logoutRequest.GetSubject(),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthAccept,
		definitions.LogKeyUriPath, a.deps.Cfg.GetServer().Frontend.GetLogoutPage()+"/post",
		definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
	)
}

// logInfoLogoutReject logs an info-level message indicating a rejected logout attempt.
func (a *ApiConfig) logInfoLogoutReject() {
	level.Info(a.deps.Logger).Log(
		definitions.LogKeyGUID, a.guid,
		definitions.LogKeyAuthSubject, a.logoutRequest.GetSubject(),
		definitions.LogKeyAuthStatus, definitions.LogKeyAuthReject,
		definitions.LogKeyUriPath, a.deps.Cfg.GetServer().Frontend.GetLogoutPage()+"/post",
		definitions.LogKeyClientIP, a.ctx.Request.RemoteAddr,
	)
}

// LogoutPOSTHandler Page '/logout/post'
func (h *HydraHandlers) LogoutPOSTHandler(ctx *gin.Context) {
	var (
		err          error
		httpResponse *http.Response
	)

	logoutChallenge := ctx.PostForm("ory.hydra.logout_challenge")
	if logoutChallenge == "" {
		HandleHydraErrWithDeps(ctx, errors.ErrNoLoginChallenge, h.deps)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx, deps: h.deps}

	apiConfig.initialize()

	apiConfig.challenge = logoutChallenge

	apiConfig.logoutRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2LogoutRequest(ctx).LogoutChallenge(
		apiConfig.challenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse, h.deps)

		return
	}

	apiConfig.handleLogoutSubmit()
}

// LogoutPOSTHandler Page '/logout/post' (legacy)
func LogoutPOSTHandler(deps AuthDeps) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := NewHydraHandlers(deps)
		h.LogoutPOSTHandler(ctx)
	}
}

// getClaimsFromConsentContext extracts claims from consentContext based on acceptedScopes
func getClaimsFromConsentContext(guid string, acceptedScopes []string, consentContext any, deps AuthDeps) (
	session *openapi.AcceptOAuth2ConsentRequestSession,
) {
	claimDict, assertOk := consentContext.(map[string]any)
	if !assertOk {
		return nil
	}

	claims := make(map[string]any)
	for index, scope := range acceptedScopes {
		switch scope {
		case definitions.ScopeProfile:
			processProfileClaim(claimDict, claims)
		case definitions.ScopeEmail:
			processEmailClaim(claimDict, claims)
		case definitions.ScopeAddress:
			processAddressClaim(claimDict, claims)
		case definitions.ScopePhone:
			processPhoneClaim(claimDict, claims)
		case definitions.ScopeGroups:
			processGroupsClaim(claimDict, claims)
		}

		processCustomScopes(claimDict, claims, acceptedScopes, index, deps)
	}

	util.DebugModuleWithCfg(context.Background(), deps.Cfg, deps.Logger, definitions.DbgHydra, definitions.LogKeyGUID, guid, "claims", fmt.Sprintf("%+v", claims))

	session = &openapi.AcceptOAuth2ConsentRequestSession{
		IdToken: claims,
	}

	return
}

// processProfileClaim processes the profile claims from the claim dictionary and adds them to the claims map.
// The profile claims include: ClaimName, ClaimGivenName, ClaimFamilyName, ClaimMiddleName, ClaimNickName,
// ClaimPreferredUserName, ClaimProfile, ClaimWebsite, ClaimPicture, ClaimGender, ClaimBirtDate, ClaimZoneInfo, ClaimLocale.
// For each profile claim found in the claim dictionary, it is added to the claims map.
// If ClaimUpdatedAt is found in the claim dictionary as a float64, it is added to the claims map as well.
func processProfileClaim(claimDict map[string]any, claims map[string]any) {
	profileClaims := []string{
		definitions.ClaimName, definitions.ClaimGivenName, definitions.ClaimFamilyName, definitions.ClaimMiddleName, definitions.ClaimNickName,
		definitions.ClaimPreferredUserName, definitions.ClaimProfile, definitions.ClaimWebsite, definitions.ClaimPicture, definitions.ClaimGender,
		definitions.ClaimBirtDate, definitions.ClaimZoneInfo, definitions.ClaimLocale,
	}

	for _, key := range profileClaims {
		if value, found := claimDict[key]; found {
			claims[key] = value
		}
	}

	if value, found := claimDict[definitions.ClaimUpdatedAt].(float64); found {
		claims[definitions.ClaimUpdatedAt] = value
	}
}

// processEmailClaim updates the claims map with the email and email_verified claims
func processEmailClaim(claimDict map[string]any, claims map[string]any) {
	keys := []string{definitions.ClaimEmail, definitions.ClaimEmailVerified}
	for _, key := range keys {
		if value, found := claimDict[key]; found {
			claims[key] = value
		}
	}
}

// processAddressClaim updates the claims map with the address claim from the claimDict.
// The address claim is stored under the key "address".
func processAddressClaim(claimDict map[string]any, claims map[string]any) {
	claims[definitions.ClaimAddress] = claimDict[definitions.ClaimAddress]
}

// processPhoneClaim processes the phone claims from the claim dictionary and adds them to the claims map.
func processPhoneClaim(claimDict map[string]any, claims map[string]any) {
	keys := []string{definitions.ClaimPhoneNumber, definitions.ClaimPhoneNumberVerified}
	for _, key := range keys {
		if value, found := claimDict[key]; found {
			claims[key] = value
		}
	}
}

// processGroupsClaim processes the groups claim from the claimDict and adds it to the claims map.
//
// If the groups claim is found in the claimDict, it extracts the string values and adds them to a string slice.
// The string slice is then assigned to the groups claim in the claims map.
func processGroupsClaim(claimDict map[string]any, claims map[string]any) {
	if value, found := claimDict[definitions.ClaimGroups].([]any); found {
		var stringSlice []string

		for anyIndex := range value {
			if arg, assertOk := value[anyIndex].(string); assertOk {
				stringSlice = append(stringSlice, arg)
			}
		}

		claims[definitions.ClaimGroups] = value
	}
}

// processCustomScopes iterates through the custom scopes defined in the configuration file and processes the corresponding claims for the accepted scope at the given index.
// For each custom scope, it calls the processCustomClaim function to process its claims.
// If the accepted scope at the given index does not match the name of a custom scope, it continues to the next custom scope.
// It breaks out of the loop after processing the first matched custom scope.
// Arguments:
// - claimDict: A map[string]any representing the dictionary of claims.
// - claims: A map[string]any representing the processed claims.
// - acceptedScopes: A []string representing the list of accepted scopes.
// - index: An int indicating the index of the accepted scope to process.
func processCustomScopes(claimDict map[string]any, claims map[string]any, acceptedScopes []string, index int, deps AuthDeps) {
	if deps.Cfg.GetOauth2() != nil {
		for scopeIndex := range deps.Cfg.GetOauth2().CustomScopes {
			customScope := deps.Cfg.GetOauth2().CustomScopes[scopeIndex]

			if acceptedScopes[index] != customScope.Name {
				continue
			}

			for claimIndex := range customScope.Claims {
				customClaim := customScope.Claims[claimIndex]
				claims = assignClaimValueByType(claimDict, customClaim.Name, customClaim.Type, claims, deps)
			}

			break
		}
	}
}

// Assigns claim type-specific value and returns updated claims' map
func assignClaimValueByType(claimDict map[string]any, customClaimName string, customClaimType string, claims map[string]any, deps AuthDeps) map[string]any {
	switch customClaimType {
	case definitions.ClaimTypeString:
		if value, found := claimDict[customClaimName].(string); found {
			claims[customClaimName] = value
		}
	case definitions.ClaimTypeFloat:
		if value, found := claimDict[customClaimName].(float64); found {
			claims[customClaimName] = value
		}
	case definitions.ClaimTypeInteger:
		if value, found := handleIntegerClaimType(claimDict, customClaimName); found {
			claims[customClaimName] = value
		}
	case definitions.ClaimTypeBoolean:
		if value, found := claimDict[customClaimName].(bool); found {
			claims[customClaimName] = value
		}
	default:
		logUnknownClaimTypeError(customClaimName, customClaimType, deps)
	}

	return claims
}

// Handling specific case for Integer claim type
func handleIntegerClaimType(claimDict map[string]any, customClaimName string) (int64, bool) {
	if value, found := claimDict[customClaimName].(int64); found {
		return value, found
	} else if value, found := claimDict[customClaimName].(float64); found {
		return int64(value), found
	}

	return 0, false
}

// Logs error for unknown claim type
func logUnknownClaimTypeError(customClaimName string, customClaimType string, deps AuthDeps) {
	level.Error(deps.Logger).Log(
		"custom_claim_name", customClaimName,
		definitions.LogKeyMsg, "Unknown claim type",
		definitions.LogKeyError, fmt.Errorf("Unknown type '%s'", customClaimType),
	)
}
