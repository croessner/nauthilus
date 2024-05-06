package core

// See the markdown documentation for the login-, two-factor-, consent- and logout pages for a brief description.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/tags"
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

// Scope represents a scope used in the ConsentPageData struct. It contains the name and description of the scope.
// Scope represents the scope of an object.
type Scope struct {
	// ScopeName represents the name of the scope.
	ScopeName string

	// ScopeDescription represents a detailed description of the scope.
	ScopeDescription string
}

// Language represents a language used in various page data structs.
// Language represents a programming language
type Language struct {
	// LanguageLink represents the link associated with the language
	LanguageLink string

	// LanguageName represents the name of the language
	LanguageName string
}

type LoginPageData struct {
	// InDevelopment is a flag that is true, if the build-tag dev is used.
	InDevelopment bool

	// Determines if the Welcome message should be displayed
	WantWelcome bool

	// Determines if the Policy should be displayed
	WantPolicy bool

	// Determines if the Terms of Service (TOS) should be displayed
	WantTos bool

	// Determines if the About information should be displayed
	WantAbout bool

	// WantRemember is a flag for the regular login page.
	WantRemember bool

	// Indicates if there was an error
	HaveError bool

	// The title of the Login page
	Title string

	// The Welcome message
	Welcome string

	// The path or URL to logo image to be displayed
	LogoImage string

	// The alternate text for the logo image
	LogoImageAlt string

	// The name of the application
	ApplicationName string

	// The login details
	Login string

	// The placeholder for the login input form
	LoginPlaceholder string

	// The Privacy statement
	Privacy string

	// User password
	Password string

	// Placeholder for password input form
	PasswordPlaceholder string

	// The Policy terms
	Policy string

	// The URL to the policy document
	PolicyUri string

	// The Terms of Service
	Tos string

	// The URL to the Terms of Service document
	TosUri string

	// Information about the service or company
	About string

	// The URL to more About information
	AboutUri string

	// Information regarding remember functionality
	Remember string

	// Text for Submit button
	Submit string

	// Error message if any
	ErrorMessage string

	// Alternate choices text
	Or string

	// Information on the device being used
	Device string

	// CSRF security token
	CSRFToken string

	// Login challenge token
	LoginChallenge string

	// Endpoint for submitting login
	PostLoginEndpoint string

	// Endpoint for device login
	DeviceLoginEndpoint string

	// Current language code
	LanguageTag string

	// Name of the current language
	LanguageCurrentName string

	// List of other available languages
	LanguagePassive []Language
}

// TwoFactorData is a struct that includes parameters for processing two-factor
// authentication. It handles various attributes ranging from welcome messages,
// terms of service, about sections, among others.
type TwoFactorData struct {
	// WantWelcome indicates if a welcome message is desired
	WantWelcome bool

	// WantPolicy indicates if a policy message is required
	WantPolicy bool

	// WantTos indicates if Terms of Service is mandatory
	WantTos bool

	// WantAbout indicates if displaying 'About' information is desired
	WantAbout bool

	// Title is the title of the webpage or context
	Title string

	// Welcome is the welcome message
	Welcome string

	// LogoImage is the link of the logo image
	LogoImage string

	// LogoImageAlt is the alt text of the logo image
	LogoImageAlt string

	// ApplicationName is the name of the application
	ApplicationName string

	// Code is the two-factor authentication code
	Code string

	// Policy is the policy text
	Policy string

	// PolicyUri is the link to the policy document
	PolicyUri string

	// Tos is the Terms of Service text
	Tos string

	// TosUri is the URL to the Terms of Service document
	TosUri string

	// About holds content related to 'About Us' or 'About the Application'
	About string

	// AboutUri is the URL to the 'About Us' or 'About the application' page
	AboutUri string

	// Submit is the label for the submit action
	Submit string

	// CSRFToken is the token used for Cross-Site Request Forgery protection
	CSRFToken string

	// LoginChallenge represents the challenge used for login
	LoginChallenge string

	// User is the User ID or Name
	User string

	// PostLoginEndpoint is the API endpoint to submit login data
	PostLoginEndpoint string

	// LanguageTag houses the language tag, e.g., 'en-US'
	LanguageTag string

	// LanguageCurrentName is the fullname of the current language (e.g., 'English')
	LanguageCurrentName string

	// LanguagePassive houses a slice of the languages that are passively being used/available
	LanguagePassive []Language
}

// LogoutPageData defines the data structure for details related to the logout page.
type LogoutPageData struct {
	// WantWelcome is a flag indicating if the welcome message should be displayed or not.
	WantWelcome bool

	// Title represents the title of the logout page.
	Title string

	// Welcome holds the welcome message to be displayed, if WantWelcome flag is set to true.
	Welcome string

	// LogoutMessage carries the logout message.
	LogoutMessage string

	// AcceptSubmit and RejectSubmit hold messages for submission options upon logout.
	// These could be used for multi-step or confirmation based logout procedures.
	AcceptSubmit string
	RejectSubmit string

	// CSRFToken represents the CSRF token for security measures.
	CSRFToken string

	// LogoutChallenge represents a challenge string for logout.
	// It can be used for additional validation on logout requests.
	LogoutChallenge string

	// PostLogoutEndpoint is the endpoint to which requests are made after logout.
	PostLogoutEndpoint string

	// LanguageTag refers to the IETF language tag for selected language (e.g. "en-US").
	LanguageTag string

	// LanguageCurrentName is the human-readable name of the current language (e.g. "English").
	LanguageCurrentName string

	// LanguagePassive is a slice of passive languages supported by the system.
	// These could be offered as alternative language options on the logout page.
	LanguagePassive []Language
}

// ConsentPageData defines the data structure for managing user consent information on a web page.
type ConsentPageData struct {
	// WantWelcome is a boolean to indicate if a welcome message is needed.
	WantWelcome bool

	// WantPolicy is a boolean to indicate if a policy is needed.
	WantPolicy bool

	// WantTos is a boolean to indicate if Terms of Service is required.
	WantTos bool

	// WantAbout is a boolean to indicate if an "About Us" section is needed.
	WantAbout bool

	// Title represents the title of the consent page.
	Title string

	// Welcome represents welcome text message on the page.
	Welcome string

	// LogoImage represents the URI to logo image on the page.
	LogoImage string

	// LogoImageAlt is the alternative text for the Logo Image.
	LogoImageAlt string

	// ConsentMessage is the message shown on the consent page.
	ConsentMessage string

	// ApplicationName represents the name of the application asking for consent.
	ApplicationName string

	// Policy represents the text of the policy.
	Policy string

	// PolicyUri represents the URI to the policy document.
	PolicyUri string

	// Tos represents the text of the Terms of Service (ToS).
	Tos string

	// TosUri represents the URI to the Terms of Service (ToS) document.
	TosUri string

	// About represents the text of the about section.
	About string

	// AboutUri represents the URI to the about information.
	AboutUri string

	// Remember is the text related to remember user preferences on the consent page.
	Remember string

	// AcceptSubmit represents the text on the Accept button.
	AcceptSubmit string

	// RejectSubmit represents the text on the Reject button.
	RejectSubmit string

	// CSRFToken is used for CSRF protection.
	CSRFToken string

	// ConsentChallenge holds the unique consent challenge string from ORY Hydra.
	ConsentChallenge string

	// PostConsentEndpoint is the endpoint where the browser will be redirected after consent is provided.
	PostConsentEndpoint string

	// LanguageTag represents the language preference of the client.
	LanguageTag string

	// LanguageCurrentName represents the current name of the language.
	LanguageCurrentName string

	// Scopes represents the list of scopes that the app is requesting access to.
	Scopes []Scope

	// LanguagePassive represents the list of passive languages.
	LanguagePassive []Language
}

// NotifyPageData represents page notification data.
type NotifyPageData struct {
	// WantWelcome indicates if a welcome message is desired.
	WantWelcome bool

	// WantPolicy indicates if a policy notification is desired.
	WantPolicy bool

	// WantTos indicates if terms of service notification is desired.
	WantTos bool

	// Title represents the title of the notification page.
	Title string

	// Welcome represents the welcome message on the notification page.
	Welcome string

	// LogoImage represents the URL of the logo displayed on the notification page.
	LogoImage string

	// LogoImageAlt represents the alternative text for the logo image.
	LogoImageAlt string

	// NotifyMessage represents the notification message displayed on the page.
	NotifyMessage string

	// LanguageTag represents the IETF language tag for the current language.
	LanguageTag string

	// LanguageCurrentName represents the name of the current language in its language.
	LanguageCurrentName string

	// LanguagePassive represents a list of other available languages.
	LanguagePassive []Language
}

// ApiConfig is a struct that encapsulates configuration and parameters for
// HTTP communication with OAuth2 OpenID-Connect server via OpenAPI. This includes
// configurations for HTTP client, authorization parameters, and request context.
type ApiConfig struct {
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

// handleErr handles an error by logging the error details and printing a goroutine dump.
// It sets the "failure" and "message" values in the context, and then calls the notifyGETHandler function.
// If the error is of type *errors2.DetailedError, it logs the error details along with the error message.
// Otherwise, it logs only the error message.
// The function also prints the goroutine dump with the corresponding GUID.
// Finally, it cleans up the session using the sessionCleaner function.
//
// ctx: The Gin context.
// err: The error to handle.
func handleErr(ctx *gin.Context, err error) {
	processErrorLogging(ctx, err)
	sessionCleaner(ctx)
	ctx.Set("failure", true)
	ctx.Set("message", err)
	notifyGETHandler(ctx)
}

// processErrorLogging logs the error details and prints a goroutine dump.
// It takes the Gin context and the error as inputs.
// It retrieves the GUID from the context and logs the error using the logError function.
// It then creates a buffer and uses the runtime.Stack function to fill the buffer with a goroutine dump.
// Finally, it prints the goroutine dump along with the GUID to the console.
//
// ctx: The Gin context.
// err: The error to log.
// Usage example:
//
//	handleErr(ctx, err)
//	sessionCleaner(ctx)
//	ctx.Set("failure", true)
//	ctx.Set("message", err)
//	notifyGETHandler(ctx)
//
// See logError, global.CtxGUIDKey, and runtime.Stack for additional information.
func processErrorLogging(ctx *gin.Context, err error) {
	guid := ctx.GetString(global.CtxGUIDKey)

	logError(ctx, err)

	if config.LoadableConfig.Server.Log.Level.Level() == global.LogLevelDebug && config.EnvConfig.DevMode {
		buf := make([]byte, 1<<20)
		stackLen := runtime.Stack(buf, false)

		fmt.Printf("=== guid=%s\n*** goroutine dump...\n%s\n*** end\n", guid, buf[:stackLen])
	}
}

// logError logs the error details along with the corresponding GUID, client IP, and error message.
// If the error is of type *errors2.DetailedError, it logs the error details using logging.DefaultErrLogger.Log method.
// Otherwise, it logs only the error message.
//
// ctx: The Gin context.
// err: The error to log.
func logError(ctx *gin.Context, err error) {
	var detailedError *errors2.DetailedError

	guid := ctx.GetString(global.CtxGUIDKey)

	if errors.As(err, &detailedError) {
		level.Error(logging.DefaultErrLogger).Log(
			global.LogKeyGUID, guid,
			global.LogKeyError, (*detailedError).Error(),
			global.LogKeyErrorDetails, (*detailedError).GetDetails(),
			global.LogKeyClientIP, ctx.Request.RemoteAddr,
		)
	} else {
		level.Error(logging.DefaultErrLogger).Log(
			global.LogKeyGUID, guid,
			global.LogKeyError, err,
			global.LogKeyClientIP, ctx.Request.RemoteAddr,
		)
	}
}

// notifyGETHandler handles the GET request for the notification page.
// It sets the HTTP status code, status title, and notification message based on the context.
// It also prepares the data for rendering the notify.html template and executes the HTML rendering.
func notifyGETHandler(ctx *gin.Context) {
	var (
		found          bool
		msg            string
		value          any
		httpStatusCode = http.StatusOK
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
	cookieValue := session.Get(global.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(ctx, viper.GetString("notify_page"), config.DefaultLanguageTags, languageCurrentName)

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
		LanguageTag:         session.Get(global.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		WantTos:             false,
		WantPolicy:          false,
	}

	ctx.HTML(httpStatusCode, "notify.html", notifyData)
}

// getLocalized is a function that returns the localized message based on the message ID and the context provided.
// If the localization fails, an error is logged.
func getLocalized(ctx *gin.Context, messageID string) string {
	localizer := ctx.MustGet(global.CtxLocalizedKey).(*i18n.Localizer)

	localizeConfig := i18n.LocalizeConfig{
		MessageID: messageID,
	}
	localization, err := localizer.Localize(&localizeConfig)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(
			global.LogKeyGUID, ctx.GetString(global.CtxGUIDKey),
			"message_id", messageID, global.LogKeyError, err.Error(),
		)
	}

	return localization
}

// handleHydraErr handles an error by checking the status code of the http response.
// If the status code is StatusNotFound, it calls the handleErr function with errors2.ErrUnknownJSON as the error.
// If the status code is StatusGone, it calls the handleErr function with errors2.ErrHTTPRequestGone as the error.
// Otherwise, it calls the handleErr function with the original error.
// If the http response is nil, it calls the handleErr function with the original error.
//
// ctx: The Gin context.
// err: The error to handle.
// httpResponse: The http response object.
// handleErr: The function that handles an error.
// errors2.ErrUnknownJSON: The error representing an unknown JSON response.
// errors2.ErrHTTPRequestGone: The error representing a gone http request.
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
func setLanguageDetails(langFromURL string, langFromCookie string) (lang string, needCookie bool, needRedirect bool) {
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

	return lang, needCookie, needRedirect
}

// withLanguageMiddleware is a middleware function that handles the language setup for the application.
// It tries to get the language tag from the URL and the cookie.
// It sets the language details and creates a localizer based on the selected language.
// It also handles CSRF token and localization in the context.
// If the language is not found in the catalog, it aborts the request with a "Language Not Found" error.
// If the language needs to be saved in a cookie or redirection is required, it does so accordingly.
// Finally, it calls the next handler in the chain.
func withLanguageMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			langFromURL    string
			langFromCookie string
		)

		guid := ctx.GetString(global.CtxGUIDKey)

		// Try to get language tag from URL
		langFromURL = ctx.Param("languageTag")

		// Try to get language tag from cookie
		session := sessions.Default(ctx)

		cookieValue := session.Get(global.CookieLang)
		if cookieValue != nil {
			langFromCookie, _ = cookieValue.(string)
		}

		lang, needCookie, needRedirect := setLanguageDetails(langFromURL, langFromCookie)
		accept := ctx.GetHeader("Accept-Language")
		tag, _ := language.MatchStrings(config.Matcher, lang, accept)
		baseName, _ := tag.Base()

		util.DebugModule(
			global.DbgHydra,
			global.LogKeyGUID, guid,
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
			session.Set(global.CookieLang, baseName.String())
			session.Save()
		}

		ctx.Set(global.CtxCSRFTokenKey, nosurf.Token(ctx.Request))
		ctx.Set(global.CtxLocalizedKey, localizer)

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

// createHttpClient creates an HTTP client with a custom configuration.
// The client uses an http.Transport with a custom *tls.Config, which allows skipping TLS verification
// based on the value of the "http_client_skip_tls_verify" configuration.
// The client also has a Timeout of 30 seconds.
// Returns the created http.Client.
func createHttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: config.LoadableConfig.Server.TLS.HTTPClientSkipVerify}},
		Timeout:   30 * time.Second,
	}
}

// createConfiguration returns a new instance of the openapi.Configuration struct with the provided httpClient and server configuration.
// The httpClient parameter is used as the underlying HTTP client for API calls made by the openapi.client.
// The server configuration is read from the "hydra_admin_uri" configuration value using viper.GetString() function.
func createConfiguration(httpClient *http.Client) *openapi.Configuration {
	return &openapi.Configuration{
		HTTPClient: httpClient,
		Servers:    []openapi.ServerConfiguration{{URL: config.LoadableConfig.Server.HydraAdminUrl}},
	}
}

// createUserdata creates a map containing user data from a session based on the given keys.
// It returns a map[string]any. The function iterates through the keys and retrieves the corresponding values from the session.
// If the value is not nil, it is added to the userData map with the key as the key in the session.
//
// Params:
// - session: the session to retrieve data from
// - keys: the keys to retrieve data for
//
// Returns:
// - userData: a map containing the user data
func createUserdata(session sessions.Session, keys ...string) map[string]any {
	userData := make(map[string]any, len(keys))

	for _, key := range keys {
		value := session.Get(key)
		if value != nil {
			userData[key] = value
		}
	}

	return userData
}

// createLanguagePassive is a function that takes a gin.Context and a slice of language.Tags as input,
// along with the currentName string. It returns a slice of Language structs. The function iterates over
// the languageTags slice and creates a Language struct for each tag, except the one with the currentName.
// The Language struct has two fields: LanguageLink and LanguageName.
// The function appends each created Language struct to the languagePassive slice, and finally returns
// the languagePassive slice.
func createLanguagePassive(ctx *gin.Context, destPage string, languageTags []language.Tag, currentName string) []Language {
	var languagePassive []Language

	for _, languageTag := range languageTags {
		languageName := cases.Title(languageTag, cases.NoLower).String(display.Self.Name(languageTag))
		if languageName != currentName {
			baseName, _ := languageTag.Base()
			languagePassive = append(
				languagePassive,
				Language{
					LanguageLink: destPage + "/" + baseName.String() + "?" + ctx.Request.URL.RawQuery,
					LanguageName: languageName,
				},
			)
		}
	}

	return languagePassive
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
	a.httpClient = createHttpClient()
	a.guid = a.ctx.GetString(global.CtxGUIDKey)
	configuration := createConfiguration(a.httpClient)
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
func (a *ApiConfig) handleLogin(skip bool) {
	util.DebugModule(global.DbgHydra, global.LogKeyGUID, a.guid, global.LogKeyMsg, fmt.Sprintf("%s is %v", global.LogKeyLoginSkip, skip))

	if skip {
		a.handleLoginSkip()
	} else {
		a.handleLoginNoSkip()
	}
}

// handleLoginSkip processes the login request when skip is true.
func (a *ApiConfig) handleLoginSkip() {
	var (
		err           error
		acceptRequest *openapi.OAuth2RedirectTo
		httpResponse  *http.Response
		claims        map[string]any
	)

	util.DebugModule(global.DbgHydra, global.LogKeyGUID, a.guid, global.LogKeyMsg, fmt.Sprintf("%s is %v", global.LogKeyLoginSkip, true))

	oauth2Client := a.loginRequest.GetClient()

	auth := &Authentication{
		HTTPClientContext: a.ctx.Copy(),
		NoAuth:            true,
		Protocol:          config.NewProtocol(global.ProtoOryHydra),
	}

	auth.withDefaults(a.ctx).withClientInfo(a.ctx).withLocalInfo(a.ctx).withUserAgent(a.ctx).withXSSL(a.ctx)

	auth.Username = a.loginRequest.GetSubject()
	auth.UsernameOrig = a.loginRequest.GetSubject()

	if err := auth.setStatusCodes(global.ServOryHydra); err != nil {
		handleErr(a.ctx, err)

		return
	}

	if authStatus := auth.handlePassword(a.ctx); authStatus == global.AuthResultOK {
		if config.LoadableConfig.Oauth2 != nil {
			_, claims = auth.getOauth2SubjectAndClaims(oauth2Client)
		}
	} else {
		auth.ClientIP = a.ctx.GetString(global.CtxClientIPKey)

		auth.updateBruteForceBucketsCounter()
		a.ctx.AbortWithError(http.StatusInternalServerError, errors2.ErrUnknownCause)

		return
	}

	acceptLoginRequest := a.apiClient.OAuth2API.AcceptOAuth2LoginRequest(a.ctx).AcceptOAuth2LoginRequest(
		openapi.AcceptOAuth2LoginRequest{
			Subject: a.loginRequest.GetSubject(),
			Context: claims,
		})

	acceptRequest, httpResponse, err = acceptLoginRequest.LoginChallenge(a.challenge).Execute()
	if err != nil {
		handleHydraErr(a.ctx, err, httpResponse)

		return
	}

	a.ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

	a.logInfoLoginSkip(acceptRequest.GetRedirectTo())
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

	util.DebugModule(global.DbgHydra, global.LogKeyGUID, a.guid, global.LogKeyMsg, fmt.Sprintf("%s is %v", global.LogKeyLoginSkip, false))

	oauth2Client := a.loginRequest.GetClient()

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
	session := sessions.Default(a.ctx)

	cookieValue := session.Get(global.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(a.ctx, viper.GetString("login_page"), config.DefaultLanguageTags, languageCurrentName)

	userData := createUserdata(session, global.CookieUsername, global.CookieAuthResult)

	// Handle TOTP request
	if authResult, found := userData[global.CookieAuthResult]; found {
		if authResult != global.AuthResultUnset {
			twoFactorData := &TwoFactorData{
				Title: getLocalized(a.ctx, "Login"),
				WantWelcome: func() bool {
					if viper.GetString("login_page_welcome") != "" {
						return true
					}

					return false
				}(),
				Welcome:             viper.GetString("login_page_welcome"),
				ApplicationName:     applicationName,
				WantAbout:           wantAbout,
				About:               getLocalized(a.ctx, "Get further information about this application..."),
				AboutUri:            clientUri,
				LogoImage:           imageUri,
				LogoImageAlt:        viper.GetString("login_page_logo_image_alt"),
				WantPolicy:          wantPolicy,
				Code:                getLocalized(a.ctx, "OTP-Code"),
				Policy:              getLocalized(a.ctx, "Privacy policy"),
				PolicyUri:           policyUri,
				WantTos:             wantTos,
				Tos:                 getLocalized(a.ctx, "Terms of service"),
				TosUri:              tosUri,
				Submit:              getLocalized(a.ctx, "Submit"),
				PostLoginEndpoint:   viper.GetString("login_page"),
				LanguageTag:         session.Get(global.CookieLang).(string),
				LanguageCurrentName: languageCurrentName,
				LanguagePassive:     languagePassive,
				CSRFToken:           a.csrfToken,
				LoginChallenge:      a.challenge,
			}

			a.ctx.HTML(http.StatusOK, "totp.html", twoFactorData)

			util.DebugModule(
				global.DbgHydra,
				global.LogKeyGUID, a.guid,
				global.LogKeyMsg, "Two factor authentication",
				global.LogKeyUsername, userData[global.CookieUsername].(string),
			)

			return
		}
	}

	if errorMessage = a.ctx.Query("_error"); errorMessage != "" {
		if errorMessage == global.PasswordFail {
			errorMessage = getLocalized(a.ctx, global.PasswordFail)
		}

		haveError = true
	}

	loginData := &LoginPageData{
		Title: getLocalized(a.ctx, "Login"),
		WantWelcome: func() bool {
			if viper.GetString("login_page_welcome") != "" {
				return true
			}

			return false
		}(),
		Welcome:             viper.GetString("login_page_welcome"),
		ApplicationName:     applicationName,
		WantAbout:           wantAbout,
		About:               getLocalized(a.ctx, "Get further information about this application..."),
		AboutUri:            clientUri,
		LogoImage:           imageUri,
		LogoImageAlt:        viper.GetString("login_page_logo_image_alt"),
		HaveError:           haveError,
		ErrorMessage:        errorMessage,
		Login:               getLocalized(a.ctx, "Login"),
		Privacy:             getLocalized(a.ctx, "We'll never share your data with anyone else."),
		LoginPlaceholder:    getLocalized(a.ctx, "Please enter your username or email address"),
		Password:            getLocalized(a.ctx, "Password"),
		PasswordPlaceholder: getLocalized(a.ctx, "Please enter your password"),
		WantPolicy:          wantPolicy,
		Policy:              getLocalized(a.ctx, "Privacy policy"),
		PolicyUri:           policyUri,
		WantTos:             wantTos,
		Tos:                 getLocalized(a.ctx, "Terms of service"),
		TosUri:              tosUri,
		Remember:            getLocalized(a.ctx, "Remember me"),
		Submit:              getLocalized(a.ctx, "Submit"),
		Or:                  getLocalized(a.ctx, "or"),
		Device:              getLocalized(a.ctx, "Login with WebAuthn"),
		PostLoginEndpoint:   viper.GetString("login_page"),
		DeviceLoginEndpoint: viper.GetString("device_page"),
		LanguageTag:         session.Get(global.CookieLang).(string),
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
func (a *ApiConfig) logInfoLoginSkip(redirectTo string) {
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, a.guid,
		global.LogKeySkip, true,
		global.LogKeyClientID, *a.clientId,
		global.LogKeyClientName, a.clientName,
		global.LogKeyAuthSubject, a.loginRequest.GetSubject(),
		global.LogKeyAuthChallenge, a.challenge,
		global.LogKeyAuthStatus, global.LogKeyAuthAccept,
		global.LogKeyUriPath, viper.GetString("login_page"),
		global.LogKeyRedirectTo, redirectTo,
	)
}

// logInfoLoginNoSkip logs information about the login operation without skipping any step.
func (a *ApiConfig) logInfoLoginNoSkip() {
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, a.guid,
		global.LogKeySkip, false,
		global.LogKeyClientID, *a.clientId,
		global.LogKeyClientName, a.clientName,
		global.LogKeyAuthChallenge, a.challenge,
		global.LogKeyUriPath, viper.GetString("login_page"),
	)
}

// Page '/login'
func loginGETHandler(ctx *gin.Context) {
	var (
		err          error
		httpResponse *http.Response
	)

	loginChallenge := ctx.Query("login_challenge")
	if loginChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx}

	apiConfig.initialize()

	apiConfig.challenge = loginChallenge
	apiConfig.csrfToken = ctx.GetString(global.CtxCSRFTokenKey)

	apiConfig.loginRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2LoginRequest(ctx).LoginChallenge(
		apiConfig.challenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	oauth2Client := apiConfig.loginRequest.GetClient()

	clientIdFound := false
	if apiConfig.clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		handleErr(ctx, errors2.ErrHydraNoClientId)

		return
	}

	apiConfig.clientName = oauth2Client.GetClientName()

	apiConfig.handleLogin(apiConfig.loginRequest.GetSkip())
}

// initializeAuthLogin initializes the Authentication struct with the necessary information for logging in.
func initializeAuthLogin(ctx *gin.Context) (*Authentication, error) {
	auth := &Authentication{
		HTTPClientContext: ctx.Copy(),
		Username:          ctx.PostForm("username"),
		Password:          ctx.PostForm("password"),
		Protocol:          config.NewProtocol(global.ProtoOryHydra),
	}

	// It might be the second call after 2FA! In this case, there does not exist any username or password.
	if auth.Username != "" && !util.ValidateUsername(auth.Username) {
		return nil, errors2.ErrInvalidUsername
	}

	if err := auth.setStatusCodes(global.ServOryHydra); err != nil {
		return nil, err
	}

	auth.withDefaults(ctx).withClientInfo(ctx).withLocalInfo(ctx).withUserAgent(ctx).withXSSL(ctx)

	if found, reject := auth.preproccessAuthRequest(ctx); reject {
		return nil, errors2.ErrBruteForceAttack
	} else if found {
		auth.withClientInfo(ctx).withLocalInfo(ctx).withUserAgent(ctx).withXSSL(ctx)
	}

	return auth, nil
}

// handleSessionDataLogin retrieves session data related to the login process and populates the provided `auth` variable with the values.
//
// Parameters:
// - ctx: The gin context object.
// - auth: Pointer to an Authentication struct to populate with retrieved values.
//
// Returns:
// - authResult: The result of the authentication process (global.AuthResult enum).
// - recentSubject: The recently used subject value.
// - rememberPost2FA: The remember value after the second factor authentication.
// - post2FA: A bool indicating if a second factor authentication is required.
// - err: An error object if saving the session failed, or nil otherwise.
func handleSessionDataLogin(ctx *gin.Context, auth *Authentication) (
	authResult global.AuthResult, recentSubject string, rememberPost2FA string, post2FA bool, err error,
) {
	var cookieValue any

	session := sessions.Default(ctx)

	// Restore authentication data from first call to login.html
	if cookieValue = session.Get(global.CookieUsername); cookieValue != nil {
		if cookieValue.(string) != "" {
			auth.Username = cookieValue.(string)
			auth.NoAuth = true
		}

		session.Delete(global.CookieUsername)
	}

	if cookieValue = session.Get(global.CookieAuthResult); cookieValue != nil {
		authResult = global.AuthResult(cookieValue.(uint8))
		if authResult != global.AuthResultUnset {
			post2FA = true
		}

		session.Delete(global.CookieAuthResult)
	}

	if cookieValue = session.Get(global.CookieSubject); cookieValue != nil {
		recentSubject = cookieValue.(string)

		session.Delete(global.CookieSubject)
	}

	if cookieValue = session.Get(global.CookieRemember); cookieValue != nil {
		rememberPost2FA = cookieValue.(string)

		session.Delete(global.CookieRemember)
	}

	err = session.Save()
	if err != nil {
		return
	}

	auth.UsernameOrig = auth.Username

	return
}

// processAuthOkLogin processes the successful login authentication flow.
//
// Params:
// - auth: the Authentication object containing the authentication data
// - authResult: the AuthResult code indicating the authentication result
// - rememberPost2FA: a string indicating whether to remember the user after 2FA
// - recentSubject: the subject of the recent login attempt
// - post2FA: a boolean indicating whether this is a post-2FA login attempt
//
// Returns:
// - err: an error if any occurred during the process
func (a *ApiConfig) processAuthOkLogin(auth *Authentication, authResult global.AuthResult, rememberPost2FA string, recentSubject string, post2FA bool) error {
	var (
		redirectFlag bool
		redirectTo   string
		err          error
	)

	account, found := auth.getAccountOk()
	if !found {
		return errors2.ErrNoAccount
	}

	subject, claims := a.getSubjectAndClaims(account, auth)

	if post2FA {
		if recentSubject != subject {
			return errors2.ErrNoAccount
		}

		err = a.handlePost2FA(auth, account)
		if err != nil {
			return err
		}
	} else {
		session := sessions.Default(a.ctx)

		redirectFlag, err = a.handleNonPost2FA(auth, session, authResult, subject)
		if err != nil {
			return err
		}

		if redirectFlag {
			return nil
		}
	}

	remember := a.isRemember(rememberPost2FA, post2FA)
	if redirectTo, err = a.acceptLogin(claims, subject, remember); err != nil {
		return err
	}

	a.logInfoLoginAccept(subject, redirectTo, auth)

	return nil
}

// getSubjectAndClaims retrieves the subject and claims for a given account and authentication object.
// If available, it uses the OAuth2 client to get the subject and claims from the authentication object.
// If the OAuth2 client is not available or the subject is empty, it uses the account as the subject.
// If the subject is empty, it logs a warning message using the `guid` field from the `ApiConfig` object and the account value.
// It returns the subject and claims as a string and map respectively.
func (a *ApiConfig) getSubjectAndClaims(account string, auth *Authentication) (string, map[string]any) {
	var (
		subject string
		claims  map[string]any
	)

	oauth2Client := a.loginRequest.GetClient()
	if config.LoadableConfig.Oauth2 != nil {
		subject, claims = auth.getOauth2SubjectAndClaims(oauth2Client)
	}

	if subject == "" {
		subject = account

		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyGUID, a.guid,
			global.LogKeyMsg, fmt.Sprintf("Empty 'subject', using '%s' as value", account),
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
// - auth: The Authentication object.
// - session: The session object.
// - authResult: The authentication result.
// - subject: The authentication subject.
//
// Returns:
// - bool: Indicates whether redirection is performed or not.
// - error: The error if any occurs.
func (a *ApiConfig) handleNonPost2FA(auth *Authentication, session sessions.Session, authResult global.AuthResult, subject string) (bool, error) {
	if config.GetSkipTOTP(*a.clientId) {
		return false, nil
	}

	if _, found := auth.getTOTPSecretOk(); found {
		if err := a.setSessionVariablesForAuth(session, authResult, subject); err != nil {
			return false, err
		}

		a.ctx.Redirect(
			http.StatusFound,
			viper.GetString("login_page")+"?login_challenge="+a.challenge,
		)

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
func (a *ApiConfig) handlePost2FA(auth *Authentication, account string) error {
	code := a.ctx.PostForm("code")
	if code == "" {
		return errors2.ErrNoTOTPCode
	}

	totpSecret, found := auth.getTOTPSecretOk()
	if !found {
		return errors2.ErrNoTOTPCode
	}

	err := a.totpValidation(code, account, totpSecret)
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

	rememberFor := int64(viper.GetInt("login_remember_for"))
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
func (a *ApiConfig) logInfoLoginAccept(subject string, redirectTo string, auth *Authentication) {
	logs := []any{
		global.LogKeyGUID, a.guid,
		global.LogKeyClientID, *a.clientId,
		global.LogKeyClientName, a.clientName,
		global.LogKeyAuthSubject, subject,
		global.LogKeyAuthChallenge, a.challenge,
		global.LogKeyUsername, a.ctx.PostForm("username"),
		global.LogKeyAuthStatus, global.LogKeyAuthAccept,
		global.LogKeyUriPath, viper.GetString("login_page") + "/post",
		global.LogKeyRedirectTo, redirectTo,
	}

	if len(auth.AdditionalLogs) > 0 && len(auth.AdditionalLogs)%2 == 0 {
		logs = append(logs, auth.AdditionalLogs...)
	}

	level.Info(logging.DefaultLogger).Log(logs...)
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
func (a *ApiConfig) totpValidation(code string, account string, totpSecret string) error {
	var urlComponents []string

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

	key, err := otp.NewKeyFromURL(totpURL)
	if err != nil {
		return err
	}

	if config.LoadableConfig.Server.Log.Level.Level() >= global.LogLevelDebug && config.EnvConfig.DevMode {
		util.DebugModule(
			global.DbgHydra,
			global.LogKeyGUID, a.guid,
			"totp_key", fmt.Sprintf("%+v", key),
		)
	}

	codeValid, err := totp.ValidateCustom(code, key.Secret(), time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      viper.GetUint("totp_skew"),
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if !codeValid {
		return errors2.ErrTOTPCodeInvalid
	}

	return nil
}

// setSessionVariablesForAuth sets the necessary session variables for authentication.
// It takes a `sessions.Session` object, `authResult` of type `global.AuthResult`, and the `subject` string as parameters.
// It sets the following session variables:
// - `global.CookieAuthResult`: uint8 value of `authResult`
// - `global.CookieUsername`: value of `username` field from the request form
// - `global.CookieSubject`: value of `subject`
// - `global.CookieRemember`: value of `remember` field from the request form
// It returns an `error` if there is any error saving the session.
//
// Example usage:
//
//	session := sessions.Default(ctx)
//	err := setSessionVariablesForAuth(session, authResult, subject)
//	if err != nil {
//	    // Handle error
//	}
func (a *ApiConfig) setSessionVariablesForAuth(session sessions.Session, authResult global.AuthResult, subject string) error {
	session.Set(global.CookieAuthResult, uint8(authResult))
	session.Set(global.CookieUsername, a.ctx.Request.Form.Get("username"))
	session.Set(global.CookieSubject, subject)
	session.Set(global.CookieRemember, a.ctx.Request.Form.Get("remember"))

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
// - auth: the Authentication object for the failed login
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
func (a *ApiConfig) processAuthFailLogin(auth *Authentication, authResult global.AuthResult, post2FA bool) (err error) {
	session := sessions.Default(a.ctx)

	if !post2FA {
		if !config.GetSkipTOTP(*a.clientId) {
			if _, found := auth.getTOTPSecretOk(); found {
				session.Set(global.CookieAuthResult, uint8(authResult))
				session.Set(global.CookieUsername, a.ctx.Request.Form.Get("username"))

				err = session.Save()
				if err != nil {
					return
				}
			}
		}
	}

	return
}

// logFailedLoginAndRedirect logs a failed login attempt and redirects the user to a login page with an error message.
func (a *ApiConfig) logFailedLoginAndRedirect(auth *Authentication) {
	loginChallenge := a.ctx.PostForm("ory.hydra.login_challenge")
	auth.ClientIP = a.ctx.GetString(global.CtxClientIPKey)

	auth.updateBruteForceBucketsCounter()

	a.ctx.Redirect(
		http.StatusFound,
		viper.GetString("login_page")+"?login_challenge="+loginChallenge+"&_error="+global.PasswordFail,
	)

	logs := []any{
		global.LogKeyGUID, a.guid,
		global.LogKeyClientID, *a.clientId,
		global.LogKeyClientName, a.clientName,
		global.LogKeyAuthChallenge, loginChallenge,
		global.LogKeyUsername, a.ctx.PostForm("username"),
		global.LogKeyAuthStatus, global.LogKeyAuthReject,
		global.LogKeyUriPath, viper.GetString("login_page") + "/post",
	}

	if len(auth.AdditionalLogs) > 0 && len(auth.AdditionalLogs)%2 == 0 {
		logs = append(logs, auth.AdditionalLogs...)
	}

	level.Info(logging.DefaultLogger).Log(logs...)
}

// Page '/login/post'
func loginPOSTHandler(ctx *gin.Context) {
	var (
		post2FA         bool
		authResult      global.AuthResult
		recentSubject   string
		rememberPost2FA string
		httpResponse    *http.Response
	)

	loginChallenge := ctx.PostForm("ory.hydra.login_challenge")
	if loginChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx}

	apiConfig.initialize()

	apiConfig.challenge = loginChallenge

	auth, err := initializeAuthLogin(ctx)
	if err != nil {
		handleErr(ctx, err)

		return
	}

	authResult, recentSubject, rememberPost2FA, post2FA, err = handleSessionDataLogin(ctx, auth)
	if err != nil {
		handleErr(ctx, err)

		return
	}

	apiConfig.loginRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2LoginRequest(ctx).LoginChallenge(
		apiConfig.challenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	oauth2Client := apiConfig.loginRequest.GetClient()

	clientIdFound := false
	if apiConfig.clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		handleErr(ctx, errors2.ErrHydraNoClientId)

		return
	}

	apiConfig.clientName = oauth2Client.GetClientName()

	if authResult == global.AuthResultUnset || authResult == global.AuthResultOK {
		authResult = auth.handlePassword(ctx)
	}

	switch authResult {
	case global.AuthResultOK:
		err = apiConfig.processAuthOkLogin(auth, authResult, rememberPost2FA, recentSubject, post2FA)
		if err != nil {
			handleErr(ctx, err)
		}

		return
	case global.AuthResultFail, global.AuthResultEmptyUsername, global.AuthResultEmptyPassword:
		err = apiConfig.processAuthFailLogin(auth, authResult, post2FA)
		if err != nil {
			handleErr(ctx, err)

			return
		}

		apiConfig.logFailedLoginAndRedirect(auth)
	default:
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}
}

// Page '/device'
func deviceGETHandler(ctx *gin.Context) {
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
		guid         = ctx.GetString(global.CtxGUIDKey)
		csrfToken    = ctx.GetString(global.CtxCSRFTokenKey)
		loginRequest *openapi.OAuth2LoginRequest
		httpResponse *http.Response
	)

	loginChallenge := ctx.Query("login_challenge")
	if loginChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	httpClient := createHttpClient()
	configuration := createConfiguration(httpClient)
	apiClient := openapi.NewAPIClient(configuration)

	loginRequest, httpResponse, err = apiClient.OAuth2API.GetOAuth2LoginRequest(ctx).LoginChallenge(
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

	cookieValue := session.Get(global.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(ctx, viper.GetString("device_page"), config.DefaultLanguageTags, languageCurrentName)

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
		LanguageTag:         session.Get(global.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           csrfToken,
		LoginChallenge:      loginChallenge,
	}

	ctx.HTML(http.StatusOK, "device.html", loginData)

	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, guid,
		global.LogKeySkip, false,
		global.LogKeyClientID, *clientId,
		global.LogKeyClientName, clientName,
		global.LogKeyAuthChallenge, loginChallenge,
		global.LogKeyUriPath, viper.GetString("device_page"),
	)
}

// Page '/device/post'
func devicePOSTHandler(ctx *gin.Context) {
	handleErr(ctx, errors.New("not implemented yet"))
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
func handleRequestedScopes(ctx *gin.Context, requestedScopes []string, session sessions.Session) []Scope {
	var (
		scopes           []Scope
		scopeDescription string
	)

	cookieValue := session.Get(global.CookieLang)

	for _, requestedScope := range requestedScopes {
		scopeDescription = getScopeDescription(ctx, requestedScope, cookieValue)
		scopes = append(scopes, Scope{ScopeName: requestedScope, ScopeDescription: scopeDescription})
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
// cookieValue: interface{}: Data to be used for custom scope requests.
//
// Returns:
// String: A string corresponding to the type of OAuth scope requested
func getScopeDescription(ctx *gin.Context, requestedScope string, cookieValue interface{}) string {
	switch requestedScope {
	case global.ScopeOpenId:
		return getLocalized(ctx, "Allow access to identity information")
	case global.ScopeOfflineAccess:
		return getLocalized(ctx, "Allow an application access to private data without your personal presence")
	case global.ScopeProfile:
		return getLocalized(ctx, "Allow access to personal profile data")
	case global.ScopeEmail:
		return getLocalized(ctx, "Allow access to your email address")
	case global.ScopeAddress:
		return getLocalized(ctx, "Allow access to your home address")
	case global.ScopePhone:
		return getLocalized(ctx, "Allow access to your phone number")
	case global.ScopeGroups:
		return getLocalized(ctx, "Allow access to group memberships")
	default:
		return getCustomScopeDescription(ctx, requestedScope, cookieValue)
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
func getCustomScopeDescription(ctx *gin.Context, requestedScope string, cookieValue any) string {
	var scopeDescription string

	if config.LoadableConfig.Oauth2 != nil {
		for _, customScope := range config.LoadableConfig.Oauth2.CustomScopes {
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
		scopeDescription = getLocalized(ctx, "Allow access to a specific scope")
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
	if !(a.consentRequest.GetSkip() || config.GetSkipConsent(*a.clientId)) {
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
	scopes := handleRequestedScopes(a.ctx, a.consentRequest.GetRequestedScope(), session)

	oauth2Client := a.consentRequest.GetClient()

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

	languageCurrentTag := language.MustParse(session.Get(global.CookieLang).(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(a.ctx, viper.GetString("consent_page"), config.DefaultLanguageTags, languageCurrentName)

	consentData := &ConsentPageData{
		Title: getLocalized(a.ctx, "Consent"),
		WantWelcome: func() bool {
			if viper.GetString("login_page_welcome") != "" {
				return true
			}

			return false
		}(),
		Welcome:             viper.GetString("consent_page_welcome"),
		LogoImage:           imageUri,
		LogoImageAlt:        viper.GetString("consent_page_logo_image_alt"),
		ConsentMessage:      getLocalized(a.ctx, "An application requests access to your data"),
		ApplicationName:     applicationName,
		WantAbout:           wantAbout,
		About:               getLocalized(a.ctx, "Get further information about this application..."),
		AboutUri:            clientUri,
		Scopes:              scopes,
		WantPolicy:          wantPolicy,
		Policy:              getLocalized(a.ctx, "Privacy policy"),
		PolicyUri:           policyUri,
		WantTos:             wantTos,
		Tos:                 getLocalized(a.ctx, "Terms of service"),
		TosUri:              tosUri,
		Remember:            getLocalized(a.ctx, "Do not ask me again"),
		AcceptSubmit:        getLocalized(a.ctx, "Accept access"),
		RejectSubmit:        getLocalized(a.ctx, "Deny access"),
		LanguageTag:         session.Get(global.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           a.csrfToken,
		ConsentChallenge:    a.challenge,
		PostConsentEndpoint: viper.GetString("consent_page"),
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
	rememberFor := int64(viper.GetInt("login_remember_for"))

	util.DebugModule(
		global.DbgHydra,
		global.LogKeyGUID, a.guid,
		"accepted_scopes", fmt.Sprintf("%+v", acceptedScopes),
	)

	needClaims := false

	for index := range acceptedScopes {
		if acceptedScopes[index] != global.ScopeOpenId {
			continue
		}

		needClaims = true

		break
	}

	if needClaims {
		util.DebugModule(
			global.DbgHydra,
			global.LogKeyGUID, a.guid,
			global.LogKeyMsg, "Scope 'openid' found, need claims",
		)

		session = getClaimsFromConsentContext(a.guid, acceptedScopes, consentContext)
	}

	acceptConsentRequest := a.apiClient.OAuth2API.AcceptOAuth2ConsentRequest(a.ctx).AcceptOAuth2ConsentRequest(
		openapi.AcceptOAuth2ConsentRequest{
			GrantAccessTokenAudience: a.consentRequest.GetRequestedAccessTokenAudience(),
			GrantScope:               acceptedScopes,
			Remember: func() *bool {
				if config.GetSkipConsent(*a.clientId) {
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
		handleHydraErr(a.ctx, err, httpResponse)

		return
	}

	a.ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

	a.logInfoRedirectWithConsent(acceptRequest.GetRedirectTo())
}

// logInfoConsent logs information about the consent request.
func (a *ApiConfig) logInfoConsent() {
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, a.guid,
		global.LogKeySkip, false,
		global.LogKeyClientID, *a.clientId,
		global.LogKeyClientName, a.clientName,
		global.LogKeyAuthSubject, a.consentRequest.GetSubject(),
		global.LogKeyAuthChallenge, a.challenge,
		global.LogKeyUriPath, viper.GetString("consent_page"),
	)
}

// logInfoRedirectWithConsent logs an info level message with the given parameters
// to the default logger.
func (a *ApiConfig) logInfoRedirectWithConsent(redirectTo string) {
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, a.guid,
		global.LogKeySkip, true,
		global.LogKeyClientID, *a.clientId,
		global.LogKeyClientName, a.clientName,
		global.LogKeyAuthSubject, a.consentRequest.GetSubject(),
		global.LogKeyAuthChallenge, a.challenge,
		global.LogKeyAuthStatus, global.LogKeyAuthAccept,
		global.LogKeyUriPath, viper.GetString("consent_page"),
		global.LogKeyRedirectTo, redirectTo,
	)
}

// Page '/consent'
func consentGETHandler(ctx *gin.Context) {
	var (
		err          error
		httpResponse *http.Response
	)

	consentChallenge := ctx.Query("consent_challenge")
	if consentChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx}

	apiConfig.initialize()

	apiConfig.challenge = consentChallenge
	apiConfig.csrfToken = ctx.GetString(global.CtxCSRFTokenKey)

	apiConfig.consentRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2ConsentRequest(ctx).ConsentChallenge(
		apiConfig.challenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	oauth2Client := apiConfig.consentRequest.GetClient()

	clientIdFound := false
	if apiConfig.clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		handleErr(ctx, errors2.ErrHydraNoClientId)

		return
	}

	apiConfig.clientName = oauth2Client.GetClientName()

	util.DebugModule(
		global.DbgHydra,
		global.LogKeyGUID, apiConfig.guid,
		"skip_hydra", fmt.Sprintf("%v", apiConfig.consentRequest.GetSkip()),
		"skip_config", fmt.Sprintf("%v", config.GetSkipConsent(*apiConfig.clientId)),
	)

	apiConfig.HandleConsentSkip()
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

	util.DebugModule(
		global.DbgHydra,
		global.LogKeyGUID, a.guid,
		"accepted_scopes", fmt.Sprintf("%+v", acceptedScopes),
	)

	needClaims := false

	for index := range acceptedScopes {
		if acceptedScopes[index] != global.ScopeOpenId {
			continue
		}

		needClaims = true

		break
	}

	if needClaims {
		util.DebugModule(global.DbgHydra, global.LogKeyGUID, a.guid, global.LogKeyMsg, "Scope 'openid' found, need claims")

		session = getClaimsFromConsentContext(a.guid, acceptedScopes, consentContext)
	}

	rememberFor := int64(viper.GetInt("login_remember_for"))
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
		handleHydraErr(a.ctx, err, httpResponse)

		return
	}

	a.ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

	a.logInfoConsentAccept(acceptRequest.GetRedirectTo())
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
//   - global.PasswordFail: A constant for the password failure message.
//
// Dependencies:
// - handleHydraErr function
// - global.PasswordFail constant
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
		handleHydraErr(a.ctx, err, httpResponse)

		return
	}

	if redirectTo, isSet = rejectRequest.GetRedirectToOk(); isSet {
		a.ctx.Redirect(http.StatusFound, *redirectTo)
	} else {
		redirectToValue := "unknown"
		redirectTo = &redirectToValue

		a.ctx.String(http.StatusForbidden, global.PasswordFail)
	}

	a.logInfoConsentReject(redirectTo)
}

// logInfoConsentAccept logs an info level log message for accepting the consent and redirects to the specified URL.
func (a *ApiConfig) logInfoConsentAccept(redirectTo string) {
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, a.guid,
		global.LogKeyClientID, *a.clientId,
		global.LogKeyClientName, a.clientName,
		global.LogKeyAuthSubject, a.consentRequest.GetSubject(),
		global.LogKeyAuthChallenge, a.challenge,
		global.LogKeyAuthStatus, global.LogKeyAuthAccept,
		global.LogKeyUriPath, viper.GetString("consent_page")+"/post",
		global.LogKeyRedirectTo, redirectTo,
	)
}

// logInfoConsentReject logs the information about a rejected consent request.
func (a *ApiConfig) logInfoConsentReject(redirectTo *string) {
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, a.guid,
		global.LogKeyClientID, *a.clientId,
		global.LogKeyClientName, a.clientName,
		global.LogKeyAuthSubject, a.consentRequest.GetSubject(),
		global.LogKeyAuthChallenge, a.challenge,
		global.LogKeyAuthStatus, global.LogKeyAuthReject,
		global.LogKeyUriPath, viper.GetString("consent_page")+"/post",
		global.LogKeyRedirectTo, *redirectTo,
	)
}

// Page '/consent/post'
func consentPOSTHandler(ctx *gin.Context) {
	var (
		err          error
		httpResponse *http.Response
	)

	consentChallenge := ctx.PostForm("ory.hydra.consent_challenge")
	if consentChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx}

	apiConfig.initialize()

	apiConfig.challenge = consentChallenge

	apiConfig.consentRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2ConsentRequest(ctx).ConsentChallenge(
		apiConfig.challenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	oauth2Client := apiConfig.consentRequest.GetClient()

	clientIdFound := false
	if apiConfig.clientId, clientIdFound = oauth2Client.GetClientIdOk(); !clientIdFound {
		handleErr(ctx, errors2.ErrHydraNoClientId)

		return
	}

	apiConfig.clientName = oauth2Client.GetClientName()

	apiConfig.handleConsentSubmit()
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
	cookieValue := session.Get(global.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(a.ctx, viper.GetString("logout_page"), config.DefaultLanguageTags, languageCurrentName)

	logoutData := &LogoutPageData{
		Title: getLocalized(a.ctx, "Logout"),
		WantWelcome: func() bool {
			if viper.GetString("login_page_welcome") != "" {
				return true
			}

			return false
		}(),
		Welcome:             viper.GetString("logout_page_welcome"),
		LogoutMessage:       getLocalized(a.ctx, "Do you really want to log out?"),
		AcceptSubmit:        getLocalized(a.ctx, "Yes"),
		RejectSubmit:        getLocalized(a.ctx, "No"),
		LanguageTag:         session.Get(global.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           a.csrfToken,
		LogoutChallenge:     a.challenge,
		PostLogoutEndpoint:  viper.GetString("logout_page"),
	}

	a.ctx.HTML(http.StatusOK, "logout.html", logoutData)

	a.logInfoLogout()
}

// logInfoLogout logs information about a logout action.
func (a *ApiConfig) logInfoLogout() {
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, a.guid,
		global.LogKeyAuthSubject, a.logoutRequest.GetSubject(),
		global.LogKeyAuthChallenge, a.challenge,
		global.LogKeyUriPath, viper.GetString("logout_page"),
	)
}

// Page '/logout'
func logoutGETHandler(ctx *gin.Context) {
	var (
		err          error
		httpResponse *http.Response
	)

	logoutChallenge := ctx.Query("logout_challenge")
	if logoutChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
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

	apiConfig := ApiConfig{ctx: ctx}

	apiConfig.initialize()

	apiConfig.challenge = logoutChallenge
	apiConfig.csrfToken = ctx.GetString(global.CtxCSRFTokenKey)

	apiConfig.logoutRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2LogoutRequest(ctx).LogoutChallenge(
		logoutChallenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	if apiConfig.logoutRequest.GetRpInitiated() {
		// We could skip the UI
		util.DebugModule(global.DbgHydra, global.LogKeyGUID, apiConfig.guid, global.LogKeyMsg, "rp_initiated==true")
	}

	apiConfig.handleLogout()
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
		handleHydraErr(a.ctx, err, httpResponse)

		return
	}

	a.ctx.Redirect(http.StatusFound, acceptRequest.GetRedirectTo())

	a.logInfoLogoutAccept(acceptRequest.GetRedirectTo())
}

// rejectLogout rejects the logout request by sending a request to the OAuth2API endpoint of the API client.
// If the request is successful, it redirects the user to the specified homepage or aborts the request with a status of 200 OK.
// If the request encounters an error, it handles the error and returns.
func (a *ApiConfig) rejectLogout() {
	rejectLogoutRequest := a.apiClient.OAuth2API.RejectOAuth2LogoutRequest(a.ctx)

	httpResponse, err := rejectLogoutRequest.LogoutChallenge(a.challenge).Execute()
	if err != nil {
		handleHydraErr(a.ctx, err, httpResponse)

		return
	}

	redirectTo := viper.GetString("homepage")
	if redirectTo != "" {
		a.ctx.Redirect(http.StatusFound, redirectTo)
	} else {
		redirectTo = "unknown"
		a.ctx.AbortWithStatus(http.StatusOK)
	}

	a.logInfoLogoutReject(redirectTo)
}

// logInfoLogoutAccept logs information about the logout request acceptance.
func (a *ApiConfig) logInfoLogoutAccept(redirectTo string) {
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, a.guid,
		global.LogKeyAuthSubject, a.logoutRequest.GetSubject(),
		global.LogKeyAuthChallenge, a.challenge,
		global.LogKeyAuthStatus, global.LogKeyAuthAccept,
		global.LogKeyUriPath, viper.GetString("logout_page")+"/post",
		global.LogKeyRedirectTo, redirectTo,
	)
}

// logInfoLogoutReject logs an info-level message indicating a rejected logout attempt.
func (a *ApiConfig) logInfoLogoutReject(redirectTo string) {
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyGUID, a.guid,
		global.LogKeyAuthSubject, a.logoutRequest.GetSubject(),
		global.LogKeyAuthChallenge, a.challenge,
		global.LogKeyAuthStatus, global.LogKeyAuthReject,
		global.LogKeyUriPath, viper.GetString("logout_page")+"/post",
		global.LogKeyRedirectTo, redirectTo,
	)
}

// Page '/logout/post'
func logoutPOSTHandler(ctx *gin.Context) {
	var (
		err          error
		httpResponse *http.Response
	)

	logoutChallenge := ctx.PostForm("ory.hydra.logout_challenge")
	if logoutChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	apiConfig := &ApiConfig{ctx: ctx}

	apiConfig.initialize()

	apiConfig.challenge = logoutChallenge

	apiConfig.logoutRequest, httpResponse, err = apiConfig.apiClient.OAuth2API.GetOAuth2LogoutRequest(ctx).LogoutChallenge(
		apiConfig.challenge).Execute()
	if err != nil {
		handleHydraErr(ctx, err, httpResponse)

		return
	}

	apiConfig.handleLogoutSubmit()
}

// getClaimsFromConsentContext extracts claims from consentContext based on acceptedScopes
func getClaimsFromConsentContext(guid string, acceptedScopes []string, consentContext any) (
	session *openapi.AcceptOAuth2ConsentRequestSession,
) {
	claimDict, assertOk := consentContext.(map[string]any)
	if !assertOk {
		return nil
	}

	claims := make(map[string]any)
	for index, scope := range acceptedScopes {
		switch scope {
		case global.ScopeProfile:
			processProfileClaim(claimDict, claims)
		case global.ScopeEmail:
			processEmailClaim(claimDict, claims)
		case global.ScopeAddress:
			processAddressClaim(claimDict, claims)
		case global.ScopePhone:
			processPhoneClaim(claimDict, claims)
		case global.ScopeGroups:
			processGroupsClaim(claimDict, claims)
		}

		processCustomScopes(claimDict, claims, acceptedScopes, index)
	}

	util.DebugModule(global.DbgHydra, global.LogKeyGUID, guid, "claims", fmt.Sprintf("%+v", claims))

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
		global.ClaimName, global.ClaimGivenName, global.ClaimFamilyName, global.ClaimMiddleName, global.ClaimNickName,
		global.ClaimPreferredUserName, global.ClaimProfile, global.ClaimWebsite, global.ClaimPicture, global.ClaimGender,
		global.ClaimBirtDate, global.ClaimZoneInfo, global.ClaimLocale,
	}

	for _, key := range profileClaims {
		if value, found := claimDict[key]; found {
			claims[key] = value
		}
	}

	if value, found := claimDict[global.ClaimUpdatedAt].(float64); found {
		claims[global.ClaimUpdatedAt] = value
	}
}

// processEmailClaim updates the claims map with the email and email_verified claims
func processEmailClaim(claimDict map[string]any, claims map[string]any) {
	keys := []string{global.ClaimEmail, global.ClaimEmailVerified}
	for _, key := range keys {
		if value, found := claimDict[key]; found {
			claims[key] = value
		}
	}
}

// processAddressClaim updates the claims map with the address claim from the claimDict.
// The address claim is stored under the key "address".
func processAddressClaim(claimDict map[string]any, claims map[string]any) {
	claims[global.ClaimAddress] = claimDict[global.ClaimAddress]
}

// processPhoneClaim processes the phone claims from the claim dictionary and adds them to the claims map.
func processPhoneClaim(claimDict map[string]any, claims map[string]any) {
	keys := []string{global.ClaimPhoneNumber, global.ClaimPhoneNumberVerified}
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
	if value, found := claimDict[global.ClaimGroups].([]any); found {
		var stringSlice []string

		for anyIndex := range value {
			if arg, assertOk := value[anyIndex].(string); assertOk {
				stringSlice = append(stringSlice, arg)
			}
		}

		claims[global.ClaimGroups] = value
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
func processCustomScopes(claimDict map[string]any, claims map[string]any, acceptedScopes []string, index int) {
	for scopeIndex := range config.LoadableConfig.Oauth2.CustomScopes {
		customScope := config.LoadableConfig.Oauth2.CustomScopes[scopeIndex]

		if acceptedScopes[index] != customScope.Name {
			continue
		}

		for claimIndex := range customScope.Claims {
			customClaim := customScope.Claims[claimIndex]
			claims = processCustomClaim(claimDict, customClaim, claims)
		}

		break
	}
}

// Extracted method for processing custom claim type
func processCustomClaim(claimDict map[string]any, customClaim config.OIDCCustomClaim, claims map[string]any) map[string]any {
	customClaimName := customClaim.Name
	customClaimType := customClaim.Type
	valueTypeMatch := false

	valueTypeMatch, claims = assignClaimValueByType(claimDict, customClaimName, customClaimType, claims)

	if !valueTypeMatch {
		logUnknownClaimTypeError(customClaimName, customClaimType)
	}

	return claims
}

// Assigns claim type-specific value and returns updated claims' map
func assignClaimValueByType(claimDict map[string]any, customClaimName string, customClaimType string, claims map[string]any) (bool, map[string]any) {
	valueTypeMatch := false

	switch customClaimType {
	case global.ClaimTypeString:
		if value, found := claimDict[customClaimName].(string); found {
			claims[customClaimName] = value
			valueTypeMatch = true
		}
	case global.ClaimTypeFloat:
		if value, found := claimDict[customClaimName].(float64); found {
			claims[customClaimName] = value
			valueTypeMatch = true
		}
	case global.ClaimTypeInteger:
		if value, found := handleIntegerClaimType(claimDict, customClaimName); found {
			claims[customClaimName] = value
			valueTypeMatch = true
		}
	case global.ClaimTypeBoolean:
		if value, found := claimDict[customClaimName].(bool); found {
			claims[customClaimName] = value
			valueTypeMatch = true
		}
	}

	return valueTypeMatch, claims
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
func logUnknownClaimTypeError(customClaimName string, customClaimType string) {
	level.Error(logging.DefaultErrLogger).Log(
		"custom_claim_name", customClaimName,
		global.LogKeyError, fmt.Sprintf("Unknown type '%s'", customClaimType),
	)
}
