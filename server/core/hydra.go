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

// Scope represents a scope used in the ConsentPageData struct. It contains the name and description of the scope.
type Scope struct {
	ScopeName        string
	ScopeDescription string
}

// Language represents a language used in various page data structs.
type Language struct {
	LanguageLink string
	LanguageName string
}

type LoginPageData struct {
	// Determines if the Welcome message should be displayed
	WantWelcome bool

	// Determines if the Policy should be displayed
	WantPolicy bool

	// Determines if the Terms of Service (TOS) should be displayed
	WantTos bool

	// Determines if the About information should be displayed
	WantAbout bool

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

type ApiConfig struct {
	httpClient   *http.Client
	apiClient    *openapi.APIClient
	ctx          *gin.Context
	loginRequest *openapi.OAuth2LoginRequest
	clientId     *string
	guid         string
	csrfToken    string
	clientName   string
	challenge    string
}

// handleErr handles an error by logging the error details and printing a goroutine dump.
// It sets the "failure" and "message" values in the context, and then calls the notifyGETHandler function.
// If the error is of type *errors2.DetailedError, it logs the error details along with the error message.
// Otherwise, it logs only the error message.
// The function also prints the goroutine dump with the corresponding GUID.
// Finally, it cleans up the session using the SessionCleaner function.
//
// ctx: The Gin context.
// err: The error to handle.
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

	fmt.Printf("=== guid=%s\n*** goroutine dump...\n%s\n*** end\n", guid, buf[:stackLen])

	SessionCleaner(ctx)

	ctx.Set("failure", true)
	ctx.Set("message", err)

	notifyGETHandler(ctx)
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
	cookieValue := session.Get(decl.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(ctx, config.DefaultLanguageTags, languageCurrentName)

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

// getLocalized is a function that returns the localized message based on the message ID and the context provided.
// If the localization fails, an error is logged.
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

		guid := ctx.Value(decl.GUIDKey).(string)

		// Try to get language tag from URL
		langFromURL = ctx.Param("languageTag")

		// Try to get language tag from cookie
		session := sessions.Default(ctx)

		cookieValue := session.Get(decl.CookieLang)
		if cookieValue != nil {
			langFromCookie, _ = cookieValue.(string)
		}

		lang, needCookie, needRedirect := setLanguageDetails(langFromURL, langFromCookie)
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

// createHttpClient creates an HTTP client with a custom configuration.
// The client uses an http.Transport with a custom *tls.Config, which allows skipping TLS verification
// based on the value of the "http_client_skip_tls_verify" configuration.
// The client also has a Timeout of 30 seconds.
// Returns the created http.Client.
func createHttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("http_client_skip_tls_verify")}},
		Timeout:   30 * time.Second,
	}
}

// createConfiguration returns a new instance of the openapi.Configuration struct with the provided httpClient and server configuration.
// The httpClient parameter is used as the underlying HTTP client for API calls made by the openapi.client.
// The server configuration is read from the "hydra_admin_uri" configuration value using viper.GetString() function.
func createConfiguration(httpClient *http.Client) *openapi.Configuration {
	return &openapi.Configuration{
		HTTPClient: httpClient,
		Servers:    []openapi.ServerConfiguration{{URL: viper.GetString("hydra_admin_uri")}},
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
func createLanguagePassive(ctx *gin.Context, languageTags []language.Tag, currentName string) []Language {
	var languagePassive []Language

	for _, languageTag := range languageTags {
		languageName := cases.Title(languageTag, cases.NoLower).String(display.Self.Name(languageTag))
		if languageName != currentName {
			baseName, _ := languageTag.Base()
			languagePassive = append(
				languagePassive,
				Language{
					LanguageLink: viper.GetString("login_page") + "/" + baseName.String() + "?" + ctx.Request.URL.RawQuery,
					LanguageName: languageName,
				},
			)
		}
	}

	return languagePassive
}

// Initialize sets up the `ApiConfig` object by initializing the HTTP client, GUID, and API client.
// Must be called before using any other methods on `ApiConfig`.
//
// Example usage:
//
//	apiConfig := &ApiConfig{ctx: ctx}
//	apiConfig.Initialize()
//
//	// Use the initialized `ApiConfig` object
//	apiConfig.HandleLogin(apiConfig.loginRequest.GetSkip())
//
// Dependencies:
// - `createHttpClient` function
// - `createConfiguration` function
//
// Note: This method assumes that the `ApiConfig` object is properly initialized with the `ctx` field set.
func (a *ApiConfig) Initialize() {
	a.httpClient = createHttpClient()
	a.guid = a.ctx.Value(decl.GUIDKey).(string)
	configuration := createConfiguration(a.httpClient)
	a.apiClient = openapi.NewAPIClient(configuration)
}

// HandleLogin handles the login process based on the value of `skip`.
//
// If `skip` is true, it calls the `handleLoginSkip` method.
// If `skip` is false, it calls the `handleLoginNoSkip` method.
//
// Example usage:
//
//	apiConfig := &ApiConfig{ctx: ctx}
//	apiConfig.Initialize()
//	apiConfig.HandleLogin(apiConfig.loginRequest.GetSkip())
//
// Dependencies:
// - `handleLoginSkip` method
// - `handleLoginNoSkip` method
func (a *ApiConfig) HandleLogin(skip bool) {
	util.DebugModule(decl.DbgHydra, decl.LogKeyGUID, a.guid, decl.LogKeyMsg, fmt.Sprintf("%s is %v", decl.LogKeyLoginSkip, skip))

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

	util.DebugModule(decl.DbgHydra, decl.LogKeyGUID, a.guid, decl.LogKeyMsg, fmt.Sprintf("%s is %v", decl.LogKeyLoginSkip, true))

	oauth2Client := a.loginRequest.GetClient()

	auth := &Authentication{
		HTTPClientContext: a.ctx,
		NoAuth:            true,
		Protocol:          config.NewProtocol(decl.ProtoOryHydra),
	}

	auth.WithDefaults(a.ctx).WithClientInfo(a.ctx).WithLocalInfo(a.ctx).WithUserAgent(a.ctx).WithXSSL(a.ctx)

	auth.Username = a.loginRequest.GetSubject()
	auth.UsernameOrig = a.loginRequest.GetSubject()

	if err := auth.SetStatusCode(decl.ServOryHydra); err != nil {
		handleErr(a.ctx, err)

		return
	}

	if authStatus := auth.HandlePassword(a.ctx); authStatus == decl.AuthResultOK {
		if config.LoadableConfig.Oauth2 != nil {
			_, claims = auth.GetOauth2SubjectAndClaims(oauth2Client)
		}
	} else {
		auth.ClientIP = a.ctx.Value(decl.ClientIPKey).(string)

		auth.UpdateBruteForceBucketsCounter()
		a.ctx.AbortWithError(http.StatusInternalServerError, errors2.ErrUnknownCause)

		return
	}

	acceptLoginRequest := a.apiClient.OAuth2Api.AcceptOAuth2LoginRequest(a.ctx).AcceptOAuth2LoginRequest(
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

	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyGUID, a.guid,
		decl.LogKeySkip, true,
		decl.LogKeyClientID, *a.clientId,
		decl.LogKeyClientName, a.clientName,
		decl.LogKeyAuthSubject, a.loginRequest.GetSubject(),
		decl.LogKeyAuthChallenge, a.challenge,
		decl.LogKeyAuthStatus, decl.LogKeyAuthAccept,
		decl.LogKeyUriPath, viper.GetString("login_page"),
		decl.LogKeyRedirectTo, acceptRequest.GetRedirectTo(),
	)
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

	util.DebugModule(decl.DbgHydra, decl.LogKeyGUID, a.guid, decl.LogKeyMsg, fmt.Sprintf("%s is %v", decl.LogKeyLoginSkip, false))

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

	cookieValue := session.Get(decl.CookieLang)

	languageCurrentTag := language.MustParse(cookieValue.(string))
	languageCurrentName := cases.Title(languageCurrentTag, cases.NoLower).String(display.Self.Name(languageCurrentTag))
	languagePassive := createLanguagePassive(a.ctx, config.DefaultLanguageTags, languageCurrentName)

	userData := createUserdata(session, decl.CookieUsername, decl.CookieAuthResult)

	// Handle TOTP request
	if authResult, found := userData[decl.CookieAuthResult]; found {
		if authResult != decl.AuthResultUnset {
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
				LanguageTag:         session.Get(decl.CookieLang).(string),
				LanguageCurrentName: languageCurrentName,
				LanguagePassive:     languagePassive,
				CSRFToken:           a.csrfToken,
				LoginChallenge:      a.challenge,
			}

			a.ctx.HTML(http.StatusOK, "totp.html", twoFactorData)

			util.DebugModule(
				decl.DbgHydra,
				decl.LogKeyGUID, a.guid,
				decl.LogKeyMsg, "Two factor authentication",
				decl.LogKeyUsername, userData[decl.CookieUsername].(string),
			)

			return
		}
	}

	if errorMessage = a.ctx.Query("_error"); errorMessage != "" {
		if errorMessage == decl.PasswordFail {
			errorMessage = getLocalized(a.ctx, decl.PasswordFail)
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
		LanguageTag:         session.Get(decl.CookieLang).(string),
		LanguageCurrentName: languageCurrentName,
		LanguagePassive:     languagePassive,
		CSRFToken:           a.csrfToken,
		LoginChallenge:      a.challenge,
	}

	a.ctx.HTML(http.StatusOK, "login.html", loginData)

	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyGUID, a.guid,
		decl.LogKeySkip, false,
		decl.LogKeyClientID, *a.clientId,
		decl.LogKeyClientName, a.clientName,
		decl.LogKeyAuthChallenge, a.challenge,
		decl.LogKeyUriPath, viper.GetString("login_page"),
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

	apiConfig.Initialize()

	apiConfig.challenge = loginChallenge
	apiConfig.csrfToken = ctx.Value(decl.CSRFTokenKey).(string)

	apiConfig.loginRequest, httpResponse, err = apiConfig.apiClient.OAuth2Api.GetOAuth2LoginRequest(ctx).LoginChallenge(
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

	apiConfig.HandleLogin(apiConfig.loginRequest.GetSkip())
}

// initializeAuthLogin initializes the Authentication struct with the necessary information for logging in.
func initializeAuthLogin(ctx *gin.Context) (*Authentication, error) {
	auth := &Authentication{
		HTTPClientContext: ctx,
		Username:          ctx.PostForm("username"),
		Password:          ctx.PostForm("password"),
		Protocol:          config.NewProtocol(decl.ProtoOryHydra),
	}

	if err := auth.SetStatusCode(decl.ServOryHydra); err != nil {
		return nil, err
	}

	return auth.WithDefaults(ctx).WithClientInfo(ctx).WithLocalInfo(ctx).WithUserAgent(ctx).WithXSSL(ctx), nil
}

// handleSessionDataLogin retrieves session data related to the login process and populates the provided `auth` variable with the values.
//
// Parameters:
// - ctx: The gin context object.
// - auth: Pointer to an Authentication struct to populate with retrieved values.
//
// Returns:
// - authResult: The result of the authentication process (decl.AuthResult enum).
// - recentSubject: The recently used subject value.
// - rememberPost2FA: The remember value after the second factor authentication.
// - post2FA: A bool indicating if a second factor authentication is required.
// - err: An error object if saving the session failed, or nil otherwise.
func handleSessionDataLogin(ctx *gin.Context, auth *Authentication) (
	authResult decl.AuthResult, recentSubject string, rememberPost2FA string, post2FA bool, err error,
) {
	var cookieValue any

	session := sessions.Default(ctx)

	// Restore authentication data from first call to login.html
	if cookieValue = session.Get(decl.CookieUsername); cookieValue != nil {
		if cookieValue.(string) != "" {
			auth.Username = cookieValue.(string)
			auth.NoAuth = true
		}

		session.Delete(decl.CookieUsername)
	}

	if cookieValue = session.Get(decl.CookieAuthResult); cookieValue != nil {
		authResult = decl.AuthResult(cookieValue.(uint8))
		if authResult != decl.AuthResultUnset {
			post2FA = true
		}

		session.Delete(decl.CookieAuthResult)
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
func (a *ApiConfig) processAuthOkLogin(auth *Authentication, authResult decl.AuthResult, rememberPost2FA string, recentSubject string, post2FA bool) error {
	var (
		redirectFlag bool
		redirectTo   string
		err          error
	)

	account, found := auth.GetAccountOk()
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

	a.logInfo(subject, redirectTo)

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
		subject, claims = auth.GetOauth2SubjectAndClaims(oauth2Client)
	}

	if subject == "" {
		subject = account

		level.Warn(logging.DefaultLogger).Log(
			decl.LogKeyGUID, a.guid,
			decl.LogKeyMsg, fmt.Sprintf("Empty 'subject', using '%s' as value", account),
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
func (a *ApiConfig) handleNonPost2FA(auth *Authentication, session sessions.Session, authResult decl.AuthResult, subject string) (bool, error) {
	if config.GetSkipTOTP(*a.clientId) {
		return false, nil
	}

	if _, found := auth.GetTOTPSecretOk(); found {
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

	totpSecret, found := auth.GetTOTPSecretOk()
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
	acceptLoginRequest := a.apiClient.OAuth2Api.AcceptOAuth2LoginRequest(a.ctx).AcceptOAuth2LoginRequest(
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

// logInfo logs the information for an authentication event with the given subject and redirect URL.
// It uses the DefaultLogger from the logging package.
//
// Parameters:
// - subject: The authentication subject
// - redirectTo: The URL to redirect to after authentication
//
// Example usage:
// apiConfig.logInfo("john_doe", "/dashboard")
//
// Dependencies:
// - DefaultLogger from the logging package
//
// Note: This method assumes that the ApiConfig object is properly initialized with the relevant fields.
func (a *ApiConfig) logInfo(subject string, redirectTo string) {
	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyGUID, a.guid,
		decl.LogKeyClientID, *a.clientId,
		decl.LogKeyClientName, a.clientName,
		decl.LogKeyAuthSubject, subject,
		decl.LogKeyAuthChallenge, a.challenge,
		decl.LogKeyUsername, a.ctx.PostForm("username"),
		decl.LogKeyAuthStatus, decl.LogKeyAuthAccept,
		decl.LogKeyUriPath, viper.GetString("login_page")+"/post",
		decl.LogKeyRedirectTo, redirectTo,
	)
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

	if config.EnvConfig.Verbosity.Level() >= decl.LogLevelDebug && config.EnvConfig.DevMode {
		util.DebugModule(
			decl.DbgHydra,
			decl.LogKeyGUID, a.guid,
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
// It takes a `sessions.Session` object, `authResult` of type `decl.AuthResult`, and the `subject` string as parameters.
// It sets the following session variables:
// - `decl.CookieAuthResult`: uint8 value of `authResult`
// - `decl.CookieUsername`: value of `username` field from the request form
// - `decl.CookieSubject`: value of `subject`
// - `decl.CookieRemember`: value of `remember` field from the request form
// It returns an `error` if there is any error saving the session.
//
// Example usage:
//
//	session := sessions.Default(ctx)
//	err := setSessionVariablesForAuth(session, authResult, subject)
//	if err != nil {
//	    // Handle error
//	}
func (a *ApiConfig) setSessionVariablesForAuth(session sessions.Session, authResult decl.AuthResult, subject string) error {
	session.Set(decl.CookieAuthResult, uint8(authResult))
	session.Set(decl.CookieUsername, a.ctx.Request.Form.Get("username"))
	session.Set(decl.CookieSubject, subject)
	session.Set(decl.CookieRemember, a.ctx.Request.Form.Get("remember"))

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
// - auth.GetTOTPSecretOk(): method to get the TOTP secret for the authentication
//
// Note: This method assumes that the ApiConfig object is properly initialized with the ctx field set.
func (a *ApiConfig) processAuthFailLogin(auth *Authentication, authResult decl.AuthResult, post2FA bool) (err error) {
	session := sessions.Default(a.ctx)

	if !post2FA {
		if !config.GetSkipTOTP(*a.clientId) {
			if _, found := auth.GetTOTPSecretOk(); found {
				session.Set(decl.CookieAuthResult, uint8(authResult))
				session.Set(decl.CookieUsername, a.ctx.Request.Form.Get("username"))

				session.Save()
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
	auth.ClientIP = a.ctx.Value(decl.ClientIPKey).(string)

	auth.UpdateBruteForceBucketsCounter()

	a.ctx.Redirect(
		http.StatusFound,
		viper.GetString("login_page")+"?login_challenge="+loginChallenge+"&_error="+decl.PasswordFail,
	)

	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyGUID, a.guid,
		decl.LogKeyClientID, *a.clientId,
		decl.LogKeyClientName, a.clientName,
		decl.LogKeyAuthChallenge, loginChallenge,
		decl.LogKeyUsername, a.ctx.PostForm("username"),
		decl.LogKeyAuthStatus, decl.LogKeyAuthReject,
		decl.LogKeyUriPath, viper.GetString("login_page")+"/post",
	)
}

// Page '/login/post'
func loginPOSTHandler(ctx *gin.Context) {
	var (
		post2FA         bool
		authResult      decl.AuthResult
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

	apiConfig.Initialize()

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

	apiConfig.loginRequest, httpResponse, err = apiConfig.apiClient.OAuth2Api.GetOAuth2LoginRequest(ctx).LoginChallenge(
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

	if authResult == decl.AuthResultUnset || authResult == decl.AuthResultOK {
		authResult = auth.HandlePassword(ctx)
	}

	switch authResult {
	case decl.AuthResultOK:
		err = apiConfig.processAuthOkLogin(auth, authResult, rememberPost2FA, recentSubject, post2FA)
		if err != nil {
			handleErr(ctx, err)
		}

		return
	case decl.AuthResultFail, decl.AuthResultEmptyUsername, decl.AuthResultEmptyPassword:
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
		guid         = ctx.Value(decl.GUIDKey).(string)
		csrfToken    = ctx.Value(decl.CSRFTokenKey).(string)
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
	languagePassive := createLanguagePassive(ctx, config.DefaultLanguageTags, languageCurrentName)

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
		wantAbout      bool
		wantPolicy     bool
		wantTos        bool
		skipConsent    bool
		policyUri      string
		tosUri         string
		clientUri      string
		imageUri       string
		err            error
		clientId       *string
		guid           = ctx.Value(decl.GUIDKey).(string)
		csrfToken      = ctx.Value(decl.CSRFTokenKey).(string)
		consentRequest *openapi.OAuth2ConsentRequest
		acceptRequest  *openapi.OAuth2RedirectTo
		httpResponse   *http.Response
	)

	consentChallenge := ctx.Query("consent_challenge")
	if consentChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	httpClient := createHttpClient()
	configuration := createConfiguration(httpClient)
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
		languagePassive := createLanguagePassive(ctx, config.DefaultLanguageTags, languageCurrentName)

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

	consentChallenge := ctx.PostForm("ory.hydra.consent_challenge")
	if consentChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	httpClient := createHttpClient()
	configuration := createConfiguration(httpClient)
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
		err           error
		guid          = ctx.Value(decl.GUIDKey).(string)
		csrfToken     = ctx.Value(decl.CSRFTokenKey).(string)
		logoutRequest *openapi.OAuth2LogoutRequest
		httpResponse  *http.Response
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

	httpClient := createHttpClient()
	configuration := createConfiguration(httpClient)
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
	languagePassive := createLanguagePassive(ctx, config.DefaultLanguageTags, languageCurrentName)

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

	logoutChallenge := ctx.PostForm("ory.hydra.logout_challenge")
	if logoutChallenge == "" {
		handleErr(ctx, errors2.ErrNoLoginChallenge)

		return
	}

	httpClient := createHttpClient()
	configuration := createConfiguration(httpClient)
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
		case decl.ScopeProfile:
			processProfileClaim(claimDict, claims)
		case decl.ScopeEmail:
			processEmailClaim(claimDict, claims)
		case decl.ScopeAddress:
			processAddressClaim(claimDict, claims)
		case decl.ScopePhone:
			processPhoneClaim(claimDict, claims)
		case decl.ScopeGroups:
			processGroupsClaim(claimDict, claims)
		}

		processCustomScopes(claimDict, claims, acceptedScopes, index)
	}

	util.DebugModule(decl.DbgHydra, decl.LogKeyGUID, guid, "claims", fmt.Sprintf("%+v", claims))

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
		decl.ClaimName, decl.ClaimGivenName, decl.ClaimFamilyName, decl.ClaimMiddleName, decl.ClaimNickName,
		decl.ClaimPreferredUserName, decl.ClaimProfile, decl.ClaimWebsite, decl.ClaimPicture, decl.ClaimGender,
		decl.ClaimBirtDate, decl.ClaimZoneInfo, decl.ClaimLocale,
	}

	for _, key := range profileClaims {
		if value, found := claimDict[key]; found {
			claims[key] = value
		}
	}

	if value, found := claimDict[decl.ClaimUpdatedAt].(float64); found {
		claims[decl.ClaimUpdatedAt] = value
	}
}

// processEmailClaim updates the claims map with the email and email_verified claims
func processEmailClaim(claimDict map[string]any, claims map[string]any) {
	keys := []string{decl.ClaimEmail, decl.ClaimEmailVerified}
	for _, key := range keys {
		if value, found := claimDict[key]; found {
			claims[key] = value
		}
	}
}

// processAddressClaim updates the claims map with the address claim from the claimDict.
// The address claim is stored under the key "address".
func processAddressClaim(claimDict map[string]any, claims map[string]any) {
	claims[decl.ClaimAddress] = claimDict[decl.ClaimAddress]
}

// processPhoneClaim processes the phone claims from the claim dictionary and adds them to the claims map.
func processPhoneClaim(claimDict map[string]any, claims map[string]any) {
	keys := []string{decl.ClaimPhoneNumber, decl.ClaimPhoneNumberVerified}
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
	case decl.ClaimTypeString:
		if value, found := claimDict[customClaimName].(string); found {
			claims[customClaimName] = value
			valueTypeMatch = true
		}
	case decl.ClaimTypeFloat:
		if value, found := claimDict[customClaimName].(float64); found {
			claims[customClaimName] = value
			valueTypeMatch = true
		}
	case decl.ClaimTypeInteger:
		if value, found := handleIntegerClaimType(claimDict, customClaimName); found {
			claims[customClaimName] = value
			valueTypeMatch = true
		}
	case decl.ClaimTypeBoolean:
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
		decl.LogKeyError, fmt.Sprintf("Unknown type '%s'", customClaimType),
	)
}
