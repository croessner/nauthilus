package core

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gwatts/gin-adapter"
	"github.com/justinas/nosurf"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/segmentio/ksuid"
	"github.com/spf13/viper"
)

var (
	HTTPEndChan chan Done    //nolint:gochecknoglobals // Quit-Channel for HTTP on shutdown
	LangBundle  *i18n.Bundle //nolint:gochecknoglobals // System wide i18n bundle
)

// RESTResult is a generic JSON result object for the Nauthilus REST API.
type RESTResult struct {
	GUID      string `json:"session"`
	Object    string `json:"object"`
	Operation string `json:"operation"`
	Result    any    `json:"result"`
}

//nolint:gocognit // Main logic
func httpQueryHandler(ctx *gin.Context) {
	if ctx.FullPath() == "/ping" {
		HealthCheck(ctx)
	} else {
		switch ctx.Param("category") {
		case decl.CatMail, decl.CatGeneric:
			auth := NewAuthentication(ctx)
			if auth == nil {
				ctx.AbortWithStatus(http.StatusBadRequest)

				return
			}

			if auth.CheckBruteForce() {
				auth.UpdateBruteForceBucketsCounter()
				auth.PostLuaAction(&PassDBResult{})
				auth.AuthFail(ctx)

				return
			}

			switch ctx.Param("service") {
			case decl.ServNginx, decl.ServDovecot, decl.ServUserInfo:
				auth.Generic(ctx)
			case decl.ServSaslauthd:
				auth.SASLauthd(ctx)
			default:
				ctx.AbortWithStatus(http.StatusNotFound)
			}

		case decl.CatHTTP:
			auth := NewAuthentication(ctx)
			if auth == nil {
				ctx.AbortWithStatus(http.StatusBadRequest)

				return
			}

			if auth.CheckBruteForce() {
				auth.UpdateBruteForceBucketsCounter()
				auth.PostLuaAction(&PassDBResult{})
				auth.AuthFail(ctx)

				return
			}

			switch ctx.Param("service") {
			case decl.ServBasicAuth:
				auth.Generic(ctx)
			default:
				ctx.AbortWithStatus(http.StatusNotFound)
			}

		case decl.CatBruteForce:
			switch ctx.Param("service") {
			case decl.ServList:
				ListBruteforce(ctx)
			default:
				ctx.AbortWithStatus(http.StatusNotFound)
			}

		default:
			ctx.AbortWithStatus(http.StatusNotFound)
		}
	}
}

func httpCacheHandler(ctx *gin.Context) {
	//nolint:gocritic // Prepared for future commands
	switch ctx.Param("category") {
	case decl.CatCache:
		switch ctx.Param("service") {
		case decl.ServFlush:
			FlushCache(ctx)
		}

	case decl.CatBruteForce:
		switch ctx.Param("service") {
		case decl.ServFlush:
			FlushBruteForceRule(ctx)
		}
	}
}

// `protectEndpointMiddleware` is a middleware function for Gin Web Framework that provides security features for an endpoint.
// It extracts the request's client information such as GUID, Client-IP, Protocol, and UserAgent from the context of the request.
// The function also checks for brute force attacks, and if detected, it updates the counter for brute force attempts and fails the authentication.
// Further, it handles security features such as TLS, Domain Relay, RBL, and Lua, and in case of their failure, it stops further execution of the request.
// This middleware function should be used in the setup of routing to ensure the security of the endpoint it is applied to.
func protectEndpointMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		guid := ctx.Value(decl.GUIDKey).(string) // MiddleWare behind Logger!

		protocol := &config.Protocol{}
		protocol.Set(decl.ProtoHTTP)

		clientIP := ctx.Request.Header.Get("Client-IP")
		clientPort := util.WithNotAvailable(ctx.Request.Header.Get("X-Client-Port"))
		method := "plain"

		auth := &Authentication{
			HTTPClientContext: ctx,
			NoAuth:            true,
			GUID:              &guid,
			Protocol:          protocol,
			Method:            &method,
		}

		auth.WithUserAgent(ctx)
		auth.WithXSSL(ctx)

		if clientIP == "" {
			clientIP, clientPort, _ = net.SplitHostPort(ctx.Request.RemoteAddr)
		}

		clientIP, clientPort = util.GetProxyAddress(ctx.Request, clientIP, clientPort)

		if clientIP == "" {
			clientIP = decl.NotAvailable
		}

		if clientPort == "" {
			clientPort = decl.NotAvailable
		}

		auth.ClientIP = clientIP
		auth.XClientPort = clientPort

		// Store remote client IP into connection context. It can be used for brute force updates.
		ctx.Set(decl.ClientIPKey, clientIP)

		if auth.CheckBruteForce() {
			auth.UpdateBruteForceBucketsCounter()
			auth.PostLuaAction(&PassDBResult{})
			auth.AuthFail(ctx)
			ctx.Abort()

			return
		}

		//nolint:exhaustive // Ignore some results
		switch auth.HandleFeatures(ctx) {
		case decl.AuthResultFeatureTLS:
			auth.PostLuaAction(&PassDBResult{})
			handleErr(ctx, errors2.ErrNoTLS)
			ctx.Abort()

			return
		case decl.AuthResultFeatureRelayDomain, decl.AuthResultFeatureRBL, decl.AuthResultFeatureLua:
			auth.PostLuaAction(&PassDBResult{})
			auth.AuthFail(ctx)
			ctx.Abort()

			return
		case decl.AuthResultUnset:
		case decl.AuthResultOK:
		case decl.AuthResultFail:
		case decl.AuthResultTempFail:
		case decl.AuthResultEmptyUsername:
		case decl.AuthResultEmptyPassword:
		}

		ctx.Next()
	}
}

// basicAuthMiddleware returns a gin middleware handler dedicated for performing HTTP Basic Authentication.
// It first checks for specified parameters in the incoming request context.
// If the request already contains BasicAuth in its header, it attempts to authenticate the credentials. Hashed values
// of the supplied username and password are compared in constant time against expected username and password hashes.
// If the credentials match, it allows the equest to proceed; else terminates the request with HTTP 403 Forbidden status.
// If BasicAuth wasn't provided in request, it asks the client to provide credentials responding with HTTP 401 Unauthorized,
// and inserts a WWW-Authenticate field into response header.
func basicAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		guid := ctx.Value(decl.GUIDKey).(string)

		// Note: Chicken-egg problem.
		if ctx.Param("category") == decl.CatHTTP && ctx.Param("service") == decl.ServBasicAuth {
			level.Warn(logging.DefaultLogger).Log(
				decl.LogKeyGUID, guid,
				decl.LogKeyWarning, "Disabling HTTP basic Auth",
				"category", ctx.Param("category"),
				"service", ctx.Param("service"),
			)

			return
		}

		username, password, httpBasicAuthOk := ctx.Request.BasicAuth()

		if httpBasicAuthOk {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(config.EnvConfig.HTTPOptions.Auth.UserName))
			expectedPasswordHash := sha256.Sum256([]byte(config.EnvConfig.HTTPOptions.Auth.Password))

			usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1
			passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1

			if usernameMatch && passwordMatch {
				ctx.Next()

				return
			}

			ctx.AbortWithStatus(http.StatusForbidden)
		} else {
			ctx.Header("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			ctx.AbortWithError(http.StatusUnauthorized, errors2.ErrUnauthorized)
		}
	}
}

// loggerMiddleware is a middleware function that logs information about the incoming HTTP request and response.
// It sets a GUID (generated using ksuid.New().String()) in the Gin context with the key defined by decl.GUIDKey.
// The function starts a timer to measure the latency of the request.
// It then proceeds to the next middleware or handler in the chain by calling ctx.Next().
// After the request is processed, it checks for any errors in the context using ctx.Errors.Last().
// Based on the presence of an error, it decides which logger, logWrapper, and logKey to use.
// The logger is either logging.DefaultErrLogger or logging.DefaultLogger.
// The logWrapper is either level.Error or level.Info.
// The logKey is either decl.LogKeyError or decl.LogKeyMsg.
// The function stops the timer and calculates the latency.
// It then collects additional information about the request, such as negotiatedProtocol and cipherSuiteName.
// Finally, it calls logWrapper(logger).Log() to log the request information with the appropriate logger, logKey, and values.
func loggerMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			logKey     string
			logger     log.Logger
			logWrapper func(logger log.Logger) log.Logger
		)

		guid := ksuid.New().String()
		ctx.Set(decl.GUIDKey, guid)

		// Start timer
		start := time.Now()

		// Process request
		ctx.Next()

		err := ctx.Errors.Last()

		// Decide which logger to use
		if err != nil {
			logger = logging.DefaultErrLogger
			logWrapper = level.Error
			logKey = decl.LogKeyError
		} else {
			logger = logging.DefaultLogger
			logWrapper = level.Info
			logKey = decl.LogKeyMsg
		}

		// Stop timer
		end := time.Now()
		latency := end.Sub(start)

		negotiatedProtocol := decl.NotAvailable
		cipherSuiteName := decl.NotAvailable

		if ctx.Request.TLS != nil {
			negotiatedProtocol = tls.VersionName(ctx.Request.TLS.Version)
			cipherSuiteName = tls.CipherSuiteName(ctx.Request.TLS.CipherSuite)
		}

		logWrapper(logger).Log(
			decl.LogKeyGUID, guid,
			decl.LogKeyClientIP, ctx.ClientIP(),
			decl.LogKeyMethod, ctx.Request.Method,
			decl.LogKeyProtocol, ctx.Request.Proto,
			decl.LogKeyHTTPStatus, ctx.Writer.Status(),
			decl.LogKeyLatency, latency,
			decl.LogKeyUserAgent, func() string {
				if ctx.Request.UserAgent() != "" {
					return ctx.Request.UserAgent()
				}

				return decl.NotAvailable
			}(),
			decl.LogKeyTLSSecure, negotiatedProtocol,
			decl.LogKeyTLSCipher, cipherSuiteName,
			decl.LogKeyUriPath, ctx.Request.URL.Path,
			logKey, func() string {
				if err != nil {
					return err.Error()
				}

				return "HTTP request"
			}(),
		)
	}
}

// luaContextMiddleware is a middleware function that adds a Lua context to the Gin context.
// It sets the value of decl.DataExchangeKey in the Gin context to a new instance of Context created by lualib.NewContext().
// The function then calls the Next() method in the Gin context to proceed to the next middleware or handler in the chain.
func luaContextMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(decl.DataExchangeKey, lualib.NewContext())

		ctx.Next()
	}
}

// createMiddlewareChain is a function that creates a middleware chain for Gin framework.
// It takes a session store implementation as a parameter.
// The function returns a slice of gin.HandlerFunc, representing the middleware chain.
// The middleware chain consists of the following middlewares in order:
// - sessions.Sessions: middleware for session management using the provided session store.
// - adapter.Wrap: middleware that wraps the provided nosurf CSRF protection middleware.
// - luaContextMiddleware: custom middleware that adds a Lua context to the Gin context.
// - protectEndpointMiddleware: custom middleware that performs authentication and authorization checks.
// - withLanguageMiddleware: custom middleware that sets the language for the request.
func createMiddlewareChain(sessionStore sessions.Store) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		sessions.Sessions(decl.SessionName, sessionStore),
		adapter.Wrap(nosurf.NewPure),
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
	}
}

// routerGroup is a function that creates a new gin.RouterGroup and sets up routes for GET and POST requests.
// It takes the following parameters:
// - path: a string representing the base path for the router group.
// - router: an implementation of the gin.IRouter interface on which the router group will be added.
// - store: an implementation of the sessions.Store interface for session management.
// - getHandler: a gin.HandlerFunc that will be used to handle GET requests.
// - postHandler: a gin.HandlerFunc that will be used to handle POST requests.
//
// The function creates a new router group using the path and a list of middleware created by calling the createMiddlewareChain function.
// It then registers two GET routes ("/" and "/:languageTag") and two POST routes ("/post" and "/post/:languageTag") on the router group.
// The getHandler and postHandler functions are used as the handlers for these routes.
//
// The function returns the created router group.
func routerGroup(path string, router gin.IRouter, store sessions.Store, getHandler gin.HandlerFunc, postHandler gin.HandlerFunc) *gin.RouterGroup {
	group := router.Group(path, createMiddlewareChain(store)...)

	group.GET("/", getHandler)
	group.GET("/:languageTag", getHandler)

	group.POST("/post", postHandler)
	group.POST("/post/:languageTag", postHandler)

	return group
}

// setupWebAuthn is a function that initializes and configures a webauthn.WebAuthn instance for WebAuthn authentication and registration.
// It creates a new instance of webauthn.WebAuthn using the provided webauthn.Config.
// The config includes the RPDisplayName, RPID, RPOrigins, and Timeouts parameters for setting up the WebAuthn instance.
// The function returns a pointer to the initialized webauthn.WebAuthn instance and an error if there was an issue creating it.
func setupWebAuthn() (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPDisplayName: viper.GetString("webauthn_display_name"),
		RPID:          viper.GetString("webauthn_rp_id"),
		RPOrigins:     viper.GetStringSlice("webauthn_rp_origins"),
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,             // Require the response from the client comes before the end of the timeout.
				Timeout:    time.Second * 60, // Standard timeout for login sessions.
				TimeoutUVD: time.Second * 60, // Timeout for login sessions which have user verification set to discourage.
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,             // Require the response from the client comes before the end of the timeout.
				Timeout:    time.Second * 60, // Standard timeout for registration sessions.
				TimeoutUVD: time.Second * 60, // Timeout for login sessions which have user verification set to discourage.
			},
		},
	})
}

// setupSessionStore is a function that initializes and configures a sessions.Store for session management.
// It creates a cookie-based store using the keys from config.LoadableConfig.CookieStoreAuthKey and config.LoadableConfig.CookieStoreEncKey.
// The function also sets the session options including the path, secure flag, and SameSite mode.
// The configured session store is then returned.
func setupSessionStore() sessions.Store {
	sessionStore := cookie.NewStore([]byte(config.LoadableConfig.CookieStoreAuthKey), []byte(config.LoadableConfig.CookieStoreEncKey))
	sessionStore.Options(sessions.Options{
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	return sessionStore
}

// setupHTTPServer is a function that configures and returns an http.Server instance.
// It takes a *gin.Engine router as input and sets the router as the HTTP handler for the server.
// The function sets the server's address, idle timeout, read timeout, read header timeout, and write timeout based on the values from the config.EnvConfig struct.
//
// Usage:
// router := gin.New()
// server := setupHTTPServer(router)
// err := server.ListenAndServe()
func setupHTTPServer(router *gin.Engine) *http.Server {
	return &http.Server{
		Addr:              config.EnvConfig.HTTPAddress,
		Handler:           router,
		IdleTimeout:       time.Minute,
		ReadTimeout:       10 * time.Second, //nolint:gomnd // Ignore
		ReadHeaderTimeout: 10 * time.Second, //nolint:gomnd // Ignore
		WriteTimeout:      30 * time.Second, //nolint:gomnd // Ignore
	}
}

// prometheusMiddleware is a function that adds Prometheus middleware to a gin.Engine router.
// It returns a gin.HandlerFunc that is used to handle HTTP requests.
// The function performs the following steps:
// 1. Extracts the path from the request context.
// 2. Creates a new Prometheus timer to measure the duration of the request.
// 3. Calls the Next() method to pass the request to the next middleware or handler.
// 4. Increments the HTTPRequestsTotalCounter with the path label value.
// 5. Observes the duration of the request using the timer.
//
// Usage:
// router := gin.New()
// router.Use(prometheusMiddleware())
func prometheusMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		path := ctx.FullPath()

		timer := prometheus.NewTimer(HTTPResponseTimeSecondsHist.WithLabelValues(path))

		ctx.Next()

		HTTPRequestsTotalCounter.WithLabelValues(path).Inc()

		timer.ObserveDuration()
	}
}

// setupHydraEndpoints is a function that sets up the Hydra endpoints in the given Gin router.
//
// It takes in two parameters:
// - router: a pointer to a gin.Engine instance, which represents the Gin router.
// - store: a sessions.Store instance, which represents the session store.
//
// This function adds the following endpoints to the router:
//
//  1. GET endpoint with the path specified by "login_page" configuration value and handles the user login endpoint.
//     It calls the loginGETHandler handler to handle the request.
//
//  2. GET endpoint with the path specified by "device_page" configuration value and handles the U2F/FIDO2 login endpoint.
//     It calls the deviceGETHandler handler to handle the request.
//
//  3. GET endpoint with the path specified by "consent_page" configuration value and handles the user consent endpoint.
//     It calls the consentGETHandler handler to handle the request.
//
//  4. GET endpoint with the path specified by "logout_page" configuration value and handles the user logout endpoint.
//     It calls the logoutGETHandler handler to handle the request.
//
// Usage:
//
//	setupHydraEndpoints(router, sessionStore)
func setupHydraEndpoints(router *gin.Engine, store sessions.Store) {
	// This page handles the user login endpoint
	routerGroup(viper.GetString("login_page"), router, store, loginGETHandler, loginPOSTHandler)

	// This page handles the U2F/FIDO2 login endpoint
	routerGroup(viper.GetString("device_page"), router, store, deviceGETHandler, devicePOSTHandler)

	// This page handles the user consent endpoint
	routerGroup(viper.GetString("consent_page"), router, store, consentGETHandler, consentPOSTHandler)

	// This page handles the user logout endpoint
	routerGroup(viper.GetString("logout_page"), router, store, logoutGETHandler, logoutPOSTHandler)
}

// setup2FAEndpoints is a function that sets up the 2FA (Two-Factor Authentication) endpoints in the given Gin router.
//
// It takes in two parameters:
// - router: a pointer to a gin.Engine instance, which represents the Gin router.
// - sessionStore: a sessions.Store instance, which represents the session store.
//
// This function adds the following endpoints to the router:
//
//  1. GET endpoint with the path "/2fa/v1/home" or "/2fa/v1/home/:languageTag" and handles the user registration home page for 2FA.
//     It calls the register2FAHomeHandler handler to handle the request.
//
//  2. GET endpoint with the path "/2fa/v1/:totp_page" and handles the TOTP registration.
//     It calls the registerTotpGETHandler handler to handle the request.
//
// Note: The implementation of register2FAHomeHandler and registerTotpGETHandler is not provided here.
// Please refer to their respective declarations for more information on the function implementation.
//
// Usage:
//
//	setup2FAEndpoints(router, sessionStore)
func setup2FAEndpoints(router *gin.Engine, sessionStore sessions.Store) {
	group := router.Group(decl.TwoFAv1Root)

	// This page handles the user login request to do a two-factor authentication
	twoFactorGroup := routerGroup(viper.GetString("login_2fa_page"), group, sessionStore, loginGET2FAHandler, loginPOST2FAHandler)
	twoFactorGroup.GET("/home", register2FAHomeHandler)
	twoFactorGroup.GET("/home/:languageTag", register2FAHomeHandler)

	// This page handles the TOTP registration
	routerGroup(viper.GetString("totp_page"), group, sessionStore, registerTotpGETHandler, registerTotpPOSTHandler)
}

// setupStaticContent is a function that sets up the static content endpoints in the given Gin router.
// It takes in one parameter:
// - router: a pointer to a gin.Engine instance, which represents the Gin router.
// This function adds the following static file endpoints to the router:
// - A GET endpoint with the path "/favicon.ico" and the file path obtained from the "html_static_content_path" configuration value appended with "/img/favicon.ico"
// - A GET endpoint with the path "/static/css" and the file path obtained from the "html_static_content_path" configuration value appended with "/css"
// - A GET endpoint with the path "/static/js" and the file path obtained from the "html_static_content_path" configuration value appended with "/js"
// - A GET endpoint with the path "/static/img" and the file path obtained from the "html_static_content_path" configuration value appended with "/img"
// - A GET endpoint with the path "/static/fonts" and the file path obtained from the "html_static_content_path" configuration value appended with "/fonts"
func setupStaticContent(router *gin.Engine) {
	router.StaticFile("/favicon.ico", viper.GetString("html_static_content_path")+"/img/favicon.ico")
	router.Static("/static/css", viper.GetString("html_static_content_path")+"/css")
	router.Static("/static/js", viper.GetString("html_static_content_path")+"/js")
	router.Static("/static/img", viper.GetString("html_static_content_path")+"/img")
	router.Static("/static/fonts", viper.GetString("html_static_content_path")+"/fonts")
}

// setupNotifyEndpoint is a function that sets up the endpoints for the notify page in the given Gin router.
// It takes in two parameters:
// - router: a pointer to a gin.Engine instance, which represents the Gin router.
// - sessionStore: an instance of the sessions.Store interface, which represents the session store.
// This function creates a group in the router with the path specified in the "notify_page" configuration value.
// It adds a middleware to the group that sets up the session store for the requests.
// It then adds two GET endpoints to the group:
// - An endpoint with the path "/" and a middlewares: luaContextMiddleware, protectEndpointMiddleware, withLanguageMiddleware, notifyGETHandler
// - An endpoint with the path "/:languageTag" and a middlewares: luaContextMiddleware, protectEndpointMiddleware, withLanguageMiddleware, notifyGETHandler
func setupNotifyEndpoint(router *gin.Engine, sessionStore sessions.Store) {
	group := router.Group(viper.GetString("notify_page"))

	group.Use(sessions.Sessions(decl.SessionName, sessionStore))
	group.GET("/", luaContextMiddleware(), protectEndpointMiddleware(), withLanguageMiddleware(), notifyGETHandler)
	group.GET("/:languageTag", luaContextMiddleware(), protectEndpointMiddleware(), withLanguageMiddleware(), notifyGETHandler)
}

// setupBackChannelEndpoints is a function that sets up the endpoints for the back channel in the given Gin router.
// It takes in one parameter:
// - router: a pointer to a gin.Engine instance, which represents the Gin router.
//
// This function creates a group in the router with the path "/api/v1".
// If the configuration value "UseBasicAuth" in the EnvConfig struct is set to true,
// it adds a middleware to the group that implements basic authentication.
//
// It then adds three endpoints to the group:
// - A GET endpoint with the path "/:category/:service" that is handled by the luaContextMiddleware and httpQueryHandler functions.
// - A POST endpoint with the path "/:category/:service" that is also handled by the luaContextMiddleware and httpQueryHandler functions.
// - A DELETE endpoint with the path "/:category/:service" that is handled by the httpCacheHandler function.
func setupBackChannelEndpoints(router *gin.Engine) {
	group := router.Group("/api/v1")

	if config.EnvConfig.HTTPOptions.UseBasicAuth {
		group.Use(basicAuthMiddleware())
	}

	group.GET("/:category/:service", luaContextMiddleware(), httpQueryHandler)
	group.POST("/:category/:service", luaContextMiddleware(), httpQueryHandler)
	group.DELETE("/:category/:service", httpCacheHandler)
}

// setupWebAuthnEndpoints is a function that sets up the endpoints related to WebAuthn in the given Gin router.
// It takes in two parameters:
// - router: a pointer to a gin.Engine instance, which represents the Gin router.
// - sessionStore: an instance of sessions.Store, which is used for session management.
// This function creates a group in the router with the path specified by the constant decl.TwoFAv1Root.
// Inside this group, it creates another group with the path specified by the configuration value "webauthn_page" retrieved from viper.GetString("webauthn_page").
// It adds a middleware to this sub-group that enables session management using the provided session store.
// It then adds two endpoints to this sub-group:
// - A GET endpoint at the path "/register/begin" which is handled by the beginRegistration function.
// - A POST endpoint at the path "/register/finish" which is handled by the finishRegistration function.
func setupWebAuthnEndpoints(router *gin.Engine, sessionStore sessions.Store) {
	group := router.Group(decl.TwoFAv1Root)

	regGroup := group.Group(viper.GetString("webauthn_page"))
	regGroup.Use(sessions.Sessions(decl.SessionName, sessionStore))
	regGroup.GET("/register/begin", beginRegistration)
	regGroup.POST("/register/finish", finishRegistration)
}

// waitForShutdown is a function that waits for the context to be done, then shuts down the provided http.Server.
// It takes in two parameters:
// - www: a pointer to the http.Server instance
// - ctx: a context.Context instance
func waitForShutdown(www *http.Server, ctx context.Context) {
	<-ctx.Done()

	www.Shutdown(ctx)

	HTTPEndChan <- Done{}

	return
}

// HTTPApp is a function that starts the HTTP server and sets up the necessary middlewares and endpoints.
// It takes a context.Context parameter.
func HTTPApp(ctx context.Context) {
	var err error

	webAuthn, err = setupWebAuthn()
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(decl.LogKeyMsg, "Failed to create WebAuthn from EnvConfig", decl.LogKeyError, err)

		os.Exit(-1)
	}

	// Disable debugging
	if !(config.EnvConfig.Verbosity.Level() == decl.LogLevelDebug && config.EnvConfig.DevMode) {
		gin.SetMode(gin.ReleaseMode)
	}

	gin.DisableConsoleColor()

	router := gin.New()

	if config.EnvConfig.Verbosity.Level() == decl.LogLevelDebug {
		pprof.Register(router)
	}

	// Wrap the GoKit logger
	router.Use(loggerMiddleware())

	www := setupHTTPServer(router)

	go waitForShutdown(www, ctx)

	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	router.Use(gin.Recovery())

	// Add trusted proxies
	router.SetTrustedProxies(viper.GetStringSlice("trusted_proxies"))

	// Add Prometheus middleware
	router.Use(prometheusMiddleware())

	// Prometheus endpoint
	router.GET("/metrics", gin.WrapF(promhttp.Handler().ServeHTTP))

	// Healthcheck
	router.GET("/ping", httpQueryHandler)

	// Parse static folder for template files
	router.LoadHTMLGlob(viper.GetString("html_static_content_path") + "/*.html")

	store := setupSessionStore()

	setupHydraEndpoints(router, store)
	setup2FAEndpoints(router, store)
	setupWebAuthnEndpoints(router, store)
	setupStaticContent(router)
	setupNotifyEndpoint(router, store)
	setupBackChannelEndpoints(router)

	// www.SetKeepAlivesEnabled(false)

	if config.EnvConfig.HTTPOptions.UseSSL {
		www.TLSConfig = &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: tls.VersionTLS12,
		}
		err = www.ListenAndServeTLS(config.EnvConfig.HTTPOptions.X509.Cert, config.EnvConfig.HTTPOptions.X509.Key)
	} else {
		err = www.ListenAndServe()
	}

	if !errors.Is(err, http.ErrServerClosed) {
		level.Error(logging.DefaultErrLogger).Log(decl.LogKeyError, err)

		os.Exit(1)
	}
}
