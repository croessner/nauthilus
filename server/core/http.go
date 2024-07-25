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
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/tags"
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
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
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
		healthCheck(ctx)
	} else {
		switch ctx.Param("category") {
		case global.CatMail, global.CatGeneric:
			auth := NewAuthState(ctx)
			if auth == nil {
				ctx.AbortWithStatus(http.StatusBadRequest)

				return
			}

			if found, reject := auth.preproccessAuthRequest(ctx); reject {
				return
			} else if found {
				auth.withClientInfo(ctx).withLocalInfo(ctx).withUserAgent(ctx).withXSSL(ctx)
			}

			switch ctx.Param("service") {
			case global.ServNginx, global.ServDovecot, global.ServUserInfo, global.ServJSON:
				auth.generic(ctx)
			case global.ServSaslauthd:
				auth.saslAuthd(ctx)
			case global.ServCallback:
				auth.callback(ctx)
				ctx.Status(auth.StatusCodeOK)
			default:
				ctx.AbortWithStatus(http.StatusNotFound)
			}

		case global.CatHTTP:
			auth := NewAuthState(ctx)
			if auth == nil {
				ctx.AbortWithStatus(http.StatusBadRequest)

				return
			}

			if found, reject := auth.preproccessAuthRequest(ctx); reject {
				return
			} else if found {
				auth.withClientInfo(ctx).withLocalInfo(ctx).withUserAgent(ctx).withXSSL(ctx)
			}

			switch ctx.Param("service") {
			case global.ServBasicAuth:
				auth.generic(ctx)
			default:
				ctx.AbortWithStatus(http.StatusNotFound)
			}

		case global.CatBruteForce:
			switch ctx.Param("service") {
			case global.ServList:
				listBruteforce(ctx)
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
	case global.CatCache:
		switch ctx.Param("service") {
		case global.ServFlush:
			flushCache(ctx)
		}

	case global.CatBruteForce:
		switch ctx.Param("service") {
		case global.ServFlush:
			flushBruteForceRule(ctx)
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
		guid := ctx.GetString(global.CtxGUIDKey) // MiddleWare behind Logger!

		protocol := &config.Protocol{}
		protocol.Set(global.ProtoHTTP)

		clientIP := ctx.GetHeader("Client-IP")
		clientPort := util.WithNotAvailable(ctx.GetHeader("X-Client-Port"))
		method := "plain"

		auth := &AuthState{
			HTTPClientContext: ctx.Copy(),
			NoAuth:            true,
			GUID:              &guid,
			Protocol:          protocol,
			Method:            &method,
		}

		auth.withUserAgent(ctx)
		auth.withXSSL(ctx)

		if clientIP == "" {
			clientIP, clientPort, _ = net.SplitHostPort(ctx.Request.RemoteAddr)
		}

		clientIP, clientPort = util.GetProxyAddress(ctx.Request, clientIP, clientPort)

		if clientIP == "" {
			clientIP = global.NotAvailable
		}

		if clientPort == "" {
			clientPort = global.NotAvailable
		}

		auth.ClientIP = clientIP
		auth.XClientPort = clientPort

		// Store remote client IP into connection context. It can be used for brute force updates.
		ctx.Set(global.CtxClientIPKey, clientIP)

		if auth.checkBruteForce() {
			auth.updateBruteForceBucketsCounter()
			auth.postLuaAction(&PassDBResult{})
			auth.authFail(ctx)
			ctx.Abort()

			return
		}

		//nolint:exhaustive // Ignore some results
		switch auth.handleFeatures(ctx) {
		case global.AuthResultFeatureTLS:
			auth.postLuaAction(&PassDBResult{})
			handleErr(ctx, errors2.ErrNoTLS)
			ctx.Abort()

			return
		case global.AuthResultFeatureRelayDomain, global.AuthResultFeatureRBL, global.AuthResultFeatureLua:
			auth.postLuaAction(&PassDBResult{})
			auth.authFail(ctx)
			ctx.Abort()

			return
		case global.AuthResultUnset:
		case global.AuthResultOK:
		case global.AuthResultFail:
		case global.AuthResultTempFail:
		case global.AuthResultEmptyUsername:
		case global.AuthResultEmptyPassword:
		}

		ctx.Next()
	}
}

// basicAuthMiddleware returns a gin middleware handler dedicated for performing HTTP Basic AuthState.
// It first checks for specified parameters in the incoming request context.
// If the request already contains BasicAuth in its header, it attempts to authenticate the credentials. Hashed values
// of the supplied username and password are compared in constant time against expected username and password hashes.
// If the credentials match, it allows the equest to proceed; else terminates the request with HTTP 403 Forbidden status.
// If BasicAuth wasn't provided in request, it asks the client to provide credentials responding with HTTP 401 Unauthorized,
// and inserts a WWW-Authenticate field into response header.
func basicAuthMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		guid := ctx.GetString(global.CtxGUIDKey)

		// Note: Chicken-egg problem.
		if ctx.Param("category") == global.CatHTTP && ctx.Param("service") == global.ServBasicAuth {
			level.Warn(logging.DefaultLogger).Log(
				global.LogKeyGUID, guid,
				global.LogKeyWarning, "Disabling HTTP basic Auth",
				"category", ctx.Param("category"),
				"service", ctx.Param("service"),
			)

			return
		}

		username, password, httpBasicAuthOk := ctx.Request.BasicAuth()

		if httpBasicAuthOk {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(config.LoadableConfig.Server.BasicAuth.Username))
			expectedPasswordHash := sha256.Sum256([]byte(config.LoadableConfig.Server.BasicAuth.Password))

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
// It sets a GUID (generated using ksuid.New().String()) in the Gin context with the key defined by global.CtxGUIDKey.
// The function starts a timer to measure the latency of the request.
// It then proceeds to the next middleware or handler in the chain by calling ctx.Next().
// After the request is processed, it checks for any errors in the context using ctx.Errors.Last().
// Based on the presence of an error, it decides which logger, logWrapper, and logKey to use.
// The logger is either logging.DefaultErrLogger or logging.DefaultLogger.
// The logWrapper is either level.Error or level.Info.
// The logKey is either global.LogKeyError or global.LogKeyMsg.
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
		ctx.Set(global.CtxGUIDKey, guid)
		ctx.Set(global.CtxLocalCacheAuthKey, false)

		// Start timer
		start := time.Now()

		// Process request
		ctx.Next()

		err := ctx.Errors.Last()

		// Decide which logger to use
		if err != nil {
			logger = logging.DefaultErrLogger
			logWrapper = level.Error
			logKey = global.LogKeyError
		} else {
			logger = logging.DefaultLogger
			logWrapper = level.Info
			logKey = global.LogKeyMsg
		}

		// Stop timer
		end := time.Now()
		latency := end.Sub(start)

		negotiatedProtocol := global.NotAvailable
		cipherSuiteName := global.NotAvailable

		if ctx.Request.TLS != nil {
			negotiatedProtocol = tls.VersionName(ctx.Request.TLS.Version)
			cipherSuiteName = tls.CipherSuiteName(ctx.Request.TLS.CipherSuite)
		}

		logWrapper(logger).Log(
			global.LogKeyGUID, guid,
			global.LogKeyClientIP, ctx.ClientIP(),
			global.LogKeyMethod, ctx.Request.Method,
			global.LogKeyProtocol, ctx.Request.Proto,
			global.LogKeyHTTPStatus, ctx.Writer.Status(),
			global.LogKeyLatency, latency,
			global.LogKeyUserAgent, func() string {
				if ctx.Request.UserAgent() != "" {
					return ctx.Request.UserAgent()
				}

				return global.NotAvailable
			}(),
			global.LogKeyTLSSecure, negotiatedProtocol,
			global.LogKeyTLSCipher, cipherSuiteName,
			global.LogKeyUriPath, ctx.Request.URL.Path,
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
// It sets the value of global.CtxDataExchangeKey in the Gin context to a new instance of Context created by lualib.NewContext().
// The function then calls the Next() method in the Gin context to proceed to the next middleware or handler in the chain.
func luaContextMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(global.CtxDataExchangeKey, lualib.NewContext())

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
		sessions.Sessions(global.SessionName, sessionStore),
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
	sessionStore := cookie.NewStore([]byte(config.LoadableConfig.Server.Frontend.CookieStoreAuthKey), []byte(config.LoadableConfig.Server.Frontend.CookieStoreEncKey))
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
		Addr:              config.LoadableConfig.Server.Address,
		Handler:           router,
		IdleTimeout:       time.Minute,
		ReadTimeout:       10 * time.Second, //nolint:gomnd // Ignore
		ReadHeaderTimeout: 10 * time.Second, //nolint:gomnd // Ignore
		WriteTimeout:      30 * time.Second, //nolint:gomnd // Ignore
	}
}

// `prometheusMiddleware` is a middleware function for Gin Web Framework that collects metrics using Prometheus.
// It measures the duration of the HTTP request and increments a counter for the number of requests for each path.
// The collected metrics are stored in the Prometheus histogram, counter, and summary variables.
// This middleware function should be used in the setup of routing to collect metrics for each HTTP request.
func prometheusMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var timer *prometheus.Timer

		stopTimer := stats.PrometheusTimer(global.PromRequest, "request_total")
		path := ctx.FullPath()

		if config.LoadableConfig.Server.PrometheusTimer.Enabled {
			timer = prometheus.NewTimer(stats.HttpResponseTimeSecondsHist.WithLabelValues(path))
		}

		ctx.Next()

		stats.HttpRequestsTotalCounter.WithLabelValues(path).Inc()

		redisStatsMap := map[string]*redis.PoolStats{
			"master": rediscli.WriteHandle.PoolStats(),
		}

		if rediscli.WriteHandle != rediscli.ReadHandle {
			redisStatsMap["replica"] = rediscli.ReadHandle.PoolStats()
		}

		for handleType, redisStats := range redisStatsMap {
			stats.RedisHits.With(prometheus.Labels{"type": handleType}).Add(float64(redisStats.Hits))
			stats.RedisMisses.With(prometheus.Labels{"type": handleType}).Add(float64(redisStats.Misses))
			stats.RedisTimeouts.With(prometheus.Labels{"type": handleType}).Add(float64(redisStats.Timeouts))
			stats.RedisTotalConns.With(prometheus.Labels{"type": handleType}).Set(float64(redisStats.TotalConns))
			stats.RedisIdleConns.With(prometheus.Labels{"type": handleType}).Set(float64(redisStats.IdleConns))
			stats.RedisStaleConns.With(prometheus.Labels{"type": handleType}).Set(float64(redisStats.StaleConns))
		}

		if config.LoadableConfig.Server.PrometheusTimer.Enabled {
			timer.ObserveDuration()
		}

		stopTimer()
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

// setup2FAEndpoints is a function that sets up the 2FA (Two-Factor AuthState) endpoints in the given Gin router.
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
	if tags.Register2FA {
		group := router.Group(global.TwoFAv1Root)

		// This page handles the user login request to do a two-factor authentication
		twoFactorGroup := routerGroup(viper.GetString("login_2fa_page"), group, sessionStore, loginGET2FAHandler, loginPOST2FAHandler)
		twoFactorGroup.GET("/home", register2FAHomeHandler)
		twoFactorGroup.GET("/home/:languageTag", register2FAHomeHandler)

		// This page handles the TOTP registration
		routerGroup(viper.GetString("totp_page"), group, sessionStore, registerTotpGETHandler, registerTotpPOSTHandler)
	}
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

	group.Use(sessions.Sessions(global.SessionName, sessionStore))
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

	if config.LoadableConfig.Server.BasicAuth.Enabled {
		group.Use(basicAuthMiddleware())
	}

	group.GET("/:category/:service", prometheusMiddleware(), luaContextMiddleware(), httpQueryHandler)
	group.POST("/:category/:service", prometheusMiddleware(), luaContextMiddleware(), httpQueryHandler)
	group.DELETE("/:category/:service", httpCacheHandler)
}

// setupWebAuthnEndpoints is a function that sets up the endpoints related to WebAuthn in the given Gin router.
// It takes in two parameters:
// - router: a pointer to a gin.Engine instance, which represents the Gin router.
// - sessionStore: an instance of sessions.Store, which is used for session management.
// This function creates a group in the router with the path specified by the constant global.TwoFAv1Root.
// Inside this group, it creates another group with the path specified by the configuration value "webauthn_page" retrieved from viper.GetString("webauthn_page").
// It adds a middleware to this sub-group that enables session management using the provided session store.
// It then adds two endpoints to this sub-group:
// - A GET endpoint at the path "/register/begin" which is handled by the beginRegistration function.
// - A POST endpoint at the path "/register/finish" which is handled by the finishRegistration function.
func setupWebAuthnEndpoints(router *gin.Engine, sessionStore sessions.Store) {
	if tags.IsDevelopment {
		group := router.Group(global.TwoFAv1Root)

		regGroup := group.Group(viper.GetString("webauthn_page"))
		regGroup.Use(sessions.Sessions(global.SessionName, sessionStore))
		regGroup.GET("/register/begin", beginRegistration)
		regGroup.POST("/register/finish", finishRegistration)
	}
}

// waitForShutdown is a function that waits for the context to be done, then shuts down the provided http.Server.
// It takes in two parameters:
// - www: a pointer to the http.Server instance
// - ctx: a context.Context instance
func waitForShutdown(www *http.Server, ctx context.Context) {
	<-ctx.Done()

	waitCtx, cancel := context.WithDeadline(ctx, time.Now().Add(30*time.Second))

	defer cancel()

	www.Shutdown(waitCtx)

	HTTPEndChan <- Done{}

	return
}

// prepareHAproxyV2 returns a *proxyproto.Listener which is used to prepare HAProxy V2 version by:
// 1. Creating a listener on the specified address using `net.Listen` with "tcp" network and the address from `config.LoadableConfig.Server.Address`.
// 2. Setting the policyFunc to `proxyproto.REQUIRE` using `proxyproto.Listener` to ensure HAProxy V2 requirement.
// The function returns a pointer to `proxyproto.Listener` if `config.LoadableConfig.Server.HAproxyV2` is true, otherwise returns nil.
// It panics if an error occurs while creating the listener.
func prepareHAproxyV2() *proxyproto.Listener {
	var (
		listener      net.Listener
		proxyListener *proxyproto.Listener
		err           error
	)

	if config.LoadableConfig.Server.HAproxyV2 {
		listener, err = net.Listen("tcp", config.LoadableConfig.Server.Address)
		if err != nil {
			panic(err)
		}

		policyFunc := func(upstream net.Addr) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		}

		proxyListener = &proxyproto.Listener{
			Listener: listener,
			Policy:   policyFunc,
		}
	}

	return proxyListener
}

// HTTPApp is a function that starts the HTTP server and sets up the necessary middlewares and endpoints.
// It takes a context.Context parameter.
func HTTPApp(ctx context.Context) {
	var err error

	webAuthn, err = setupWebAuthn()
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyMsg, "Failed to create WebAuthn from EnvConfig", global.LogKeyError, err)

		os.Exit(-1)
	}

	// Disable debugging
	if !(config.LoadableConfig.Server.Log.Level.Level() == global.LogLevelDebug && config.EnvConfig.DevMode) {
		gin.SetMode(gin.ReleaseMode)
	}

	gin.DisableConsoleColor()

	router := gin.New()

	if config.LoadableConfig.GetServerInsightsEnablePprof() {
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

	if config.LoadableConfig.Server.Frontend.Enabled {
		store := setupSessionStore()

		setupHydraEndpoints(router, store)
		setup2FAEndpoints(router, store)
		setupWebAuthnEndpoints(router, store)
		setupNotifyEndpoint(router, store)
	}

	setupStaticContent(router)
	setupBackChannelEndpoints(router)

	// www.SetKeepAlivesEnabled(false)

	proxyListener := prepareHAproxyV2()

	if config.LoadableConfig.Server.TLS.Enabled {
		www.TLSConfig = &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: tls.VersionTLS12,
		}

		if proxyListener != nil {
			err = www.ServeTLS(proxyListener, config.LoadableConfig.Server.TLS.Cert, config.LoadableConfig.Server.TLS.Key)
		} else {
			err = www.ListenAndServeTLS(config.LoadableConfig.Server.TLS.Cert, config.LoadableConfig.Server.TLS.Key)
		}
	} else {
		if proxyListener != nil {
			err = www.Serve(proxyListener)
		} else {
			err = www.ListenAndServe()
		}
	}

	if !errors.Is(err, http.ErrServerClosed) {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, err)

		os.Exit(1)
	}
}
