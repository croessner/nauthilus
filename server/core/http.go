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
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/tags"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gwatts/gin-adapter"
	"github.com/justinas/nosurf"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/segmentio/ksuid"
	"github.com/spf13/viper"
)

var (
	// HTTPEndChan is a channel of type `Done` used to signal the completion of HTTP server operations.
	HTTPEndChan chan Done

	// HTTP3EndChan is a channel of type `Done` used to signal the completion of HTTP3 server operations.
	HTTP3EndChan chan Done

	// LangBundle is a pointer to an instance of the i18n.Bundle type.
	// It represents a language bundle which is used for localization and internationalization purposes in the application.
	LangBundle *i18n.Bundle
)

// RESTResult is a handleAuthentication JSON result object for the Nauthilus REST API.
type RESTResult struct {
	// GUID represents a unique identifier for a session. It is a string field used in the RESTResult struct
	// and is also annotated with the json tag "session".
	GUID string `json:"session"`

	// Object represents a string field used in the RESTResult struct. It is annotated with the json tag "object".
	Object string `json:"object"`

	// Operation represents a string field used in the RESTResult struct. It is annotated with the json tag "operation".
	Operation string `json:"operation"`

	// Result represents the result field in the RESTResult struct. It can hold any type of value.
	// The field is annotated with the json tag "result".
	Result any `json:"result"`
}

// LimitCounter tracks the current number of active connections and limits them based on a specified maximum.
type LimitCounter struct {
	// MaxConnections defines the maximum number of concurrent connections allowed.
	MaxConnections int32

	// CurrentConnections tracks the current number of active connections in the LimitCounter middleware.
	CurrentConnections int32
}

// NewLimitCounter creates a new LimitCounter instance with the specified maximum number of concurrent connections.
func NewLimitCounter(maxConnections int32) *LimitCounter {
	return &LimitCounter{
		MaxConnections: maxConnections,
	}
}

// Middleware limits the number of concurrent connections handled by the server based on MaxConnections.
func (lc *LimitCounter) Middleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if atomic.LoadInt32(&lc.CurrentConnections) >= lc.MaxConnections {
			ctx.JSON(http.StatusTooManyRequests, gin.H{definitions.LogKeyMsg: "Too many requests"})

			ctx.Abort()

			return
		}

		atomic.AddInt32(&lc.CurrentConnections, 1)

		stats.CurrentRequests.Set(float64(atomic.LoadInt32(&lc.CurrentConnections)))

		defer atomic.AddInt32(&lc.CurrentConnections, -1)

		ctx.Next()
	}
}

// customWriter represents a type that logs data based on a specified log level.
type customWriter struct {
	// logger represents a logger instance and is used for all messages that are printed to stdout.
	logger kitlog.Logger

	// logLevel represents the log level used for logging data in the customWriter type.
	// The log level determines how the written data is logged:
	//   - If the log level is set to Debug, the data is logged at the Debug level.
	//   - If the log level is set to Error, the data is logged at the Error level.
	//   - If the log level is set to any other value, the data is logged normally.
	// The logLevel field is of type level.Value, which is used to store and compare log levels.
	// The logLevel field is set in the customWriter struct and is used in the Write method to determine the appropriate log level for the data being written.
	// The logLevel field is not accessible outside of the customWriter type.
	logLevel level.Value
}

// Write writes the provided byte slice to the customWriter.
//
// The Write method logs the data based on the log level specified in the customWriter type.
// If the log level is set to Debug, the data is logged at the Debug level.
// If the log level is set to Error, the data is logged at the Error level.
// For any other log level value, the data is logged normally at the Info level.
//
// The method returns the number of bytes written and any error that occurred during the logging process.
func (w *customWriter) Write(data []byte) (numBytes int, err error) {
	switch w.logLevel {
	case level.DebugValue():
		err = level.Debug(w.logger).Log("msg", string(data))
	case level.ErrorValue():
		err = level.Error(w.logger).Log("msg", string(data))
	default:
		err = level.Info(w.logger).Log("msg", string(data))
	}

	if err != nil {
		return 0, err
	}

	return len(data), nil
}

//nolint:gocognit // Main logic
func requestHandler(ctx *gin.Context) {
	if ctx.FullPath() == "/ping" {
		healthCheck(ctx)
	} else {
		switch ctx.Param("category") {
		case definitions.CatAuth:
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
			case definitions.ServBasic, definitions.ServNginx, definitions.ServHeader, definitions.ServJSON:
				auth.handleAuthentication(ctx)
			case definitions.ServSaslauthd:
				auth.handleSASLAuthdAuthentication(ctx)
			case definitions.ServCallback:
				auth.handleCallback(ctx)
				ctx.Status(auth.StatusCodeOK)
			default:
				ctx.AbortWithStatus(http.StatusNotFound)
			}

		case definitions.CatBruteForce:
			switch ctx.Param("service") {
			case definitions.ServList:
				hanldeBruteForceList(ctx)
			default:
				ctx.AbortWithStatus(http.StatusNotFound)
			}

		default:
			ctx.AbortWithStatus(http.StatusNotFound)
		}
	}
}

// httpCacheHandler handles the HTTP requests for cache related operations.
// It takes a gin.Context as a parameter.
//
// Procedure:
//  1. The function retrieves the "category" parameter from the request context.
//  2. It uses a switch statement to handle different category values.
//  3. For the "cache" category, it retrieves the "service" parameter and uses a switch statement
//     to handle different service values.
//  4. For the "flush" service, it calls the handleUserFlush function.
//  5. For the "bruteforce" category, it retrieves the "service" parameter and uses a switch statement
//     to handle different service values.
//  6. For the "flush" service, it calls the handleBruteForceRuleFlush function.
func httpCacheHandler(ctx *gin.Context) {
	//nolint:gocritic // Prepared for future commands
	switch ctx.Param("category") {
	case definitions.CatCache:
		switch ctx.Param("service") {
		case definitions.ServFlush:
			handleUserFlush(ctx)
		}

	case definitions.CatBruteForce:
		switch ctx.Param("service") {
		case definitions.ServFlush:
			handleBruteForceRuleFlush(ctx)
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
		guid := ctx.GetString(definitions.CtxGUIDKey) // MiddleWare behind Logger!

		protocol := &config.Protocol{}
		protocol.Set(definitions.ProtoHTTP)

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

		util.ProcessXForwardedFor(ctx, &clientIP, &clientPort, &auth.XSSL)

		if clientIP == "" {
			clientIP = definitions.NotAvailable
		}

		if clientPort == "" {
			clientPort = definitions.NotAvailable
		}

		auth.ClientIP = clientIP
		auth.XClientPort = clientPort

		// Store remote client IP into connection context. It can be used for brute force updates.
		ctx.Set(definitions.CtxClientIPKey, clientIP)

		if auth.checkBruteForce() {
			auth.updateBruteForceBucketsCounter()
			auth.postLuaAction(&PassDBResult{})
			auth.authFail(ctx)
			ctx.Abort()

			return
		}

		//nolint:exhaustive // Ignore some results
		switch auth.handleFeatures(ctx) {
		case definitions.AuthResultFeatureTLS:
			auth.postLuaAction(&PassDBResult{})
			handleErr(ctx, errors.ErrNoTLS)
			ctx.Abort()

			return
		case definitions.AuthResultFeatureRelayDomain, definitions.AuthResultFeatureRBL, definitions.AuthResultFeatureLua:
			auth.postLuaAction(&PassDBResult{})
			auth.authFail(ctx)
			ctx.Abort()

			return
		case definitions.AuthResultUnset:
		case definitions.AuthResultOK:
		case definitions.AuthResultFail:
		case definitions.AuthResultTempFail:
			auth.postLuaAction(&PassDBResult{})
			auth.authTempFail(ctx, definitions.TempFailDefault)
			ctx.Abort()

			return
		case definitions.AuthResultEmptyUsername:
		case definitions.AuthResultEmptyPassword:
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
		guid := ctx.GetString(definitions.CtxGUIDKey)

		// Note: Chicken-egg problem.
		if ctx.Param("category") == definitions.CatAuth && ctx.Param("service") == definitions.ServBasic {
			level.Warn(log.Logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Disabling HTTP basic Auth",
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
			ctx.AbortWithError(http.StatusUnauthorized, errors.ErrUnauthorized)
		}
	}
}

// loggerMiddleware is a middleware function that logs information about the incoming HTTP request and response.
// It sets a GUID (generated using ksuid.New().String()) in the Gin context with the key defined by definitions.CtxGUIDKey.
// The function starts a timer to measure the latency of the request.
// It then proceeds to the next middleware or handler in the chain by calling ctx.Next().
// After the request is processed, it checks for any errors in the context using ctx.Errors.Last().
// Based on the presence of an error, it decides which logger, logWrapper, and logKey to use.
// The logWrapper is either level.Error or level.Info.
// The logKey is either definitions.LogKeyMsg or global.LogKeyMsg.
// The function stops the timer and calculates the latency.
// It then collects additional information about the request, such as negotiatedProtocol and cipherSuiteName.
// Finally, it calls logWrapper(logger).Log() to log the request information with the appropriate logger, logKey, and values.
func loggerMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			logWrapper func(logger kitlog.Logger) kitlog.Logger
		)

		guid := ksuid.New().String()
		ctx.Set(definitions.CtxGUIDKey, guid)
		ctx.Set(definitions.CtxLocalCacheAuthKey, false)

		// Start timer
		start := time.Now()

		// Process request
		ctx.Next()

		err := ctx.Errors.Last()

		// Decide which logger to use
		if err != nil {
			logWrapper = level.Error
		} else {
			logWrapper = level.Info
		}

		// Stop timer
		end := time.Now()
		latency := end.Sub(start)

		negotiatedProtocol := definitions.NotAvailable
		cipherSuiteName := definitions.NotAvailable

		if ctx.Request.TLS != nil {
			negotiatedProtocol = tls.VersionName(ctx.Request.TLS.Version)
			cipherSuiteName = tls.CipherSuiteName(ctx.Request.TLS.CipherSuite)
		}

		logWrapper(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyClientIP, ctx.ClientIP(),
			definitions.LogKeyMethod, ctx.Request.Method,
			definitions.LogKeyProtocol, ctx.Request.Proto,
			definitions.LogKeyHTTPStatus, ctx.Writer.Status(),
			definitions.LogKeyLatency, latency,
			definitions.LogKeyUserAgent, func() string {
				if ctx.Request.UserAgent() != "" {
					return ctx.Request.UserAgent()
				}

				return definitions.NotAvailable
			}(),
			definitions.LogKeyTLSSecure, negotiatedProtocol,
			definitions.LogKeyTLSCipher, cipherSuiteName,
			definitions.LogKeyUriPath, ctx.Request.URL.Path,
			definitions.LogKeyMsg, func() string {
				if err != nil {
					return err.Error()
				}

				return "HTTP request"
			}(),
		)
	}
}

// luaContextMiddleware is a middleware function that adds a Lua context to the Gin context.
// It sets the value of definitions.CtxDataExchangeKey in the Gin context to a new instance of Context created by lualib.NewContext().
// The function then calls the Next() method in the Gin context to proceed to the next middleware or handler in the chain.
func luaContextMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(definitions.CtxDataExchangeKey, lualib.NewContext())

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
		sessions.Sessions(definitions.SessionName, sessionStore),
		adapter.Wrap(nosurf.NewPure),
		luaContextMiddleware(),
		withLanguageMiddleware(),
		protectEndpointMiddleware(),
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

		mode := ctx.Query("mode")
		if mode == "" {
			mode = "auth"
		}

		stopTimer := stats.PrometheusTimer(definitions.PromRequest, fmt.Sprintf("request_%s_total", strings.ReplaceAll(mode, "-", "_")))
		path := ctx.FullPath()

		if config.LoadableConfig.Server.PrometheusTimer.Enabled {
			timer = prometheus.NewTimer(stats.HttpResponseTimeSecondsHist.WithLabelValues(path))
		}

		ctx.Next()

		stats.HttpRequestsTotalCounter.WithLabelValues(path).Inc()

		if config.LoadableConfig.Server.PrometheusTimer.Enabled {
			timer.ObserveDuration()
		}

		if stopTimer != nil {
			stopTimer()
		}
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
		group := router.Group(definitions.TwoFAv1Root)

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

	group.Use(sessions.Sessions(definitions.SessionName, sessionStore))
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
// - A GET endpoint with the path "/:category/:service" that is handled by the luaContextMiddleware and requestHandler functions.
// - A POST endpoint with the path "/:category/:service" that is also handled by the luaContextMiddleware and requestHandler functions.
// - A DELETE endpoint with the path "/:category/:service" that is handled by the httpCacheHandler function.
func setupBackChannelEndpoints(router *gin.Engine) {
	group := router.Group("/api/v1")

	if config.LoadableConfig.Server.BasicAuth.Enabled {
		group.Use(basicAuthMiddleware())
	}

	group.GET("/:category/:service", luaContextMiddleware(), requestHandler)
	group.POST("/:category/:service", luaContextMiddleware(), requestHandler)
	group.DELETE("/:category/:service", httpCacheHandler)
}

// setupWebAuthnEndpoints is a function that sets up the endpoints related to WebAuthn in the given Gin router.
// It takes in two parameters:
// - router: a pointer to a gin.Engine instance, which represents the Gin router.
// - sessionStore: an instance of sessions.Store, which is used for session management.
// This function creates a group in the router with the path specified by the constant definitions.TwoFAv1Root.
// Inside this group, it creates another group with the path specified by the configuration value "webauthn_page" retrieved from viper.GetString("webauthn_page").
// It adds a middleware to this sub-group that enables session management using the provided session store.
// It then adds two endpoints to this sub-group:
// - A GET endpoint at the path "/register/begin" which is handled by the beginRegistration function.
// - A POST endpoint at the path "/register/finish" which is handled by the finishRegistration function.
func setupWebAuthnEndpoints(router *gin.Engine, sessionStore sessions.Store) {
	if tags.IsDevelopment {
		group := router.Group(definitions.TwoFAv1Root)

		regGroup := group.Group(viper.GetString("webauthn_page"))
		regGroup.Use(sessions.Sessions(definitions.SessionName, sessionStore))
		regGroup.GET("/register/begin", beginRegistration)
		regGroup.POST("/register/finish", finishRegistration)
	}
}

// waitForShutdown is a function that waits for the context to be done, then shuts down the provided http.Server.
// It takes in two parameters:
// - www: a pointer to the http.Server instance
// - ctx: a context.Context instance
func waitForShutdown(httpServer *http.Server, ctx context.Context) {
	<-ctx.Done()

	waitCtx, cancel := context.WithDeadline(ctx, time.Now().Add(30*time.Second))

	defer cancel()

	httpServer.Shutdown(waitCtx)

	HTTPEndChan <- Done{}
}

// waitForShutdown3 waits for the context to be done and then gracefully closes the http3 server.
//
// It accepts a pointer to an http3.Server and a context.Context as parameters.
// The function waits for the context to be done, which indicates that the server should be shut down.
// It then calls the CloseGracefully method of the http3.Server, with a timeout of 30 seconds,
// to gracefully close the server and release any resources.
// Finally, it sends a Done{} value to the HTTP3EndChan channel to notify that the server has shut down.
func waitForShutdown3(http3Server *http3.Server, ctx context.Context) {
	<-ctx.Done()

	http3Server.Close()

	HTTP3EndChan <- Done{}
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

// serveHTTP serves HTTP requests using the provided http.Server.
//
// The function accepts an http.Server pointer, a certFile string representing the path to
// the TLS certificate file, a keyFile string representing the path to the TLS key file,
// and a proxyListener pointer to a proxyproto.Listener.
//
// If TLS is enabled in the configuration and proxyListener is set to nil, the function
// calls httpServer.ListenAndServeTLS with certFile and keyFile as parameters. If an error
// occurs during server startup and the error is not http.ErrServerClosed, the function logs
// the error and exits the program with a status code of 1 using the logAndExit function.
//
// If TLS is enabled in the configuration and proxyListener is not nil, the function calls
// httpServer.ServeTLS with proxyListener, certFile, and keyFile as parameters. If an error
// occurs during server startup and the error is not http.ErrServerClosed, the function logs
// the error and exits the program with a status code of 1 using the logAndExit function.
//
// If TLS is not enabled in the configuration and proxyListener is set to nil, the function
// calls httpServer.ListenAndServe. If an error occurs during server startup and the error is
// not http.ErrServerClosed, the function logs the error and exits the program with a status
// code of 1 using the logAndExit function.
//
// If TLS is not enabled in the configuration and proxyListener is not nil, the function calls
// httpServer.Serve with proxyListener as a parameter. If an error occurs during server startup
// and the error is not http.ErrServerClosed, the function logs the error and exits the program
// with a status code of 1 using the logAndExit function.
func serveHTTP(httpServer *http.Server, certFile, keyFile string, proxyListener *proxyproto.Listener) {
	if config.LoadableConfig.Server.TLS.Enabled {
		if proxyListener == nil {
			if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
				logAndExit("HTTP/1.1 and HTTP/2 server error", err)
			}
		} else {
			logProxyHTTP3()

			if err := httpServer.ServeTLS(proxyListener, certFile, keyFile); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
				logAndExit("HTTP/1.1 and HTTP/2 server error", err)
			}
		}
	} else {
		if proxyListener == nil {
			if err := httpServer.ListenAndServe(); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
				logAndExit("HTTP/1.1 and HTTP/2 server error", err)
			}
		} else {
			if err := httpServer.Serve(proxyListener); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
				logAndExit("HTTP/1.1 and HTTP/2 server error", err)
			}
		}
	}
}

// logProxyHTTP3 is a function that checks if the HTTP/3 server is enabled and the HAproxy is turned on.
// If both conditions are true, it logs a warning message using the Warn level of the logger provided in the log package.
// The warning message indicates that PROXY protocol is not available for HTTP/3.
func logProxyHTTP3() {
	if config.LoadableConfig.Server.HTTP3 && config.LoadableConfig.Server.HAproxyV2 {
		level.Warn(log.Logger).Log(definitions.LogKeyMsg, "PROXY protocol not supported for HTTP/3")
	}
}

// serveHTTPAndHTTP3 serves both HTTP/1.1 and HTTP/3 requests.
//
// It starts an HTTP/1.1 and HTTP/2 server in a goroutine using the provided http.Server with TLS configuration
// specified by the certFile and keyFile parameters. If an error occurs during server start-up, it logs the error
// and exits the program with a status code of 1.
//
// It also starts an HTTP/3 server using the provided http.Server with HTTP/2 handler, TLS configuration
// specified by the certFile and keyFile parameters, and QUIC configuration. If an error occurs during server start-up,
// it returns the error.
//
// The function returns an error indicating whether the HTTP/3 server started successfully.
// If the HTTP/3 server failed to start, the error will be returned.
// Otherwise, nil is returned.
func serveHTTPAndHTTP3(ctx context.Context, httpServer *http.Server, certFile, keyFile string, proxyListener *proxyproto.Listener) {
	if config.LoadableConfig.Server.HTTP3 {
		go serveHTTP(httpServer, certFile, keyFile, proxyListener)

		http3Server := &http3.Server{
			Addr:       httpServer.Addr,
			Handler:    httpServer.Handler,
			TLSConfig:  httpServer.TLSConfig,
			QUICConfig: &quic.Config{},
		}

		go waitForShutdown3(http3Server, ctx)

		if err := http3Server.ListenAndServeTLS(certFile, keyFile); err != nil && !stderrors.Is(err, http.ErrServerClosed) {
			logAndExit("HTTP/3 server error", err)
		}
	} else {
		serveHTTP(httpServer, certFile, keyFile, proxyListener)
	}
}

// setupGinLoggers sets up the loggers for the Gin framework.
//
// It assigns a custom writer to the default Gin writer and error writer.
// The custom writer logs data based on a specified log level.
// If the log level is set to Debug, the data is logged at the Debug level.
// If the log level is set to Error, the data is logged at the Error level.
// For any other log level value, the data is logged normally at the Info level.
//
// If the log level specified in the configuration is not Debug, it sets the Gin mode to ReleaseMode.
// This disables debug features such as detailed error messages.
//
// It also disables console colors for Gin.
func setupGinLoggers() {
	gin.DefaultWriter = io.MultiWriter(&customWriter{logger: log.Logger, logLevel: level.DebugValue()})
	gin.DefaultErrorWriter = io.MultiWriter(&customWriter{logger: log.Logger, logLevel: level.ErrorValue()})

	if config.LoadableConfig.Server.Log.Level.Level() != definitions.LogLevelDebug {
		gin.SetMode(gin.ReleaseMode)
	}

	gin.DisableConsoleColor()
}

// logAndExit logs an error message and exits the program with a status code of 1.
//
// The function accepts a message string and an error. It logs the message and error using the
// `level.Error` function from the `log.Logger` package. The message is logged using the
// `global.LogKeyMsg` key and the error is logged using the `definitions.LogKeyMsg` key.
//
// After logging the message and error, the function exits the program with a status code of 1
// using the `os.Exit` function.
func logAndExit(message string, err error) {
	level.Error(log.Logger).Log(definitions.LogKeyMsg, message, definitions.LogKeyMsg, err)

	os.Exit(1)
}

// configureTLS returns a new *tls.Config with the NextProtos field set to [h2, http/1.1, h3] and the MinVersion field set to tls.VersionTLS12.
func configureTLS() *tls.Config {
	return &tls.Config{
		NextProtos: []string{"h3", "h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
}

// setupRouter sets up the router for the HTTP server.
//
// It takes in one parameter:
// - router: a pointer to a gin.Engine instance, which represents the Gin router.
//
// This function initializes the necessary middlewares and adds various endpoints to the router for handling different requests.
// The function also sets up session store, Hydra endpoints, static content, and back channel endpoints based on the configuration.
func setupRouter(router *gin.Engine) {
	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	router.Use(gin.Recovery())

	// Add trusted proxies
	router.SetTrustedProxies(viper.GetStringSlice("trusted_proxies"))

	// Add Prometheus middleware
	router.Use(prometheusMiddleware())

	// Prometheus endpoint
	router.GET("/metrics", gin.WrapF(promhttp.Handler().ServeHTTP))

	// Healthcheck
	router.GET("/ping", requestHandler)

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
}

// HTTPApp is a function that starts the HTTP server and sets up the necessary middlewares and endpoints.
// It takes a context.Context parameter.
func HTTPApp(ctx context.Context) {
	var err error

	webAuthn, err = setupWebAuthn()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, "Failed to create WebAuthn from EnvConfig", definitions.LogKeyMsg, err)

		os.Exit(-1)
	}

	setupGinLoggers()

	router := gin.New()

	if config.LoadableConfig.GetServerInsightsEnablePprof() {
		pprof.Register(router)
	}

	limitCounter := NewLimitCounter(config.LoadableConfig.Server.MaxConcurrentRequests)

	router.Use(limitCounter.Middleware())

	// Wrap the GoKit logger
	router.Use(loggerMiddleware())

	httpServer := setupHTTPServer(router)

	setupRouter(router)

	go waitForShutdown(httpServer, ctx)

	proxyListener := prepareHAproxyV2()

	if config.LoadableConfig.Server.TLS.Enabled {
		httpServer.TLSConfig = configureTLS()

		serveHTTPAndHTTP3(ctx, httpServer, config.LoadableConfig.Server.TLS.Cert, config.LoadableConfig.Server.TLS.Key, proxyListener)
	} else {
		serveHTTP(httpServer, config.LoadableConfig.Server.TLS.Cert, config.LoadableConfig.Server.TLS.Key, proxyListener)
	}
}
