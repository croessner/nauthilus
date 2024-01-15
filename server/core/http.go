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
	"github.com/easonlin404/limit"
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

			return
		}

		//nolint:exhaustive // Ignore some results
		switch auth.HandleFeatures(ctx) {
		case decl.AuthResultFeatureTLS:
			auth.PostLuaAction(&PassDBResult{})
			handleErr(ctx, errors2.ErrNoTLS)

			return
		case decl.AuthResultFeatureRelayDomain, decl.AuthResultFeatureRBL, decl.AuthResultFeatureLua:
			auth.PostLuaAction(&PassDBResult{})
			auth.AuthFail(ctx)

			return
		}

		ctx.Next()
	}
}

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

func luaContextMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Set(decl.DataExchangeKey, lualib.NewContext())
	}
}

func HTTPApp(ctx context.Context) {
	var err error

	webAuthn, err = webauthn.New(&webauthn.Config{
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

	sessionStore := cookie.NewStore([]byte(config.LoadableConfig.CookieStoreAuthKey), []byte(config.LoadableConfig.CookieStoreEncKey))
	sessionStore.Options(sessions.Options{
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// Wrap the GoKit logger
	router.Use(loggerMiddleware())

	www := &http.Server{
		Addr:              config.EnvConfig.HTTPAddress,
		Handler:           router,
		IdleTimeout:       time.Minute,
		ReadTimeout:       10 * time.Second, //nolint:gomnd // Ignore
		ReadHeaderTimeout: 10 * time.Second, //nolint:gomnd // Ignore
		WriteTimeout:      30 * time.Second, //nolint:gomnd // Ignore
	}

	go func() {
		<-ctx.Done()

		www.Shutdown(ctx)

		HTTPEndChan <- Done{}

		return
	}()

	// Do not accept HTTP requests above a fixed limit.
	router.Use(limit.Limit(viper.GetInt("max_http_requests")))

	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	router.Use(gin.Recovery())

	// Add trusted proxies
	router.SetTrustedProxies(viper.GetStringSlice("trusted_proxies"))

	// Add Prometheus middleware
	router.Use(func() gin.HandlerFunc {
		return func(ctx *gin.Context) {
			path := ctx.FullPath()

			timer := prometheus.NewTimer(HTTPResponseTimeSecondsHist.WithLabelValues(path))

			ctx.Next()

			HTTPRequestsTotalCounter.WithLabelValues(path).Inc()

			timer.ObserveDuration()
		}
	}())

	// Prometheus endpoint
	router.GET("/metrics", gin.WrapF(promhttp.Handler().ServeHTTP))

	// Healthcheck
	router.GET("/ping", httpQueryHandler)

	// Parse static folder for template files
	router.LoadHTMLGlob(viper.GetString("html_static_content_path") + "/*.html")

	// XXX: Breaks webAuthn!
	// Enable gzip compression
	//router.Use(gzip.Gzip(gzip.DefaultCompression))

	/*
		Ory hydra common known endpoints
	*/

	// This page handles the user login endpoint
	loginRouter := router.Group(viper.GetString("login_page"), adapter.Wrap(nosurf.NewPure))
	loginRouter.Use(sessions.Sessions(decl.SessionName, sessionStore))
	loginRouter.GET("/",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		loginGETHandler)
	loginRouter.GET("/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		loginGETHandler)
	loginRouter.POST("/post",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		loginPOSTHandler)
	loginRouter.POST("/post/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		loginPOSTHandler)

	// This page handles the U2F/FIDO2 login endpoint
	deviceRouter := router.Group(viper.GetString("device_page"), adapter.Wrap(nosurf.NewPure))
	deviceRouter.Use(sessions.Sessions(decl.SessionName, sessionStore))
	deviceRouter.GET("/",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		deviceGETHandler)
	deviceRouter.GET("/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		deviceGETHandler)
	deviceRouter.POST("/post",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		devicePOSTHandler)
	deviceRouter.POST("/post/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		devicePOSTHandler)

	// This page handles the user consent endpoint
	consentRouter := router.Group(viper.GetString("consent_page"), adapter.Wrap(nosurf.NewPure))
	consentRouter.Use(sessions.Sessions(decl.SessionName, sessionStore))
	consentRouter.GET("/",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		consentGETHandler)
	consentRouter.GET("/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		consentGETHandler)
	consentRouter.POST("/post",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		consentPOSTHandler)
	consentRouter.POST("/post/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		consentPOSTHandler)

	// This page handles the user logout endpoint
	logoutRouter := router.Group(viper.GetString("logout_page"), adapter.Wrap(nosurf.NewPure))
	logoutRouter.Use(sessions.Sessions(decl.SessionName, sessionStore))
	logoutRouter.GET("/",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		logoutGETHandler)
	logoutRouter.GET("/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		logoutGETHandler)
	logoutRouter.POST("/post",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		logoutPOSTHandler)
	logoutRouter.POST("/post/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		logoutPOSTHandler)

	/*
		Front channel user endpoints for 2FA
	*/

	twoFARootRouter := router.Group(decl.TwoFAv1Root, adapter.Wrap(nosurf.NewPure))

	// This page handles the user login request to do a two-factor authentication
	twoFactorRouter := twoFARootRouter.Group(viper.GetString("login_2fa_page"), adapter.Wrap(nosurf.NewPure))
	twoFactorRouter.Use(sessions.Sessions(decl.SessionName, sessionStore))
	twoFactorRouter.GET("/",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		loginGET2FAHandler)
	twoFactorRouter.GET(":languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		loginGET2FAHandler)
	twoFactorRouter.POST("/post",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		loginPOST2FAHandler)
	twoFactorRouter.POST("/post/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		loginPOST2FAHandler)
	twoFactorRouter.GET("/home",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		register2FAHomeHandler)
	twoFactorRouter.GET("/home/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		register2FAHomeHandler)

	// This page handles the TOTP registration
	registerTotpRouter := twoFARootRouter.Group(viper.GetString("totp_page"), adapter.Wrap(nosurf.NewPure))
	registerTotpRouter.Use(sessions.Sessions(decl.SessionName, sessionStore))
	registerTotpRouter.GET("/",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		registerTotpGETHandler)
	registerTotpRouter.GET("/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		registerTotpGETHandler)
	registerTotpRouter.POST("/post",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		registerTotpPOSTHandler)
	registerTotpRouter.POST("/post/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		registerTotpPOSTHandler)

	/*
		WebAuthn
	*/

	webAuthnRootRouter := router.Group(decl.TwoFAv1Root)

	registerWebAuthnRouter := webAuthnRootRouter.Group(viper.GetString("webauthn_page"))
	registerWebAuthnRouter.Use(sessions.Sessions(decl.SessionName, sessionStore))
	registerWebAuthnRouter.GET("/register/begin", beginRegistration)
	registerWebAuthnRouter.POST("/register/finish", finishRegistration)

	/*
		Global static content
	*/

	// Serve CSS, JS and IMG files
	router.StaticFile("/favicon.ico", viper.GetString("html_static_content_path")+"/img/favicon.ico")
	router.Static("/static/css", viper.GetString("html_static_content_path")+"/css")
	router.Static("/static/js", viper.GetString("html_static_content_path")+"/js")
	router.Static("/static/img", viper.GetString("html_static_content_path")+"/img")
	router.Static("/static/fonts", viper.GetString("html_static_content_path")+"/fonts")

	/*
		Error message and user information
	*/

	notifyRouter := router.Group(viper.GetString("notify_page"))
	notifyRouter.Use(sessions.Sessions(decl.SessionName, sessionStore))
	notifyRouter.GET("/",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		notifyGETHandler)
	notifyRouter.GET("/:languageTag",
		luaContextMiddleware(),
		protectEndpointMiddleware(),
		withLanguageMiddleware(),
		notifyGETHandler)

	/*
		Back channel endpoints
	*/

	apiV1 := router.Group("/api/v1")

	if config.EnvConfig.HTTPOptions.UseBasicAuth {
		apiV1.Use(basicAuthMiddleware())
	}

	apiV1.GET("/:category/:service", luaContextMiddleware(), httpQueryHandler)
	apiV1.POST("/:category/:service", luaContextMiddleware(), httpQueryHandler)
	apiV1.DELETE("/:category/:service", httpCacheHandler)

	www.SetKeepAlivesEnabled(false)

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
