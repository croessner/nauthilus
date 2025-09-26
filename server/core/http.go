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
	"crypto/tls"
	"crypto/x509"
	stderrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"

	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	mdlimit "github.com/croessner/nauthilus/server/middleware/limit"
	mdlog "github.com/croessner/nauthilus/server/middleware/logging"
	approuter "github.com/croessner/nauthilus/server/router"

	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/pires/go-proxyproto"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/spf13/viper"
	"golang.org/x/net/http2"
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

// customWriter represents a type that logs data based on a specified log level.
type customWriter struct {
	// logger represents a logger instance and is used for all messages that are printed to stdout.
	logger kitlog.Logger

	// logLevel specifies the log level for the customWriter, determining how log messages are categorized and filtered.
	logLevel level.Value
}

// Write logs the provided data using the logger at the specified log level and returns the number of bytes written or an error.
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

// initWebAuthn initializes and returns a new WebAuthn instance configured with values from the environment.
func initWebAuthn() (*webauthn.WebAuthn, error) {
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

// SetupSessionStore initializes and returns a session store configured with cookie-based storage and security options.
func SetupSessionStore() sessions.Store {
	sessionStore := cookie.NewStore([]byte(config.GetFile().GetServer().Frontend.CookieStoreAuthKey), []byte(config.GetFile().GetServer().Frontend.CookieStoreEncKey))
	sessionStore.Options(sessions.Options{
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	return sessionStore
}

// setupHTTPServer initializes an HTTP server with the given router and configures custom HTTP/2 settings.
// It uses keep-alive settings and returns the configured HTTP server instance.
func setupHTTPServer(router *gin.Engine) *http.Server {
	keepAliveConfig := config.GetFile().GetServer().GetKeepAlive()

	idleTimeout := time.Minute
	if keepAliveConfig.IsEnabled() && keepAliveConfig.GetTimeout() > 0 {
		idleTimeout = keepAliveConfig.GetTimeout()
	}

	// Create a custom HTTP/2 server with optimized settings
	h2Server := &http2.Server{
		// MaxConcurrentStreams limits the number of concurrent streams per connection
		MaxConcurrentStreams: 250,

		// MaxReadFrameSize increases the maximum frame size
		MaxReadFrameSize: 1 << 20, // 1MB

		// IdleTimeout sets how long until idle clients should be closed
		IdleTimeout: idleTimeout,
	}

	server := &http.Server{
		Addr:              config.GetFile().GetServer().Address,
		Handler:           router,
		IdleTimeout:       idleTimeout,
		ReadTimeout:       10 * time.Second, //nolint:gomnd // Ignore
		ReadHeaderTimeout: 10 * time.Second, //nolint:gomnd // Ignore
		WriteTimeout:      30 * time.Second, //nolint:gomnd // Ignore
	}

	// Configure HTTP/2 server
	if err := http2.ConfigureServer(server, h2Server); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, "Failed to configure HTTP/2 server",
			"error", err,
		)
	} else {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "HTTP/2 server configured successfully",
		)
	}

	return server
}

// waitForShutdown gracefully shuts down the HTTP server when the given context is canceled or deadline expires.
func waitForShutdown(httpServer *http.Server, ctx context.Context) {
	<-ctx.Done()

	waitCtx, cancel := context.WithDeadline(ctx, time.Now().Add(30*time.Second))

	defer cancel()

	httpServer.Shutdown(waitCtx)

	HTTPEndChan <- Done{}
}

// waitForShutdown3 gracefully shuts down the given HTTP/3 server when the provided context signals cancellation.
func waitForShutdown3(http3Server *http3.Server, ctx context.Context) {
	<-ctx.Done()

	http3Server.Close()

	HTTP3EndChan <- Done{}
}

// prepareHAproxyV2 initializes and returns a proxyproto.Listener if HAProxy protocol is enabled in the server configuration.
func prepareHAproxyV2() *proxyproto.Listener {
	var (
		listener      net.Listener
		proxyListener *proxyproto.Listener
		err           error
	)

	if config.GetFile().GetServer().IsHAproxyProtocolEnabled() {
		listener, err = net.Listen("tcp", config.GetFile().GetServer().GetListenAddress())
		if err != nil {
			panic(err)
		}

		proxyListener = &proxyproto.Listener{
			Listener: listener,
			ConnPolicy: func(connPolicyOptions proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
				return proxyproto.REQUIRE, nil
			},
		}
	}

	return proxyListener
}

// serveHTTP starts an HTTP or HTTPS server based on the TLS configuration and provided listener.
// It uses the provided http.Server, certificate file, and key file for HTTPS if TLS is enabled.
// If a proxyListener is provided, it serves requests using the specified listener.
// Logs and exits on server errors except for http.ErrServerClosed.
func serveHTTP(httpServer *http.Server, certFile, keyFile string, proxyListener *proxyproto.Listener) {
	if config.GetFile().GetServer().GetTLS().IsEnabled() {
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
	if config.GetFile().GetServer().IsHTTP3Enabled() && config.GetFile().GetServer().IsHAproxyProtocolEnabled() {
		level.Warn(log.Logger).Log(definitions.LogKeyMsg, "PROXY protocol not supported for HTTP/3")
	}
}

// serveHTTPAndHTTP3 serves HTTP and optionally HTTP/3 based on the server configuration.
func serveHTTPAndHTTP3(ctx context.Context, httpServer *http.Server, certFile, keyFile string, proxyListener *proxyproto.Listener) {
	if config.GetFile().GetServer().IsHTTP3Enabled() {
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

// setupGinLoggers configures logging for the Gin framework based on the application's log settings and log level.
func setupGinLoggers() {
	gin.DefaultWriter = io.MultiWriter(&customWriter{logger: log.Logger, logLevel: level.DebugValue()})
	gin.DefaultErrorWriter = io.MultiWriter(&customWriter{logger: log.Logger, logLevel: level.ErrorValue()})

	if config.GetFile().GetServer().GetLog().GetLogLevel() != definitions.LogLevelDebug {
		gin.SetMode(gin.ReleaseMode)
	}

	gin.DisableConsoleColor()
}

// logAndExit logs an error message and exits the program with status code 1.
func logAndExit(message string, err error) {
	level.Error(log.Logger).Log(definitions.LogKeyMsg, message, definitions.LogKeyMsg, err)

	os.Exit(1)
}

// configureTLS returns a new *tls.Config with the NextProtos field set to [h2, http/1.1, h3] and the MinVersion field set to tls.VersionTLS12.
func configureTLS() *tls.Config {
	var caCertPool *x509.CertPool
	var cipherSuites []uint16
	var minTLSVersion uint16

	if config.GetFile().GetServer().GetTLS().GetCAFile() != "" {
		caCert, err := os.ReadFile(config.GetFile().GetServer().GetTLS().GetCAFile())
		if err != nil {
			logAndExit("Failed to read CA certificate", err)
		}

		caCertPool = x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			logAndExit("Failed to parse CA certificate", err)
		}
	}

	var tlsVersionMap = map[string]uint16{
		"TLS1.2": tls.VersionTLS12,
		"TLS1.3": tls.VersionTLS13,
	}

	if tlsVersion, exists := tlsVersionMap[config.GetFile().GetServer().GetTLS().GetMinTLSVersion()]; exists {
		minTLSVersion = tlsVersion
	} else {
		minTLSVersion = tls.VersionTLS12
	}

	var cipherMap = map[string]uint16{
		// TLS 1.3 Cipher Suites
		"TLS_AES_128_GCM_SHA256":       tls.TLS_AES_128_GCM_SHA256,
		"TLS_AES_256_GCM_SHA384":       tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256": tls.TLS_CHACHA20_POLY1305_SHA256,

		// TLS 1.2 Cipher Suites
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	preferredCiphers := []string{
		"TLS_AES_256_GCM_SHA384",                  // TLS 1.3
		"TLS_CHACHA20_POLY1305_SHA256",            // TLS 1.3
		"TLS_AES_128_GCM_SHA256",                  // TLS 1.3
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", // TLS 1.2
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",   // TLS 1.2
	}

	if len(config.GetFile().GetServer().GetTLS().GetCipherSuites()) > 0 {
		preferredCiphers = config.GetFile().GetServer().GetTLS().GetCipherSuites()
	}

	for _, cipherString := range preferredCiphers {
		if cipher, exists := cipherMap[cipherString]; exists {
			cipherSuites = append(cipherSuites, cipher)
		} else {
			level.Warn(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Cipher suite %s not found", cipherString))
		}
	}

	tlsConfig := &tls.Config{
		NextProtos:         []string{"h3", "h2", "http/1.1"},
		MinVersion:         minTLSVersion,
		RootCAs:            caCertPool,
		CipherSuites:       cipherSuites,
		InsecureSkipVerify: config.GetFile().GetServer().GetTLS().GetSkipVerify(),
	}

	if caCertPool != nil {
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return tlsConfig
}

// HTTPApp starts the HTTP server and sets up middlewares and endpoints.
// Frontend and backchannel routes are provided via callbacks to avoid import cycles.
// Health and metrics routes are provided via callbacks to keep core free of handler imports.
func HTTPApp(ctx context.Context, setupHealth func(*gin.Engine), setupMetrics func(*gin.Engine), setupHydra, setup2FA, setupWebAuthn, setupNotify func(*gin.Engine), setupBackchannel func(*gin.Engine)) {
	var err error

	mdauth.SetProtectMiddleware(ProtectEndpointMiddleware)

	webAuthn, err = initWebAuthn()
	if err != nil {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, "Failed to create WebAuthn from environment", definitions.LogKeyMsg, err)

		os.Exit(-1)
	}

	setupGinLoggers()

	router := gin.New()

	if config.GetFile().GetServer().GetInsights().IsPprofEnabled() {
		pprof.Register(router)
	}

	limitCounter := mdlimit.NewLimitCounter(config.GetFile().GetServer().GetMaxConcurrentRequests())

	router.Use(limitCounter.Middleware())

	// Wrap the GoKit logger
	router.Use(mdlog.LoggerMiddleware())

	httpServer := setupHTTPServer(router)

	// Switch to router builder object to assemble middlewares and routes without changing logic
	rbuilder := approuter.NewRouter(config.GetFile())
	// Reuse the created engine so that early middlewares (limit, logger, pprof) stay first
	rbuilder.Engine = router
	// Core middlewares and routes in the same order as before
	rbuilder.
		WithRecovery().
		WithTrustedProxies().
		WithRequestDecompression().
		WithResponseCompression().
		WithMetricsMiddleware()

	// Healthcheck via injected callback
	if setupHealth != nil {
		setupHealth(router)
	}

	// Metrics via injected callback
	if setupMetrics != nil {
		setupMetrics(router)
	}

	// Frontend endpoints
	if config.GetFile().GetServer().Frontend.Enabled {
		// Parse static folder for template files (same as before)
		router.LoadHTMLGlob(viper.GetString("html_static_content_path") + "/*.html")

		// Use provided setup callbacks to register endpoints
		rbuilder.WithFrontend(setupHydra, setup2FA, setupWebAuthn, setupNotify)
	}

	// Backchannel endpoints last
	rbuilder.WithBackchannel(setupBackchannel)

	go waitForShutdown(httpServer, ctx)

	proxyListener := prepareHAproxyV2()

	if config.GetFile().GetServer().GetTLS().IsEnabled() {
		httpServer.TLSConfig = configureTLS()

		serveHTTPAndHTTP3(ctx, httpServer, config.GetFile().GetServer().GetTLS().GetCert(), config.GetFile().GetServer().GetTLS().GetKey(), proxyListener)
	} else {
		serveHTTP(httpServer, config.GetFile().GetServer().GetTLS().GetCert(), config.GetFile().GetServer().GetTLS().GetKey(), proxyListener)
	}
}
