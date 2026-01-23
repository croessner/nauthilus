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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	mdlimit "github.com/croessner/nauthilus/server/middleware/limit"
	mdlog "github.com/croessner/nauthilus/server/middleware/logging"
	"github.com/croessner/nauthilus/server/monitoring"
	"github.com/croessner/nauthilus/server/rediscli"
	approuter "github.com/croessner/nauthilus/server/router"

	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/pires/go-proxyproto"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"golang.org/x/net/http2"
)

type HTTPDeps struct {
	Cfg          config.File
	Logger       *slog.Logger
	Env          config.Environment
	Redis        rediscli.Client
	AccountCache *accountcache.Manager
}

// DefaultBootstrap wires the existing bootstrapping functions.
type DefaultBootstrap struct {
	cfg          config.File
	logger       *slog.Logger
	env          config.Environment
	redis        rediscli.Client
	accountCache *accountcache.Manager
}

func NewDefaultBootstrap(deps HTTPDeps) DefaultBootstrap {
	return DefaultBootstrap{cfg: deps.Cfg, logger: deps.Logger, env: deps.Env, redis: deps.Redis, accountCache: deps.AccountCache}
}

// InitSessionStore creates and returns the secure cookie-backed Gin session store
// with secure defaults (Secure, SameSite=Strict). The caller is responsible for
// registering the sessions middleware with Gin.

func (b DefaultBootstrap) InitSessionStore() sessions.Store {
	store := cookie.NewStore(
		[]byte(b.cfg.GetServer().Frontend.CookieStoreAuthKey),
		[]byte(b.cfg.GetServer().Frontend.CookieStoreEncKey),
	)
	store.Options(sessions.Options{
		Path:     "/",
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	return store
}

// InitGinLogging configures Gin's writers to use the project's logger and sets
// Gin mode (release/debug) and color output based on configuration.
func (b DefaultBootstrap) InitGinLogging() {
	gin.DefaultWriter = io.MultiWriter(&customWriter{logger: b.logger, lvl: slog.LevelDebug})
	gin.DefaultErrorWriter = io.MultiWriter(&customWriter{logger: b.logger, lvl: slog.LevelError})

	if b.cfg.GetServer().GetLog().GetLogLevel() != definitions.LogLevelDebug {
		gin.SetMode(gin.ReleaseMode)
	}

	gin.DisableConsoleColor()
}

// DefaultRouterComposer builds the gin.Engine and registers routes/middlewares in the exact order.
type DefaultRouterComposer struct {
	cfg          config.File
	logger       *slog.Logger
	env          config.Environment
	redis        rediscli.Client
	accountCache *accountcache.Manager
}

func NewDefaultRouterComposer(deps HTTPDeps) DefaultRouterComposer {
	return DefaultRouterComposer{cfg: deps.Cfg, logger: deps.Logger, env: deps.Env, redis: deps.Redis, accountCache: deps.AccountCache}
}

// ComposeEngine creates a fresh gin.Engine without any default middleware.
// This mirrors the legacy code which constructed the engine explicitly and
// enables ContextWithFallback so gin.Context behaves consistently as a
// context.Context with respect to Deadline/Done/Err/Value fallbacks.
func (c DefaultRouterComposer) ComposeEngine() *gin.Engine {
	mdauth.SetProtectMiddleware(func(cfg config.File, logger *slog.Logger) gin.HandlerFunc {
		return ProtectEndpointMiddleware(cfg, logger)
	})

	return gin.New(func(e *gin.Engine) {
		e.ContextWithFallback = true
	})
}

// ApplyEarlyMiddlewares registers pprof (if enabled), the concurrency limiter,
// and the structured logging middleware. The order is preserved as in the legacy code.
func (c DefaultRouterComposer) ApplyEarlyMiddlewares(r *gin.Engine) {
	if c.cfg.GetServer().GetInsights().IsPprofEnabled() {
		pprof.Register(r)
	}

	mw := c.cfg.GetServer().GetMiddlewares()

	if mw.IsLimitEnabled() {
		limitCounter := mdlimit.NewLimitCounter(c.cfg.GetServer().GetMaxConcurrentRequests())

		r.Use(limitCounter.MiddlewareWithLogger(c.logger))
	}

	if mw.IsRateEnabled() {
		rateLimiter := mdlimit.NewIPRateLimiter(
			mdlimit.Rate(c.cfg.GetServer().GetRateLimitPerSecond()),
			c.cfg.GetServer().GetRateLimitBurst(),
		)

		r.Use(rateLimiter.Middleware())
	}

	// Tracing middleware (OpenTelemetry) – enabled if insights.tracing.enable is true
	// and not disabled via server.disabled_endpoints.tracing
	if c.cfg.GetServer().GetInsights().IsTracingEnabled() {
		tr := c.cfg.GetServer().GetInsights().GetTracing()

		service := monitoring.ResolveServiceName(tr.GetServiceName(), c.cfg.GetServer().GetInstanceName(), "nauthilus-server")

		// Attach OpenTelemetry Gin middleware with explicit provider/propagators and a
		// stable span name formatter (METHOD + route pattern) to simplify querying.
		r.Use(otelgin.Middleware(
			service,
			otelgin.WithTracerProvider(otel.GetTracerProvider()),
			otelgin.WithPropagators(otel.GetTextMapPropagator()),
			otelgin.WithSpanNameFormatter(func(c *gin.Context) string {
				path := c.FullPath()
				if path == "" {
					path = c.Request.URL.Path
				}

				return c.Request.Method + " " + path
			}),
		))

		// Log explicitly that the Gin OpenTelemetry middleware has been attached.
		// This helps diagnose situations where server spans are not visible in the backend.
		level.Info(c.logger).Log(
			definitions.LogKeyMsg, "Gin OpenTelemetry tracing middleware attached",
			"service", service,
		)
	}

	if mw.IsLoggingEnabled() {
		r.Use(mdlog.LoggerMiddlewareWithLogger(c.logger))
	}
}

// ApplyCoreMiddlewares configures the router builder to add recovery, trusted
// proxies, request decompression, response compression, and metrics middleware
// in the same order as before.
func (c DefaultRouterComposer) ApplyCoreMiddlewares(r *gin.Engine) {
	rb := approuter.NewRouter(c.cfg)
	rb.Engine = r

	mw := c.cfg.GetServer().GetMiddlewares()

	if mw.IsRecoveryEnabled() {
		rb.WithRecovery()
	}

	if mw.IsTrustedProxiesEnabled() {
		rb.WithTrustedProxies()
	}

	if mw.IsRequestDecompressionEnabled() {
		rb.WithRequestDecompression()
	}

	if mw.IsResponseCompressionEnabled() {
		rb.WithResponseCompression()
	}

	if mw.IsMetricsEnabled() {
		rb.WithMetricsMiddleware()
	}
}

// RegisterRoutes wires health and metrics routes, then (if enabled) the frontend
// routes (Hydra, 2FA, WebAuthn, Notify) and finally the backchannel routes. The
// order is kept to preserve exact behavior of the legacy implementation.
func (c DefaultRouterComposer) RegisterRoutes(r *gin.Engine,
	setupHealth func(*gin.Engine),
	setupMetrics func(*gin.Engine),
	setupHydra func(*gin.Engine),
	setup2FA func(*gin.Engine),
	setupWebAuthn func(*gin.Engine),
	setupNotify func(*gin.Engine),
	setupIdP func(*gin.Engine),
	setupBackchannel func(*gin.Engine),
) {
	if setupHealth != nil {
		setupHealth(r)
	}

	if setupMetrics != nil {
		setupMetrics(r)
	}

	if c.cfg.GetServer().Frontend.Enabled {
		r.LoadHTMLGlob(c.cfg.GetServer().Frontend.GetHTMLStaticContentPath() + "/*.html")

		rb := approuter.NewRouter(c.cfg)
		rb.Engine = r

		rb.WithFrontend(setupHydra, setup2FA, setupWebAuthn, setupNotify, setupIdP)
	}

	rb := approuter.NewRouter(c.cfg)
	rb.Engine = r

	rb.WithBackchannel(setupBackchannel)
}

// DefaultHTTPServerFactory builds http.Server and configures HTTP/2 settings.
type DefaultHTTPServerFactory struct {
	cfg    config.File
	logger *slog.Logger
	env    config.Environment
	redis  rediscli.Client
}

func NewDefaultHTTPServerFactory(deps HTTPDeps) DefaultHTTPServerFactory {
	return DefaultHTTPServerFactory{cfg: deps.Cfg, logger: deps.Logger, env: deps.Env, redis: deps.Redis}
}

// New constructs a configured *http.Server* with HTTP/2 enabled and sensible
// timeouts. Idle timeout honors the configured keep-alive settings.
func (f DefaultHTTPServerFactory) New(router *gin.Engine) *http.Server {
	keepAliveConfig := f.cfg.GetServer().GetKeepAlive()

	idleTimeout := time.Minute
	if keepAliveConfig.IsEnabled() && keepAliveConfig.GetTimeout() > 0 {
		idleTimeout = keepAliveConfig.GetTimeout()
	}

	// Custom HTTP/2 server with optimized settings
	h2Server := &http2.Server{
		MaxConcurrentStreams: 250,
		MaxReadFrameSize:     1 << 20, // 1MB
		IdleTimeout:          idleTimeout,
	}

	srv := &http.Server{
		Addr:              f.cfg.GetServer().Address,
		Handler:           router,
		IdleTimeout:       idleTimeout,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	if err := http2.ConfigureServer(srv, h2Server); err != nil {
		level.Error(f.logger).Log(
			definitions.LogKeyMsg, "Failed to configure HTTP/2 server",
			definitions.LogKeyError, err,
		)
	} else {
		level.Info(f.logger).Log(
			definitions.LogKeyMsg, "HTTP/2 server configured successfully",
		)
	}

	return srv
}

// HAProxyListenerProvider provides PROXY v2 listener when enabled.
type HAProxyListenerProvider struct {
	cfg    config.File
	logger *slog.Logger
	env    config.Environment
	redis  rediscli.Client
}

func NewHAProxyListenerProvider(deps HTTPDeps) HAProxyListenerProvider {
	return HAProxyListenerProvider{cfg: deps.Cfg, logger: deps.Logger, env: deps.Env, redis: deps.Redis}
}

// Get returns a PROXY v2 aware listener if the feature is enabled in the
// configuration, otherwise it returns nil.
func (p HAProxyListenerProvider) Get() *proxyproto.Listener {
	if !p.cfg.GetServer().IsHAproxyProtocolEnabled() {
		return nil
	}

	listener, err := net.Listen("tcp", p.cfg.GetServer().GetListenAddress())
	if err != nil {
		panic(err)
	}

	return &proxyproto.Listener{
		Listener: listener,
		ConnPolicy: func(connPolicyOptions proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}
}

// DefaultTLSConfigurator constructs tls.Config according to settings.
type DefaultTLSConfigurator struct {
	cfg    config.File
	logger *slog.Logger
	env    config.Environment
	redis  rediscli.Client
}

func NewDefaultTLSConfigurator(deps HTTPDeps) DefaultTLSConfigurator {
	return DefaultTLSConfigurator{cfg: deps.Cfg, logger: deps.Logger, env: deps.Env, redis: deps.Redis}
}

// Build assembles a *tls.Config* honoring configured CA, cipher suites,
// minimum TLS version, NextProtos, and InsecureSkipVerify. If a CA is set,
// it is used for both RootCAs and optional client verification (VerifyClientCertIfGiven).
func (c DefaultTLSConfigurator) Build() *tls.Config {
	if !c.cfg.GetServer().GetTLS().IsEnabled() {
		return nil
	}

	var caCertPool *x509.CertPool
	var cipherSuites []uint16
	var minTLSVersion uint16

	if c.cfg.GetServer().GetTLS().GetCAFile() != "" {
		caCert, err := os.ReadFile(c.cfg.GetServer().GetTLS().GetCAFile())
		if err != nil {
			logAndExit(c.logger, "Failed to read CA certificate", err)
		}

		caCertPool = x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			logAndExit(c.logger, "Failed to parse CA certificate", err)
		}
	}

	tlsVersionMap := map[string]uint16{
		"TLS1.2": tls.VersionTLS12,
		"TLS1.3": tls.VersionTLS13,
	}

	if tlsVersion, exists := tlsVersionMap[c.cfg.GetServer().GetTLS().GetMinTLSVersion()]; exists {
		minTLSVersion = tlsVersion
	} else {
		minTLSVersion = tls.VersionTLS12
	}

	cipherMap := map[string]uint16{
		"TLS_AES_128_GCM_SHA256":                  tls.TLS_AES_128_GCM_SHA256,
		"TLS_AES_256_GCM_SHA384":                  tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256":            tls.TLS_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	preferredCiphers := []string{
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"TLS_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}

	if len(c.cfg.GetServer().GetTLS().GetCipherSuites()) > 0 {
		preferredCiphers = c.cfg.GetServer().GetTLS().GetCipherSuites()
	}

	for _, cipherString := range preferredCiphers {
		if cipher, exists := cipherMap[cipherString]; exists {
			cipherSuites = append(cipherSuites, cipher)
		} else {
			level.Warn(c.logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Cipher suite %s not found", cipherString))
		}
	}

	tlsConfig := &tls.Config{
		NextProtos:         []string{"h3", "h2", "http/1.1"},
		MinVersion:         minTLSVersion,
		RootCAs:            caCertPool,
		CipherSuites:       cipherSuites,
		InsecureSkipVerify: c.cfg.GetServer().GetTLS().GetSkipVerify(),
	}

	if caCertPool != nil {
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return tlsConfig
}

// DefaultServerSignals provides default channels for HTTP and HTTP/3 lifecycle notifications.
type DefaultServerSignals struct {
	httpDone  chan Done
	http3Done chan Done
}

// NewDefaultServerSignals creates a ServerSignals implementation. If enableHTTP3
// is true, the HTTP/3 done channel will be created as well.
func NewDefaultServerSignals(enableHTTP3 bool) *DefaultServerSignals {
	// Buffered channels avoid shutdown goroutines blocking indefinitely if no receiver
	// is currently waiting for the signal (e.g. restart timeouts or reordered stop hooks).
	s := &DefaultServerSignals{httpDone: make(chan Done, 1)}

	if enableHTTP3 {
		s.http3Done = make(chan Done, 1)
	}

	return s
}

// HTTPDone returns the channel that signals completion of the HTTP/1.1+2
// server lifecycle (graceful shutdown finished).
func (s *DefaultServerSignals) HTTPDone() chan Done {
	return s.httpDone
}

// HTTP3Done returns the channel that signals completion of the HTTP/3 server
// lifecycle (graceful shutdown finished). It may be nil if HTTP/3 is disabled.
func (s *DefaultServerSignals) HTTP3Done() chan Done {
	return s.http3Done
}

// DefaultTransportRunner starts HTTP/1.1+2 and optional HTTP/3, with graceful shutdown.
type DefaultTransportRunner struct {
	cfg    config.File
	logger *slog.Logger
	env    config.Environment
	redis  rediscli.Client
}

func NewDefaultTransportRunner(deps HTTPDeps) DefaultTransportRunner {
	return DefaultTransportRunner{cfg: deps.Cfg, logger: deps.Logger, env: deps.Env, redis: deps.Redis}
}

// Serve launches the HTTP/1.1+2 server (and optionally HTTP/3) and manages
// graceful shutdown on context cancellation. Termination signals are forwarded
// via the provided ServerSignals implementation to decouple consumers from globals.
func (r DefaultTransportRunner) Serve(ctx context.Context, srv *http.Server, certFile, keyFile string, proxy *proxyproto.Listener, signals ServerSignals) {
	// Graceful shutdown for HTTP/1.1/2
	go func() {
		<-ctx.Done()

		// Do not derive the shutdown context from ctx: ctx is already canceled here and would
		// make the shutdown deadline immediately expire, preventing the listener from closing.
		waitCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		_ = srv.Shutdown(waitCtx)

		if signals != nil && signals.HTTPDone() != nil {
			select {
			case signals.HTTPDone() <- Done{}:
			default:
			}
		}
	}()

	if r.cfg.GetServer().IsHTTP3Enabled() {
		// Serve HTTP/1.1+2 concurrently
		go func() {
			serveHTTPInternal(r.logger, srv, certFile, keyFile, proxy, r.cfg.GetServer().GetTLS().IsEnabled())
		}()

		h3 := &http3.Server{
			Addr:       srv.Addr,
			Handler:    srv.Handler,
			TLSConfig:  srv.TLSConfig,
			QUICConfig: &quic.Config{},
		}

		go func() {
			<-ctx.Done()

			_ = h3.Close()

			if signals != nil && signals.HTTP3Done() != nil {
				select {
				case signals.HTTP3Done() <- Done{}:
				default:
				}
			}
		}()

		if err := h3.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logAndExit(r.logger, "HTTP/3 server error", err)
		}

		return
	}

	// Only HTTP/1.1+2
	serveHTTPInternal(r.logger, srv, certFile, keyFile, proxy, r.cfg.GetServer().GetTLS().IsEnabled())
}

// serveHTTPInternal runs the HTTP/1.1+2 stack either directly on the TCP listener
// or on the provided PROXY v2 listener. When TLS is enabled, it uses the given
// certificate and key files.
func serveHTTPInternal(logger *slog.Logger, srv *http.Server, certFile, keyFile string, proxy *proxyproto.Listener, tlsEnabled bool) {
	if tlsEnabled {
		if proxy == nil {
			if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logAndExit(logger, "HTTP/1.1 and HTTP/2 server error", err)
			}
		} else {
			if err := srv.ServeTLS(proxy, certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logAndExit(logger, "HTTP/1.1 and HTTP/2 server error", err)
			}
		}

		return
	}

	if proxy == nil {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logAndExit(logger, "HTTP/1.1 and HTTP/2 server error", err)
		}
	} else {
		if err := srv.Serve(proxy); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logAndExit(logger, "HTTP/1.1 and HTTP/2 server error", err)
		}
	}
}

// DefaultHTTPApp orchestrates all components and preserves exact behavior.
type DefaultHTTPApp struct {
	cfg    config.File
	logger *slog.Logger
	env    config.Environment
	redis  rediscli.Client

	Bootstrap         Bootstrap
	RouterComposer    RouterComposer
	HTTPServerFactory HTTPServerFactory
	ProxyProvider     ProxyListenerProvider
	TLSConfigurator   TLSConfigurator
	TransportRunner   TransportRunner
}

// NewDefaultHTTPApp constructs the default HTTP application facade that wires
// together the default implementations for bootstrapping, router composition,
// server factory, proxy listener provider, TLS configuration, and transport runner.
func NewDefaultHTTPApp(deps HTTPDeps) *DefaultHTTPApp {
	return &DefaultHTTPApp{
		cfg:    deps.Cfg,
		logger: deps.Logger,
		env:    deps.Env,
		redis:  deps.Redis,

		Bootstrap:         NewDefaultBootstrap(deps),
		RouterComposer:    NewDefaultRouterComposer(deps),
		HTTPServerFactory: NewDefaultHTTPServerFactory(deps),
		ProxyProvider:     NewHAProxyListenerProvider(deps),
		TLSConfigurator:   NewDefaultTLSConfigurator(deps),
		TransportRunner:   NewDefaultTransportRunner(deps),
	}
}

// Start bootstraps dependencies (WebAuthn, Gin logging, sessions), composes
// the Gin engine, registers routes via the provided callbacks, builds the HTTP
// server (incl. HTTP/2), configures TLS if enabled, prepares optional PROXY v2,
// and finally hands off to the TransportRunner to serve traffic.
//
// The setup* callbacks are optional; if non-nil, they are invoked to register
// respective routes on the engine. Signals are used to decouple shutdown
// coordination from global channels.
func (a *DefaultHTTPApp) Start(ctx context.Context,
	setupHealth func(*gin.Engine),
	setupMetrics func(*gin.Engine),
	setupHydra func(*gin.Engine),
	setup2FA func(*gin.Engine),
	setupWebAuthn func(*gin.Engine),
	setupNotify func(*gin.Engine),
	setupIdP func(*gin.Engine),
	setupBackchannel func(*gin.Engine),
	signals ServerSignals,
) {
	// Keep auth protect middleware as before
	mdauth.SetProtectMiddleware(func(cfg config.File, logger *slog.Logger) gin.HandlerFunc {
		return ProtectEndpointMiddleware(cfg, logger)
	})

	if err := a.Bootstrap.InitWebAuthn(); err != nil {
		// The legacy code exits on error; keep that behavior
		os.Exit(-1)

		return
	}

	a.Bootstrap.InitGinLogging()
	_ = a.Bootstrap.InitSessionStore()

	router := a.RouterComposer.ComposeEngine()
	a.RouterComposer.ApplyEarlyMiddlewares(router)

	// Create server before applying the router builder so address/timeouts are set early (parity with old code)
	srv := a.HTTPServerFactory.New(router)

	a.RouterComposer.ApplyCoreMiddlewares(router)
	a.RouterComposer.RegisterRoutes(router, setupHealth, setupMetrics, setupHydra, setup2FA, setupWebAuthn, setupNotify, setupIdP, setupBackchannel)

	proxy := a.ProxyProvider.Get()
	if proxy != nil {
		logProxyHTTP3(a.cfg, a.logger)
	}

	var cert, key string
	if a.cfg.GetServer().GetTLS().IsEnabled() {
		srv.TLSConfig = a.TLSConfigurator.Build()
		cert = a.cfg.GetServer().GetTLS().GetCert()
		key = a.cfg.GetServer().GetTLS().GetKey()
	}

	a.TransportRunner.Serve(ctx, srv, cert, key, proxy, signals)
}

// Helper: customWriter logs Gin output using slog at configured level via the wrapper.
type customWriter struct {
	logger *slog.Logger
	lvl    slog.Level
}

// Write satisfies io.Writer and forwards Gin logs to the project's structured
// logger at the configured level.
func (w *customWriter) Write(data []byte) (int, error) {
	switch w.lvl {
	case slog.LevelDebug:
		_ = level.Debug(w.logger).Log(definitions.LogKeyMsg, string(data))
	case slog.LevelError:
		_ = level.Error(w.logger).Log(
			definitions.LogKeyMsg, "Gin error",
			definitions.LogKeyError, string(data),
		)
	default:
		_ = level.Info(w.logger).Log(definitions.LogKeyMsg, string(data))
	}

	return len(data), nil
}

// Helper: log and exit with code 1 (preserves legacy behavior)
func logAndExit(logger *slog.Logger, message string, err error) {
	level.Error(logger).Log(
		definitions.LogKeyMsg, message,
		definitions.LogKeyMsg, "Exiting",
		definitions.LogKeyError, err,
	)
	os.Exit(1)
}

// Helper: warn about PROXY protocol + HTTP/3 unsupported combination.
func logProxyHTTP3(cfg config.File, logger *slog.Logger) {
	if cfg.GetServer().IsHTTP3Enabled() && cfg.GetServer().IsHAproxyProtocolEnabled() {
		level.Warn(logger).Log(definitions.LogKeyMsg, "PROXY protocol not supported for HTTP/3")
	}
}
