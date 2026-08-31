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

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/app/redifx"
	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/backend/ldappool"
	"github.com/croessner/nauthilus/v4/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	coreauth "github.com/croessner/nauthilus/v4/server/core/auth"
	"github.com/croessner/nauthilus/v4/server/core/cookie"
	"github.com/croessner/nauthilus/v4/server/core/language"
	"github.com/croessner/nauthilus/v4/server/definitions"
	handlerbackchannel "github.com/croessner/nauthilus/v4/server/handler/backchannel"
	handlerdeps "github.com/croessner/nauthilus/v4/server/handler/deps"
	handleridp "github.com/croessner/nauthilus/v4/server/handler/frontend/idp"
	handlerauthority "github.com/croessner/nauthilus/v4/server/handler/grpcauthority"
	handlerhealth "github.com/croessner/nauthilus/v4/server/handler/health"
	handlermetrics "github.com/croessner/nauthilus/v4/server/handler/metrics"
	"github.com/croessner/nauthilus/v4/server/idp"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/lualib/redislib"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/util"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// contextTuple represents a tuple that contains a context and a cancel function.
// This type is used for managing contexts and cancellations in various parts of the application.
type contextTuple struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// contextStore is a struct containing context tuples and injected dependencies for managing application processes.
type contextStore struct {
	ldapLookup *contextTuple
	ldapAuth   *contextTuple
	lua        *contextTuple
	server     *contextTuple

	// cfgProvider provides the current config snapshot for newly migrated code paths.
	cfgProvider configfx.Provider

	// env is the injected environment configuration.
	env config.Environment

	// logger is the injected process logger for newly migrated code paths.
	logger *slog.Logger

	// redisClient is the injected Redis facade for newly migrated code paths.
	redisClient redifx.Client

	// channel is the injected backend channel for newly migrated code paths.
	channel backend.Channel

	// accountCache is the injected account cache manager for newly migrated code paths.
	accountCache *accountcache.Manager

	// policyStore is the sole injected runtime generation authority.
	policyStore *policyruntime.GenerationStore

	// policyDecision is the sole injected service over policyStore.
	policyDecision *decisionservice.DecisionService

	// routeArtifacts owns listener credentials and HTTP-served files parsed before the initial generation commit.
	routeArtifacts *core.RouteArtifacts

	// pluginRunner is the explicitly started process-owned native runtime.
	pluginRunner *pluginruntime.Runner

	// bruteForceTolerate is the explicitly constructed boot-lifetime tolerance owner.
	bruteForceTolerate tolerate.Tolerate

	// signals holds server lifecycle channels via the interface (no globals)
	signals core.ServerSignals

	// grpcAuthorityDone signals completion of the optional gRPC authority server.
	grpcAuthorityDone <-chan struct{}

	// langManager is the injected language manager.
	langManager language.Manager
}

// newContextTuple creates a new contextTuple with a derived context and cancel function from the provided parent context.
// It manages the lifecycle of the derived context and its cancellation.
func newContextTuple(ctx context.Context) *contextTuple {
	tuple := &contextTuple{}
	tuple.ctx, tuple.cancel = context.WithCancel(ctx)

	return tuple
}

// stopContext cancels the context associated with the given contextTuple.
func stopContext(tuple *contextTuple) {
	tuple.cancel()
}

func forEachConfiguredBackendName(cfg config.File, backendType definitions.Backend, fn func(name string)) {
	for _, configuredBackend := range cfg.GetServer().GetBackends() {
		if configuredBackend.GetName() != "" && configuredBackend.Get() != backendType {
			continue
		}

		backendName := configuredBackend.GetName()
		if backendName == "" {
			backendName = definitions.DefaultBackendName
		}

		fn(backendName)
	}
}

// startLDAPWorkers initializes and starts LDAP worker routines for lookup and authentication based on the configuration.
// It launches the `LDAPMainWorker` for processing LDAP requests and, if applicable, `LDAPAuthWorker` for authentication.
func startLDAPWorkers(store *contextStore, cfg config.File, logger *slog.Logger, channel backend.Channel) {
	forEachConfiguredBackendName(cfg, definitions.BackendLDAP, func(poolName string) {
		// The default pool is already present in the channel registry.
		if poolName != definitions.DefaultBackendName {
			if err := channel.GetLdapChannel().AddChannel(poolName); err != nil {
				level.Error(logger).Log(definitions.LogKeyMsg, "Failed to add LDAP backend channel", "pool", poolName, definitions.LogKeyError, err)

				return
			}
		}

		backend.LDAPMainWorker(store.ldapLookup.ctx, cfg, logger, channel, poolName, backend.LDAPWorkerDeps{})

		if !cfg.LDAPHavePoolOnly(poolName) {
			backend.LDAPAuthWorker(store.ldapAuth.ctx, cfg, logger, channel, poolName, backend.LDAPWorkerDeps{})
		}
	})
}

// startLuaWorkers starts a goroutine that runs the backend.LuaMainWorker function
func startLuaWorkers(store *contextStore, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, channel backend.Channel) {
	forEachConfiguredBackendName(cfg, definitions.BackendLua, func(backendName string) {
		// The default backend is already present in the channel registry.
		if backendName != definitions.DefaultBackendName {
			if err := channel.GetLuaChannel().AddChannel(backendName); err != nil {
				level.Error(logger).Log(definitions.LogKeyMsg, "Failed to add Lua backend channel", "backend", backendName, definitions.LogKeyError, err)

				return
			}
		}

		go func() {
			err := backend.LuaMainWorker(store.lua.ctx, cfg, logger, redisClient, channel, backendName)
			if err != nil {
				level.Error(logger).Log(definitions.LogKeyMsg, "Lua backend worker failed", definitions.LogKeyError, err)
			}
		}()
	})
}

// setupWorkers initializes backend workers based on the provided configuration.
func setupWorkers(ctx context.Context, store *contextStore, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, channel backend.Channel) {
	var (
		ldapStarted bool
		luaStarted  bool
	)

	for _, backendType := range cfg.GetServer().GetBackends() {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			if ldapStarted {
				continue
			}

			setupLDAPWorker(ctx, store, cfg, logger, channel)

			ldapStarted = true
		case definitions.BackendLua:
			if luaStarted {
				continue
			}

			setupLuaWorker(ctx, store, cfg, logger, redisClient, channel)

			luaStarted = true
		case definitions.BackendCache, definitions.BackendTest:
		default:
			level.Warn(logger).Log(definitions.LogKeyMsg, "Unknown backend", "backend")
		}
	}
}

// setupLDAPWorker initializes the LDAP worker contexts and starts LDAP worker routines for processing requests and authentication.
func setupLDAPWorker(ctx context.Context, store *contextStore, cfg config.File, logger *slog.Logger, channel backend.Channel) {
	store.ldapLookup = newContextTuple(ctx)
	store.ldapAuth = newContextTuple(ctx)

	startLDAPWorkers(store, cfg, logger, channel)
}

// setupLuaWorker initializes the Lua worker context, channels, and starts the Lua worker goroutine.
func setupLuaWorker(ctx context.Context, store *contextStore, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, channel backend.Channel) {
	store.lua = newContextTuple(ctx)

	startLuaWorkers(store, cfg, logger, redisClient, channel)
}

// checkRedisConnections validates the availability of both write and read Redis connections using Ping commands.
func checkRedisConnections(ctx context.Context, client rediscli.Client) bool {
	if client == nil {
		return false
	}

	if client.GetWriteHandle() == nil {
		return false
	}

	if err := client.GetWriteHandle().Ping(ctx).Err(); err != nil {
		return false
	}

	if client.GetReadHandle() == nil {
		return false
	}

	if err := client.GetReadHandle().Ping(ctx).Err(); err != nil {
		return false
	}

	return true
}

// setupRedis sets up the Redis client and its replicas.
//
// readinessCtx is used for the connectivity check loop.
// runCtx is used for background goroutines (metrics, scripts) and should be the process/root context.
func setupRedis(readinessCtx context.Context, runCtx context.Context, cfg config.File, logger *slog.Logger, client rediscli.Client) error {
	redisLogger := &util.RedisLogger{}
	redis.SetLogger(redisLogger)

	// Retry mechanism to ensure the Redis connections are usable
	maxRetries := 10
	retryInterval := 5 * time.Second

	for retries := range maxRetries {
		if readinessCtx != nil {
			if err := readinessCtx.Err(); err != nil {
				return err
			}
		}

		if checkRedisConnections(readinessCtx, client) {
			go core.UpdateRedisPoolStats(client)
			go rediscli.UpdateRedisServerMetrics(runCtx, cfg, logger, client)

			// Upload all Lua scripts to Redis at startup
			go func(uploadCtx context.Context) {
				err := rediscli.UploadAllScripts(uploadCtx, logger, client)
				if err != nil {
					level.Warn(logger).Log(
						definitions.LogKeyMsg, "Failed to upload all Redis Lua scripts at startup",
						"error", err,
					)
				}
			}(runCtx)

			return nil
		}

		level.Warn(logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Redis not ready yet. Retry %d/%d", retries+1, maxRetries))

		if readinessCtx == nil {
			time.Sleep(retryInterval)

			continue
		}

		select {
		case <-time.After(retryInterval):
		case <-readinessCtx.Done():
			return readinessCtx.Err()
		}
	}

	return fmt.Errorf("failed to establish Redis connections after max retries")
}

type grpcAuthorityStarter func(context.Context, handlerauthority.ServerDeps) (<-chan struct{}, error)

type httpServerStartOptions struct {
	grpcAuthorityStarter             grpcAuthorityStarter
	continueHTTPOnGRPCAuthorityError bool
}

func (o httpServerStartOptions) effectiveGRPCAuthorityStarter() grpcAuthorityStarter {
	if o.grpcAuthorityStarter != nil {
		return o.grpcAuthorityStarter
	}

	return handlerauthority.StartServer
}

// startHTTPServer starts the HTTP server by initializing the context, setting up channels, and launching the HTTP application.
func startHTTPServer(ctx context.Context, store *contextStore) error {
	return startHTTPServerWithOptions(ctx, store, httpServerStartOptions{})
}

type httpServerRuntime struct {
	store           *contextStore
	cfg             config.File
	env             config.Environment
	logger          *slog.Logger
	policyDecision  *decisionservice.DecisionService
	authApplication core.AuthApplicationService
	signals         core.ServerSignals
	routeArtifacts  *core.RouteArtifacts
}

type httpSetupCallbacks struct {
	health      func(*gin.Engine)
	metrics     func(*gin.Engine)
	idp         func(*gin.Engine)
	backchannel func(*gin.Engine)
}

func startHTTPServerWithOptions(ctx context.Context, store *contextStore, options httpServerStartOptions) error {
	runtime, err := prepareHTTPServerRuntime(ctx, store)
	if err != nil {
		return err
	}

	callbacks := buildHTTPSetupCallbacks(runtime)
	app := core.NewDefaultHTTPApp(core.HTTPDeps{
		Cfg:            runtime.cfg,
		Logger:         runtime.logger,
		Env:            runtime.env,
		Redis:          runtime.store.redisClient,
		AccountCache:   runtime.store.accountCache,
		RouteArtifacts: runtime.routeArtifacts,
	})

	if err := startGRPCAuthorityForHTTP(runtime.store.server.ctx, runtime, options); err != nil {
		return err
	}

	go app.Start(runtime.store.server.ctx, callbacks.health, callbacks.metrics, callbacks.idp, callbacks.backchannel, runtime.signals)

	return nil
}

func prepareHTTPServerRuntime(ctx context.Context, store *contextStore) (httpServerRuntime, error) {
	cfg, env, logger, err := validateHTTPServerStartStore(store)
	if err != nil {
		return httpServerRuntime{}, err
	}

	hostServices := coreauth.NewDefaultHostServices()
	configureHTTPServerDefaults(store, cfg, env, logger, hostServices)
	logHTTPServerStart(logger)

	store.server = newContextTuple(ctx)
	store.signals = core.NewDefaultServerSignals(cfg.GetServer().IsHTTP3Enabled())

	authApplication, err := core.NewProductionAuthApplicationService(core.AuthDeps{
		Cfg:                  cfg,
		Env:                  env,
		Logger:               logger,
		Redis:                store.redisClient,
		AccountCache:         store.accountCache,
		Channel:              store.channel,
		Tolerate:             store.bruteForceTolerate,
		PluginBackendFactory: pluginruntime.NewBackendManagerFactory(store.pluginRunner),
		NativeRuntime:        pluginruntime.NewAuthnRequestRuntime(),
		HostServices:         hostServices,
		LDAPQueue:            priorityqueue.LDAPQueue,
		LDAPAuthQueue:        priorityqueue.LDAPAuthQueue,
	}, store.policyDecision)
	if err != nil {
		return httpServerRuntime{}, fmt.Errorf("create production auth application: %w", err)
	}

	return httpServerRuntime{
		store:           store,
		cfg:             cfg,
		env:             env,
		logger:          logger,
		policyDecision:  store.policyDecision,
		authApplication: authApplication,
		signals:         store.signals,
		routeArtifacts:  store.routeArtifacts,
	}, nil
}

func validateHTTPServerStartStore(store *contextStore) (config.File, config.Environment, *slog.Logger, error) {
	if store == nil {
		return nil, nil, nil, fmt.Errorf("context store is nil")
	}

	if store.logger == nil {
		return nil, nil, nil, fmt.Errorf("logger is nil")
	}

	if store.env == nil {
		return nil, nil, nil, fmt.Errorf("environment is nil")
	}

	if store.cfgProvider == nil {
		return nil, nil, nil, fmt.Errorf("config provider is nil")
	}

	if store.policyStore == nil {
		return nil, nil, nil, fmt.Errorf("policy generation store is nil")
	}

	if store.policyDecision == nil {
		return nil, nil, nil, fmt.Errorf("policy decision service is nil")
	}

	if store.routeArtifacts == nil {
		return nil, nil, nil, fmt.Errorf("prepared route artifacts are nil")
	}

	snap := store.cfgProvider.Current()
	if snap.File == nil {
		return nil, nil, nil, fmt.Errorf("config snapshot file is nil")
	}

	cfg := snap.File

	env := store.env
	if err := validateDeveloperModeBindAddress(env.GetDevMode(), cfg.GetServer().GetListenAddress()); err != nil {
		return nil, nil, nil, err
	}

	if err := handlerbackchannel.ValidateAuthConfiguration(cfg, env.GetDevMode()); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid backchannel authentication configuration: %w", err)
	}

	return cfg, env, store.logger, nil
}

func configureHTTPServerDefaults(
	store *contextStore,
	cfg config.File,
	env config.Environment,
	logger *slog.Logger,
	hostServices core.AuthnHostServices,
) {
	core.SetDefaultResponseWriter(core.NewDefaultResponseWriter(core.ResponseDeps{
		Cfg:       cfg,
		Env:       env,
		Logger:    logger,
		WaitDelay: hostServices.WaitDelay,
	}))
	core.SetDefaultEnvironment(env)
	core.SetDefaultLogger(logger)
	util.SetDefaultEnvironment(env)
	util.SetDefaultLogger(logger)
	ldappool.SetDefaultEnvironment(env)
	redislib.SetDefaultClient(store.redisClient)
	tolerate.SetDefaultClient(store.redisClient)
}

func logHTTPServerStart(logger *slog.Logger) {
	_ = level.Info(logger).Log(
		definitions.LogKeyMsg, "Starting Nauthilus HTTP server",
		"license", "GPL-3.0",
		"author", "Christian Rößner",
		"homepage", "https://nauthilus.org",
		"copyright", "2025",
		"version", version,
		"build_time", buildTime,
	)
}

func buildHTTPSetupCallbacks(runtime httpServerRuntime) httpSetupCallbacks {
	return httpSetupCallbacks{
		health:      buildHealthSetupCallback(runtime),
		metrics:     buildMetricsSetupCallback(runtime),
		idp:         buildIDPSetupCallback(runtime),
		backchannel: buildBackchannelSetupCallback(runtime),
	}
}

func buildHealthSetupCallback(runtime httpServerRuntime) func(*gin.Engine) {
	return func(e *gin.Engine) {
		handlerhealth.New(runtime.cfg, runtime.logger, runtime.store.redisClient).Register(e)
	}
}

func buildMetricsSetupCallback(runtime httpServerRuntime) func(*gin.Engine) {
	return func(e *gin.Engine) {
		handlermetrics.New(runtime.cfg, runtime.logger, runtime.store.redisClient).Register(e)
	}
}

func buildIDPSetupCallback(runtime httpServerRuntime) func(*gin.Engine) {
	if !runtime.cfg.GetServer().Frontend.Enabled {
		return nil
	}

	deps := frontendHandlerDeps(runtime)

	if !runtime.cfg.GetIDP().OIDC.Enabled && !runtime.cfg.GetIDP().SAML2.Enabled {
		logMissingInternalIDP(runtime)

		return nil
	}

	canonicalRuntime, err := handleridp.NewCanonicalBrowserRuntime(deps)
	if err != nil {
		_ = level.Error(runtime.logger).Log(
			definitions.LogKeyMsg, "Canonical IDP browser runtime initialization failed",
			definitions.LogKeyError, err.Error(),
		)

		return nil
	}

	frontendHandler, err := handleridp.NewCanonicalFrontendHandler(deps, canonicalRuntime)
	if err != nil {
		_ = level.Error(runtime.logger).Log(
			definitions.LogKeyMsg, "Canonical IDP frontend initialization failed",
			definitions.LogKeyError, err.Error(),
		)

		return nil
	}

	return func(e *gin.Engine) {
		registerIDPRoutes(e, runtime, deps, canonicalRuntime, frontendHandler)
	}
}

func frontendHandlerDeps(runtime httpServerRuntime) *handlerdeps.Deps {
	deps := &handlerdeps.Deps{
		Cfg:            runtime.cfg,
		Env:            runtime.env,
		Logger:         runtime.logger,
		Redis:          runtime.store.redisClient,
		Channel:        runtime.store.channel,
		AccountCache:   runtime.store.accountCache,
		LangManager:    runtime.store.langManager,
		RouteArtifacts: runtime.routeArtifacts,
		LDAPQueue:      priorityqueue.LDAPQueue,
		LDAPAuthQueue:  priorityqueue.LDAPAuthQueue,
	}
	deps.AuthApplication = runtime.authApplication
	deps.Svc = handlerdeps.NewDefaultServices(deps)

	return deps
}

func logMissingInternalIDP(runtime httpServerRuntime) {
	if runtime.env.GetDevMode() {
		_ = level.Warn(runtime.logger).Log(
			definitions.LogKeyMsg,
			"Frontend is enabled, but internal IDP (OIDC/SAML2) is not enabled. Login routes will not be registered",
		)
	}
}

func registerIDPRoutes(
	e *gin.Engine,
	runtime httpServerRuntime,
	deps *handlerdeps.Deps,
	canonicalRuntime *cookie.CanonicalRuntime,
	frontendHandler *handleridp.FrontendHandler,
) {
	nauthilusIDP := idp.NewNauthilusIDP(deps)
	if runtime.cfg.GetIDP().OIDC.Enabled {
		nauthilusIDP.GetKeyManager().StartRotationJob(runtime.store.server.ctx)
	}

	frontendHandler.Register(e)

	if runtime.cfg.GetIDP().OIDC.Enabled {
		oidcHandler := handleridp.NewOIDCHandler(deps, nauthilusIDP, frontendHandler)
		frontendHandler.SetCanonicalOIDCDeviceLoginContinuer(oidcHandler.ContinueDeviceLoginCanonical)
		oidcHandler.Register(e, canonicalRuntime)
	}

	if runtime.cfg.GetIDP().SAML2.Enabled {
		handleridp.NewSAMLHandler(deps, nauthilusIDP).Register(e, canonicalRuntime)
	}
}

func buildBackchannelSetupCallback(runtime httpServerRuntime) func(*gin.Engine) {
	tokenStorage := idp.NewRedisTokenStorageWithConfig(
		runtime.store.redisClient,
		runtime.cfg.GetServer().GetRedis().GetPrefix(),
		runtime.cfg,
	)

	return func(e *gin.Engine) {
		deps := &handlerdeps.Deps{
			Cfg:            runtime.cfg,
			Env:            runtime.env,
			Logger:         runtime.logger,
			Redis:          runtime.store.redisClient,
			LangManager:    runtime.store.langManager,
			TokenFlusher:   tokenStorage,
			PolicyDecision: runtime.policyDecision,
			PluginRunner:   runtime.store.pluginRunner,
			Tolerate:       runtime.store.bruteForceTolerate,
			RouteArtifacts: runtime.routeArtifacts,
			LDAPQueue:      priorityqueue.LDAPQueue,
			LDAPAuthQueue:  priorityqueue.LDAPAuthQueue,
		}

		deps.AuthApplication = runtime.authApplication
		deps.Svc = handlerdeps.NewDefaultServices(deps)
		if err := handlerbackchannel.Setup(e, deps); err != nil {
			_ = level.Error(runtime.logger).Log(definitions.LogKeyMsg, "Backchannel route setup failed", definitions.LogKeyError, err)
		}
	}
}

func startGRPCAuthorityForHTTP(
	ctx context.Context,
	runtime httpServerRuntime,
	options httpServerStartOptions,
) error {
	grpcAuthorityDone, err := options.effectiveGRPCAuthorityStarter()(ctx, handlerauthority.ServerDeps{
		Cfg:                  runtime.cfg,
		Env:                  runtime.env,
		Logger:               runtime.logger,
		Redis:                runtime.store.redisClient,
		AccountCache:         runtime.store.accountCache,
		Channel:              runtime.store.channel,
		AuthService:          runtime.authApplication,
		PolicyService:        runtime.policyDecision,
		PluginBackendFactory: pluginruntime.NewBackendManagerFactory(runtime.store.pluginRunner),
		Tolerate:             runtime.store.bruteForceTolerate,
		RouteArtifacts:       runtime.routeArtifacts,
		LDAPQueue:            priorityqueue.LDAPQueue,
		LDAPAuthQueue:        priorityqueue.LDAPAuthQueue,
	})
	if err != nil {
		runtime.store.grpcAuthorityDone = nil

		if options.continueHTTPOnGRPCAuthorityError {
			_ = level.Warn(runtime.logger).Log(definitions.LogKeyMsg, "Unable to start gRPC authority server; continuing HTTP startup", definitions.LogKeyError, err)

			return nil
		}

		return fmt.Errorf("start gRPC authority server: %w", err)
	}

	runtime.store.grpcAuthorityDone = grpcAuthorityDone

	return nil
}

func validateDeveloperModeBindAddress(devMode bool, listenAddress string) error {
	if !devMode {
		return nil
	}

	host, _, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return fmt.Errorf("developer mode requires loopback listen address (127.0.0.1 or ::1), invalid runtime.servers.http.address %q: %w", listenAddress, err)
	}

	if host == definitions.Localhost4 || host == definitions.Localhost6 {
		return nil
	}

	return fmt.Errorf("developer mode requires loopback listen address (127.0.0.1 or ::1), got %q", listenAddress)
}
