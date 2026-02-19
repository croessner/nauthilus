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
	"time"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/app/redifx"
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/backend/ldappool"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/core/language"
	"github.com/croessner/nauthilus/server/definitions"
	handlerapiv1 "github.com/croessner/nauthilus/server/handler/api/v1"
	handlerbackchannel "github.com/croessner/nauthilus/server/handler/backchannel"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	handleridp "github.com/croessner/nauthilus/server/handler/frontend/idp"
	handlerhealth "github.com/croessner/nauthilus/server/handler/health"
	handlermetrics "github.com/croessner/nauthilus/server/handler/metrics"
	"github.com/croessner/nauthilus/server/idp"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"

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
	action     *contextTuple
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

	// signals holds server lifecycle channels via the interface (no globals)
	signals core.ServerSignals

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

// startActionWorker starts the action workers concurrently to perform the specified actions using the provided context.
func startActionWorker(actionWorkers []*action.Worker, act *contextTuple) {
	for i := 0; i < len(actionWorkers); i++ {
		go actionWorkers[i].Work(act.ctx)
	}
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
			channel.GetLdapChannel().AddChannel(poolName)
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
			channel.GetLuaChannel().AddChannel(backendName)
		}

		go func() {
			err := backend.LuaMainWorker(store.lua.ctx, cfg, logger, redisClient, channel, backendName)
			if err != nil {
				level.Error(logger).Log(definitions.LogKeyMsg, "Lua backend worker failed", definitions.LogKeyError, err)
			}
		}()
	})
}

// initializeActionWorkers creates and initializes a slice of action workers based on the maximum workers configuration.
func initializeActionWorkers(cfg config.File, logger *slog.Logger, redisClient rediscli.Client, env config.Environment) []*action.Worker {
	var workers []*action.Worker

	for i := 0; i < cfg.GetLuaActionNumberOfWorkers(); i++ {
		workers = append(workers, action.NewWorker(cfg, logger, redisClient, env))
	}

	return workers
}

// setupWorkers initializes action workers and backend workers (LDAP, Lua, etc.) based on the provided configuration.
func setupWorkers(ctx context.Context, store *contextStore, actionWorkers []*action.Worker, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, channel backend.Channel) {
	var (
		ldapStarted bool
		luaStarted  bool
	)

	startActionWorker(actionWorkers, store.action)

	for _, backendType := range cfg.GetServer().GetBackends() {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			if ldapStarted {
				continue
			}

			setupLDAPWorker(store, ctx, cfg, logger, channel)

			ldapStarted = true
		case definitions.BackendLua:
			if luaStarted {
				continue
			}

			setupLuaWorker(store, ctx, cfg, logger, redisClient, channel)

			luaStarted = true
		case definitions.BackendCache:
		default:
			level.Warn(logger).Log(definitions.LogKeyMsg, "Unknown backend", "backend")
		}
	}
}

// setupLDAPWorker initializes the LDAP worker contexts and starts LDAP worker routines for processing requests and authentication.
func setupLDAPWorker(store *contextStore, ctx context.Context, cfg config.File, logger *slog.Logger, channel backend.Channel) {
	store.ldapLookup = newContextTuple(ctx)
	store.ldapAuth = newContextTuple(ctx)

	startLDAPWorkers(store, cfg, logger, channel)
}

// setupLuaWorker initializes the Lua worker context, channels, and starts the Lua worker goroutine.
func setupLuaWorker(store *contextStore, ctx context.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, channel backend.Channel) {
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

	for retries := 0; retries < maxRetries; retries++ {
		if readinessCtx != nil {
			if err := readinessCtx.Err(); err != nil {
				return err
			}
		}

		if checkRedisConnections(readinessCtx, client) {
			go core.UpdateRedisPoolStats(client)
			go rediscli.UpdateRedisServerMetrics(runCtx, cfg, logger)

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

// startHTTPServer starts the HTTP server by initializing the context, setting up channels, and launching the HTTP application.
func startHTTPServer(ctx context.Context, store *contextStore) error {
	if store == nil {
		return fmt.Errorf("context store is nil")
	}

	if store.logger == nil {
		return fmt.Errorf("logger is nil")
	}

	if store.env == nil {
		return fmt.Errorf("environment is nil")
	}

	if store.cfgProvider == nil {
		return fmt.Errorf("config provider is nil")
	}

	snap := store.cfgProvider.Current()
	if snap.File == nil {
		return fmt.Errorf("config snapshot file is nil")
	}

	logger := store.logger
	cfg := snap.File
	env := store.env

	// Configure response/header behavior via DI instead of globals.
	core.SetDefaultResponseWriter(core.NewDefaultResponseWriter(core.ResponseDeps{Cfg: cfg, Env: env, Logger: logger}))

	// Make environment available to core subtrees without direct global access.
	core.SetDefaultEnvironment(env)

	// Provide core defaults for legacy call sites.
	core.SetDefaultConfigFile(cfg)
	core.SetDefaultLogger(logger)

	// Make environment available to util subtrees without direct global access.
	util.SetDefaultEnvironment(env)

	// Provide util defaults for legacy call sites.
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultLogger(logger)

	// Make environment available to backend/ldappool without direct global access.
	ldappool.SetDefaultEnvironment(env)

	// Make environment available to lualib/action without direct global access.
	action.SetDefaultEnvironment(env)

	// Make Redis available to lualib/redislib without direct global access.
	redislib.SetDefaultClient(store.redisClient)

	// Make Redis available to backend package without direct global access.
	backend.SetDefaultRedisClient(store.redisClient)

	// Make Redis available to bruteforce package without direct global access.
	bruteforce.SetDefaultRedisClient(store.redisClient)

	// Make Redis available to core helpers without direct global access.
	core.SetDefaultRedisClient(store.redisClient)

	// Make Redis available to bruteforce tolerations without direct global access.
	tolerate.SetDefaultClient(store.redisClient)

	level.Info(logger).Log(
		definitions.LogKeyMsg, "Starting Nauthilus HTTP server",
		"license", "GPL-3.0",
		"author", "Christian Rößner",
		"homepage", "https://nauthilus.org",
		"copyright", "2025",
		"version", version,
		"build_time", buildTime,
	)

	store.server = newContextTuple(ctx)

	enableHTTP3 := cfg.GetServer().IsHTTP3Enabled()
	signals := core.NewDefaultServerSignals(enableHTTP3)

	// Store signals on the contextStore for consumption by signal handlers
	store.signals = signals

	// Build frontend/backchannel setup callbacks to avoid core->handler import cycles
	var setupHealth func(*gin.Engine)
	var setupMetrics func(*gin.Engine)
	var setupIdP func(*gin.Engine)
	var setupBackchannel func(*gin.Engine)

	// Health endpoint (always register)
	setupHealth = func(e *gin.Engine) {
		handlerhealth.New(cfg, logger, store.redisClient).Register(e)
	}

	// Metrics endpoint (always register)
	setupMetrics = func(e *gin.Engine) {
		handlermetrics.New(cfg, logger, store.redisClient).Register(e)
	}

	// Frontend handlers only if enabled (keeps logic parity)
	if cfg.GetServer().Frontend.Enabled {
		deps := &handlerdeps.Deps{
			Cfg:          cfg,
			CfgProvider:  store.cfgProvider,
			Logger:       logger,
			Channel:      store.channel,
			AccountCache: store.accountCache,
			LangManager:  store.langManager,
		}
		deps.Svc = handlerdeps.NewDefaultServices(deps)

		storage := idp.NewRedisTokenStorage(store.redisClient, cfg.GetServer().GetRedis().GetPrefix())

		if cfg.GetIdP().OIDC.Enabled || cfg.GetIdP().SAML2.Enabled {
			setupIdP = func(e *gin.Engine) {
				deps.Env = env
				deps.Redis = store.redisClient
				nauthilusIdP := idp.NewNauthilusIdP(deps)

				if cfg.GetIdP().OIDC.Enabled {
					nauthilusIdP.GetKeyManager().StartRotationJob(store.server.ctx)
				}

				var frontendHandler *handleridp.FrontendHandler

				if cfg.GetIdP().OIDC.Enabled || cfg.GetIdP().SAML2.Enabled {
					frontendHandler = handleridp.NewFrontendHandler(deps)
					frontendHandler.Register(e)

					mfaAPI := handlerapiv1.NewMFAAPI(deps)
					mfaAPI.Register(e)

					if cfg.GetIdP().OIDC.Enabled {
						oidcSessionsAPI := handlerapiv1.NewOIDCSessionsAPI(deps, storage)
						oidcSessionsAPI.Register(e)
					}
				}

				if cfg.GetIdP().OIDC.Enabled {
					oidcHandler := handleridp.NewOIDCHandler(deps, nauthilusIdP, frontendHandler)
					oidcHandler.Register(e)
				}

				if cfg.GetIdP().SAML2.Enabled {
					samlHandler := handleridp.NewSAMLHandler(deps, nauthilusIdP)
					samlHandler.Register(e)
				}
			}
		}

		if env.GetDevMode() {
			if setupIdP == nil {
				level.Warn(logger).Log(definitions.LogKeyMsg, "Frontend is enabled, but internal IdP (OIDC/SAML2) is not enabled. Login routes will not be registered")
			}
		}
	}

	// Backchannel API
	tokenStorage := idp.NewRedisTokenStorage(store.redisClient, cfg.GetServer().GetRedis().GetPrefix())

	setupBackchannel = func(e *gin.Engine) {
		deps := &handlerdeps.Deps{
			Cfg:          cfg,
			CfgProvider:  store.cfgProvider,
			Env:          env,
			Logger:       logger,
			Redis:        store.redisClient,
			LangManager:  store.langManager,
			TokenFlusher: tokenStorage,
		}
		deps.Svc = handlerdeps.NewDefaultServices(deps)
		handlerbackchannel.Setup(e, deps)
	}

	app := core.NewDefaultHTTPApp(core.HTTPDeps{
		Cfg:          cfg,
		Logger:       logger,
		Env:          env,
		Redis:        store.redisClient,
		AccountCache: store.accountCache,
	})

	go app.Start(store.server.ctx, setupHealth, setupMetrics, setupIdP, setupBackchannel, signals)

	return nil
}
