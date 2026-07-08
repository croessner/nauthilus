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
	"encoding/json"
	"fmt"
	stdlog "log"
	"log/slog"
	"net/http"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/app/bootfx"
	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/app/envfx"
	"github.com/croessner/nauthilus/v3/server/app/logfx"
	"github.com/croessner/nauthilus/v3/server/app/loopsfx"
	"github.com/croessner/nauthilus/v3/server/app/redifx"
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/backend/ldappool"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/bruteforce"
	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/core/language"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/action"
	"github.com/croessner/nauthilus/v3/server/lualib/redislib"
	"github.com/croessner/nauthilus/v3/server/monitoring"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	"github.com/croessner/nauthilus/v3/server/privilege"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"

	"go.uber.org/fx"
)

type configDeps struct {
	fx.Out

	Provider configfx.Provider
	Reloader configfx.Reloader
}

// newConfigDeps constructs config dependencies for fx.
//
// It depends on the bootstrap token to ensure the legacy configuration has been
// loaded before the config snapshot provider is created.
func newConfigDeps(_ *bootstrapped) (configDeps, error) {
	r, err := configfx.NewProvider()
	if err != nil {
		return configDeps{}, err
	}

	return configDeps{Provider: r, Reloader: r}, nil
}

// newLogger provides the process logger for fx.
//
// It depends on the bootstrap token to ensure logging has been initialized.
func newLogger(_ *bootstrapped) *slog.Logger {
	return logfx.NewLogger()
}

// newDbgModuleMapping returns the current DbgModuleMapping and registers its lifecycle with the provided fx.Lifecycle.
func newDbgModuleMapping(lc fx.Lifecycle) *definitions.DbgModuleMapping {
	mapping := definitions.GetDbgModuleMapping()

	lc.Append(fx.Hook{
		OnStop: func(context.Context) error {
			definitions.SetDbgModuleMapping(nil)

			return nil
		},
	})

	return mapping
}

// newRedisClient provides the Redis facade for fx.
//
// It depends on the bootstrap token to ensure configuration/logging has been initialized.
type redisDeps struct {
	fx.Out

	Client    redifx.Client
	Rebuilder redifx.Rebuilder
}

// newRedisDeps provides a swap-capable Redis facade (Client) and its rebuild controller.
//
// Restart orchestration should rebuild Redis via the injected Rebuilder,
// not via the global `rediscli.RebuildClient()`.
func newRedisDeps(lc fx.Lifecycle, _ *bootstrapped, cfgProvider configfx.Provider, logger *slog.Logger) (redisDeps, error) {
	snap := cfgProvider.Current()
	client := rediscli.NewClientWithDeps(snap.File, logger)
	managed := redifx.NewManagedClient(client)

	// Ensure the current underlying client is closed on process stop.
	lc.Append(fx.Hook{OnStop: func(context.Context) error {
		managed.Close()

		return nil
	}})

	return redisDeps{Client: managed, Rebuilder: managed}, nil
}

// newActionWorkers constructs the action worker pool used by the legacy worker orchestration.
func newActionWorkers(_ *bootstrapped, cfgProvider configfx.Provider, logger *slog.Logger, redisClient rediscli.Client, env config.Environment) ([]*action.Worker, error) {
	if cfgProvider == nil {
		return nil, fmt.Errorf("config provider is nil")
	}

	snap := cfgProvider.Current()
	if snap.File == nil {
		return nil, fmt.Errorf("config snapshot file is nil")
	}

	return initializeActionWorkers(snap.File, logger, redisClient, env), nil
}

// newContextStoreForRuntime constructs the runtime context store.
//
// The store is the legacy coordination struct that still carries context tuples and
// injected dependencies for partially migrated code paths.
func newContextStoreForRuntime(
	ctx context.Context,
	_ *bootstrapped,
	cfgProvider configfx.Provider,
	env envfx.Environment,
	logger *slog.Logger,
	redisClient redifx.Client,
	channel backend.Channel,
	accountCache *accountcache.Manager,
	langManager language.Manager,
) *contextStore {
	store := &contextStore{
		cfgProvider:  cfgProvider,
		env:          env,
		logger:       logger,
		redisClient:  redisClient,
		channel:      channel,
		accountCache: accountCache,
		langManager:  langManager,
		action:       newContextTuple(ctx),
	}

	return store
}

func newAccountCache(cfgProvider configfx.Provider) *accountcache.Manager {
	return accountcache.NewManager(cfgProvider.Current().File)
}

func newBackendChannel(cfgProvider configfx.Provider) backend.Channel {
	return backend.NewChannel(cfgProvider.Current().File)
}

type runtimeLifecycleParams struct {
	fx.In

	Ctx           context.Context
	Cancel        context.CancelFunc
	Store         *contextStore
	ActionWorkers []*action.Worker
	StatsSvc      *loopsfx.StatsService
	MonitoringSvc *loopsfx.BackendMonitoringService
	ConnMgrSvc    *loopsfx.ConnMgrService
	BFSyncSvc     *loopsfx.BruteForceSyncService
	Env           config.Environment
	Channel       backend.Channel
	LangManager   language.Manager
}

// registerRuntimeLifecycle wires the legacy startup/shutdown sequence into fx.Lifecycle.
//
// Startup preserves the existing initialization order. Shutdown cancels the root context,
// stops long-running services, performs time-bounded waits, and shuts down process-wide
// resources.
func registerRuntimeLifecycle(lc fx.Lifecycle, p runtimeLifecycleParams) {
	params := p

	var pluginRunner *pluginruntime.Runner

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			var err error

			pluginRunner, err = startRuntimeLifecycle(&params)

			return err
		},
		OnStop: func(stopCtx context.Context) error {
			return stopRuntimeLifecycle(stopCtx, &params, pluginRunner)
		},
	})
}

// startRuntimeLifecycle runs the legacy startup sequence inside the fx lifecycle.
func startRuntimeLifecycle(p *runtimeLifecycleParams) (*pluginruntime.Runner, error) {
	snap := p.Store.cfgProvider.Current()
	startRuntimeTelemetryAndConfig(p, snap.File)

	pluginState, err := loadRuntimePluginState(snap.File, p.Store.logger)
	if err != nil {
		return nil, err
	}

	if err := configureRuntimeDefaults(p, snap.File); err != nil {
		return nil, err
	}

	if err := setupRuntimeWorkersAndRedis(p, snap.File); err != nil {
		return nil, err
	}

	pluginRunner, err := startRuntimePluginRunner(p, snap.File, pluginState)
	if err != nil {
		return nil, err
	}

	bootfx.RunLuaInitScript(p.Ctx, snap.File, p.Store.logger, p.Store.redisClient)
	core.LoadStatsFromRedis(p.Ctx, snap.File, p.Store.logger, p.Store.redisClient)

	if err := startHTTPAndDropPrivileges(p, snap.File); err != nil {
		return nil, err
	}

	if err := startRuntimeLoopServices(p); err != nil {
		return nil, err
	}

	return pluginRunner, nil
}

// startRuntimeTelemetryAndConfig runs early config-dependent process initialization.
func startRuntimeTelemetryAndConfig(p *runtimeLifecycleParams, cfg config.File) {
	// Initialize OpenTelemetry tracing early (no-op if disabled)
	monitoring.GetTelemetry().Start(p.Ctx, version)

	bootfx.InitializeInstanceInfo(cfg, version)
	bootfx.DebugLoadableConfig(cfg, p.Store.logger)
}

// loadRuntimePluginState returns the current plugin loader state or initializes it.
func loadRuntimePluginState(cfg config.File, logger *slog.Logger) (*pluginloader.State, error) {
	pluginState, ok := pluginloader.DefaultState()
	if ok {
		return pluginState, nil
	}

	return bootfx.SetupGoPlugins(cfg, logger)
}

// configureRuntimeDefaults wires legacy package-level defaults for runtime code.
func configureRuntimeDefaults(p *runtimeLifecycleParams, cfg config.File) error {
	if err := bootfx.SetupLuaScripts(cfg, p.Store.logger); err != nil {
		stdlog.Fatalln("Unable to setup Lua scripts. Error:", err)
	}

	bootfx.EnableBlockProfile(cfg)
	bootfx.InitializeBruteForceTolerate(p.Ctx, cfg, p.Store.logger, p.Store.redisClient)

	if err := configureRuntimeI18N(p, cfg); err != nil {
		return err
	}

	bootfx.RunLuaInitScript(p.Ctx, cfg, p.Store.logger, p.Store.redisClient)
	core.InitPassDBResultPool()

	if cfg == nil {
		return fmt.Errorf("config snapshot file is nil")
	}

	setRuntimePackageDefaults(p, cfg)
	priorityqueue.InitQueues(p.Store.logger)

	return nil
}

// configureRuntimeI18N initializes the Lua i18n runtime from the active config.
func configureRuntimeI18N(p *runtimeLifecycleParams, cfg config.File) error {
	if err := lualib.ConfigureDefaultI18NRuntime(
		localization.NewManagerCatalog(p.LangManager),
		cfg.GetServer().Frontend.GetDefaultLanguage(),
		p.Store.logger,
	); err != nil {
		return fmt.Errorf("configure Lua i18n runtime: %w", err)
	}

	return nil
}

// setRuntimePackageDefaults publishes injected dependencies to legacy package defaults.
func setRuntimePackageDefaults(p *runtimeLifecycleParams, cfg config.File) {
	// Provide core defaults for legacy call sites that are not fully constructor-injected yet.
	core.SetDefaultConfigFile(cfg)
	core.SetDefaultLogger(p.Store.logger)
	core.SetDefaultAccountCache(p.Store.accountCache)
	core.SetDefaultChannel(p.Channel)
	core.SetDefaultEnvironment(p.Env)

	// Provide util defaults for legacy call sites.
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultLogger(p.Store.logger)
	util.SetDefaultEnvironment(p.Env)

	// Provide ldappool defaults.
	ldappool.SetDefaultEnvironment(p.Env)

	// Provide action defaults.
	action.SetDefaultEnvironment(p.Env)
}

// setupRuntimeWorkersAndRedis starts workers and initializes Redis-backed defaults.
func setupRuntimeWorkersAndRedis(p *runtimeLifecycleParams, cfg config.File) error {
	p.ActionWorkers = initializeActionWorkers(cfg, p.Store.logger, p.Store.redisClient, p.Env)
	setupWorkers(p.Ctx, p.Store, p.ActionWorkers, cfg, p.Store.logger, p.Store.redisClient, p.Channel)

	if err := setupRedis(p.Ctx, p.Ctx, cfg, p.Store.logger, p.Store.redisClient); err != nil {
		return err
	}

	setRuntimeRedisDefaults(p)

	return nil
}

// setRuntimeRedisDefaults publishes the injected Redis client to legacy package defaults.
func setRuntimeRedisDefaults(p *runtimeLifecycleParams) {
	// Ensure backend package uses the injected Redis client.
	backend.SetDefaultRedisClient(p.Store.redisClient)

	// Ensure bruteforce package uses the injected Redis client.
	bruteforce.SetDefaultRedisClient(p.Store.redisClient)

	// Ensure core helpers use the injected Redis client.
	core.SetDefaultRedisClient(p.Store.redisClient)

	// Ensure bruteforce tolerations use the injected Redis client.
	tolerate.SetDefaultClient(p.Store.redisClient)

	// Ensure Lua redislib has a configured default client before any Lua code runs.
	redislib.SetDefaultClient(p.Store.redisClient)
}

// startRuntimePluginRunner starts the native plugin runtime with the production host.
func startRuntimePluginRunner(p *runtimeLifecycleParams, cfg config.File, pluginState *pluginloader.State) (*pluginruntime.Runner, error) {
	pluginRunner := pluginruntime.NewRunner(
		pluginState,
		pluginruntime.WithHost(newRuntimePluginHost(
			p.Ctx,
			p.Store.logger,
			cfg,
			p.Store.redisClient,
			priorityqueue.LDAPQueue,
		)),
		pluginruntime.WithObserver(pluginruntime.NewOperationalObserver(
			p.Store.logger,
			pluginruntime.WithOperationalObserverDebugConfig(cfg, pluginState.Registry()),
		)),
		pluginruntime.WithPluginConfig(cfg.GetPlugins()),
	)
	pluginruntime.SetDefaultRunner(pluginRunner)

	if err := pluginRunner.Start(p.Ctx); err != nil {
		return nil, err
	}

	return pluginRunner, nil
}

// startHTTPAndDropPrivileges starts HTTP entry points before privilege drop.
func startHTTPAndDropPrivileges(p *runtimeLifecycleParams, cfg config.File) error {
	if err := startHTTPServer(p.Ctx, p.Store); err != nil {
		return err
	}

	// Drop privileges after all file-based initialization and socket binding.
	srv := cfg.GetServer()

	if err := privilege.DropPrivileges(srv.GetRunAsUser(), srv.GetRunAsGroup(), srv.GetChroot()); err != nil {
		return fmt.Errorf("privilege drop failed: %w", err)
	}

	return nil
}

// startRuntimeLoopServices starts runtime loop services after HTTP is serving.
func startRuntimeLoopServices(p *runtimeLifecycleParams) error {
	if err := p.ConnMgrSvc.Start(p.Ctx); err != nil {
		return err
	}

	if err := p.MonitoringSvc.Start(p.Ctx); err != nil {
		return err
	}

	if err := p.StatsSvc.Start(p.Ctx); err != nil {
		return err
	}

	if err := p.BFSyncSvc.Start(p.Ctx); err != nil {
		return err
	}

	return nil
}

// stopRuntimeLifecycle runs the legacy shutdown sequence inside the fx lifecycle.
func stopRuntimeLifecycle(stopCtx context.Context, p *runtimeLifecycleParams, pluginRunner *pluginruntime.Runner) error {
	p.Cancel()

	snap := p.Store.cfgProvider.Current()

	stopRuntimePluginRunner(stopCtx, pluginRunner)
	stopRuntimeLoopServices(stopCtx, p)
	waitForRuntimeShutdown(stopCtx, p)
	saveRuntimeStats(stopCtx, p, snap.File)
	lualib.StopGlobalCache()
	shutdownRuntimeTelemetry(stopCtx)

	return nil
}

// stopRuntimePluginRunner stops the native plugin runtime best-effort.
func stopRuntimePluginRunner(stopCtx context.Context, pluginRunner *pluginruntime.Runner) {
	if pluginRunner == nil {
		return
	}

	if err := pluginRunner.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop native plugin runtime. Error: %v", err)
	}
}

// stopRuntimeLoopServices stops runtime loop services best-effort.
func stopRuntimeLoopServices(stopCtx context.Context, p *runtimeLifecycleParams) {
	if err := p.StatsSvc.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop stats service. Error: %v", err)
	}

	if err := p.MonitoringSvc.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop backend monitoring service. Error: %v", err)
	}

	if err := p.ConnMgrSvc.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop connection manager service. Error: %v", err)
	}

	if err := p.BFSyncSvc.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop brute-force sync service. Error: %v", err)
	}
}

// waitForRuntimeShutdown waits for workers without consuming the full stop budget.
func waitForRuntimeShutdown(stopCtx context.Context, p *runtimeLifecycleParams) {
	// Best-effort: do not spend the entire fx stop budget on shutdown waits.
	waitCtx, waitCancel := context.WithTimeout(stopCtx, definitions.FxShutdownWaitTimeout)
	waitForShutdown(waitCtx, p.Store, p.ActionWorkers)
	waitCancel()
}

// saveRuntimeStats persists stats without blocking process termination indefinitely.
func saveRuntimeStats(stopCtx context.Context, p *runtimeLifecycleParams, cfg config.File) {
	// Best-effort: do not let stats persistence block process termination.
	statsCtx, statsCancel := context.WithTimeout(stopCtx, definitions.FxShutdownStatsFlushTimeout)
	core.SaveStatsToRedis(statsCtx, cfg, p.Store.logger, p.Store.redisClient)
	statsCancel()
}

// shutdownRuntimeTelemetry shuts down telemetry within the remaining stop budget.
func shutdownRuntimeTelemetry(stopCtx context.Context) {
	// Best-effort: telemetry shutdown should respect the remaining stop budget.
	telemetryCtx, telemetryCancel := context.WithTimeout(stopCtx, definitions.FxShutdownTelemetryTimeout)
	monitoring.GetTelemetry().Shutdown(telemetryCtx)
	telemetryCancel()
}

// newRuntimePluginHost builds the production host facade after process services are initialized.
func newRuntimePluginHost(
	ctx context.Context,
	logger *slog.Logger,
	cfg config.File,
	redisClient rediscli.Client,
	ldapQueue pluginruntime.LDAPQueue,
) *pluginruntime.Host {
	redisPrefix := ""
	if cfg != nil {
		redisPrefix = cfg.GetServer().GetRedis().GetPrefix()
	}

	options := []pluginruntime.HostOption{
		pluginruntime.WithServiceContext(ctx),
		pluginruntime.WithLogger(logger),
		pluginruntime.WithConfig(runtimePluginConfigView(cfg)),
		pluginruntime.WithDebugConfig(cfg),
		pluginruntime.WithHTTPClient(&http.Client{Transport: util.NewHTTPClientTransport(cfg)}),
		pluginruntime.WithConnectionTargets(pluginruntime.NewConnectionTargetFacadeForConfig(cfg)),
		pluginruntime.WithRedisPrefix(redisPrefix),
		pluginruntime.WithHelpers(pluginruntime.NewDeterministicHelperFacade(pluginruntime.HelperOptionsFromConfig(cfg))),
	}

	if redisClient != nil {
		options = append(options, pluginruntime.WithRedisClient(redisClient))
	}

	if ldapQueue != nil {
		options = append(options, pluginruntime.WithLDAPExecutor(pluginruntime.NewLDAPQueueExecutor(ldapQueue)))
	}

	return pluginruntime.NewHost(options...)
}

// runtimePluginConfigView converts the loaded config snapshot into a read-only plugin API view.
func runtimePluginConfigView(cfg config.File) pluginapi.ConfigView {
	values, err := runtimePluginConfigMap(cfg)
	if err != nil {
		return pluginregistry.NewConfigView(nil)
	}

	return pluginregistry.NewConfigView(values)
}

// runtimePluginConfigMap materializes the active file snapshot without exposing raw Viper state.
func runtimePluginConfigMap(cfg config.File) (map[string]any, error) {
	if cfg == nil {
		return nil, nil
	}

	raw, err := cfg.GetConfigFileAsJSON()
	if err != nil {
		return nil, err
	}

	values := make(map[string]any)
	if len(raw) == 0 {
		return values, nil
	}

	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}

	return values, nil
}
