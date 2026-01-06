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
	stdlog "log"
	"log/slog"

	"github.com/croessner/nauthilus/server/app/bootfx"
	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/app/envfx"
	"github.com/croessner/nauthilus/server/app/logfx"
	"github.com/croessner/nauthilus/server/app/loopsfx"
	"github.com/croessner/nauthilus/server/app/redifx"
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/monitoring"
	"github.com/croessner/nauthilus/server/rediscli"

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
func newActionWorkers(_ *bootstrapped) []*action.Worker {
	return initializeActionWorkers()
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
) *contextStore {
	store := newContextStore()
	store.cfgProvider = cfgProvider
	store.env = env
	store.logger = logger
	store.redisClient = redisClient
	store.action = newContextTuple(ctx)

	return store
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
}

// registerRuntimeLifecycle wires the legacy startup/shutdown sequence into fx.Lifecycle.
//
// Startup preserves the existing initialization order. Shutdown cancels the root context,
// stops long-running services, performs time-bounded waits, and shuts down process-wide
// resources.
func registerRuntimeLifecycle(lc fx.Lifecycle, p runtimeLifecycleParams) {
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			// Initialize OpenTelemetry tracing early (no-op if disabled)
			monitoring.GetTelemetry().Start(p.Ctx, version)

			bootfx.InitializeInstanceInfo(version)
			bootfx.DebugLoadableConfig()

			if err := bootfx.SetupLuaScripts(); err != nil {
				stdlog.Fatalln("Unable to setup Lua scripts. Error:", err)
			}

			bootfx.EnableBlockProfile()
			bootfx.InitializeBruteForceTolerate(p.Ctx)
			bootfx.InitializeHTTPClients()
			core.InitPassDBResultPool()
			setupWorkers(p.Ctx, p.Store, p.ActionWorkers)

			if err := setupRedis(p.Ctx, p.Ctx, p.Store.redisClient); err != nil {
				return err
			}

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

			bootfx.RunLuaInitScript(p.Ctx)
			core.LoadStatsFromRedis(p.Ctx)

			if err := startHTTPServer(p.Ctx, p.Store); err != nil {
				return err
			}

			if err := p.ConnMgrSvc.Start(p.Ctx); err != nil {
				return err
			}

			if err := p.MonitoringSvc.Start(p.Ctx); err != nil {
				return err
			}

			if err := p.StatsSvc.Start(p.Ctx); err != nil {
				return err
			}

			return nil
		},
		OnStop: func(stopCtx context.Context) error {
			p.Cancel()

			if err := p.StatsSvc.Stop(stopCtx); err != nil {
				stdlog.Printf("Unable to stop stats service. Error: %v", err)
			}

			if err := p.MonitoringSvc.Stop(stopCtx); err != nil {
				stdlog.Printf("Unable to stop backend monitoring service. Error: %v", err)
			}

			if err := p.ConnMgrSvc.Stop(stopCtx); err != nil {
				stdlog.Printf("Unable to stop connection manager service. Error: %v", err)
			}

			// Best-effort: do not spend the entire fx stop budget on shutdown waits.
			waitCtx, waitCancel := context.WithTimeout(stopCtx, definitions.FxShutdownWaitTimeout)
			waitForShutdown(waitCtx, p.Store, p.ActionWorkers)
			waitCancel()

			// Best-effort: do not let stats persistence block process termination.
			statsCtx, statsCancel := context.WithTimeout(stopCtx, definitions.FxShutdownStatsFlushTimeout)
			core.SaveStatsToRedis(statsCtx)
			statsCancel()

			lualib.StopGlobalCache()

			// Best-effort: telemetry shutdown should respect the remaining stop budget.
			telemetryCtx, telemetryCancel := context.WithTimeout(stopCtx, definitions.FxShutdownTelemetryTimeout)
			monitoring.GetTelemetry().Shutdown(telemetryCtx)
			telemetryCancel()

			return nil
		},
	})
}
