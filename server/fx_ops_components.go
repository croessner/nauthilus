// Copyright (C) 2025 Christian Rößner
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

	"github.com/croessner/nauthilus/server/app/bootfx"
	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/app/loopsfx"
	"github.com/croessner/nauthilus/server/app/redifx"
	"github.com/croessner/nauthilus/server/app/reloadfx"
	"github.com/croessner/nauthilus/server/app/restartfx"
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"

	"go.uber.org/fx"
)

// reloadOrchestrator is a Reloadable implementation that bridges the reload manager
// to the current legacy reload behavior.
//
// It is intentionally conservative: it performs a best-effort reload (without stopping
// the HTTP server) and delegates to existing helpers for worker/Redis/script handling.
type reloadOrchestrator struct {
	store          *contextStore
	actionWorkers  []*action.Worker
	monitoringSvc  *loopsfx.BackendMonitoringService
	redisRebuilder redifx.Rebuilder
}

const (
	reloadTimeout  = definitions.ReloadOperationTimeout
	restartTimeout = definitions.RestartOperationTimeout
)

func (r *reloadOrchestrator) Name() string {
	return "reloadOrchestrator"
}

func (r *reloadOrchestrator) Order() int {
	return 100
}

func (r *reloadOrchestrator) ApplyConfig(ctx context.Context, snap configfx.Snapshot) error {
	opCtx, cancel := context.WithTimeout(ctx, reloadTimeout)
	defer cancel()

	prev, ok := reloadfx.PreviousSnapshotFromContext(ctx)
	if !ok {
		prev = snap
	}

	logger := getLogger(r.store)

	level.Info(logger).Log(definitions.LogKeyMsg, "Reloading Nauthilus", "signal", "SIGHUP")

	// Important: Keep the request path stable during reload.
	// Stopping/restarting LDAP/Lua workers and rebuilding Redis can stall in-flight requests
	// (Lua filters waiting for LDAP replies) and make the server appear hung.
	// A full in-process rebuild belongs to the explicit restart path.
	//
	// We still reload the config snapshot (handled by reloadfx.Manager) and apply best-effort
	// runtime config changes that do not require stopping backends.
	_ = prev
	_ = opCtx
	r.reloadLogging(snap.File)

	bootfx.DebugLoadableConfig(snap.File, logger)

	if err := bootfx.SetupLuaScripts(snap.File, logger); err != nil {
		level.Error(logger).Log(definitions.LogKeyMsg, "Unable to setup Lua scripts", definitions.LogKeyError, err)
	} else {
		bootfx.RunLuaInitScript(ctx, snap.File, logger, r.store.redisClient)
	}

	bootfx.EnableBlockProfile(snap.File)
	r.restartMonitoring(ctx)
	stats.GetReloader().Reload()

	level.Debug(logger).Log(definitions.LogKeyMsg, "Reload complete")

	return nil
}

func (r *reloadOrchestrator) stopWorkersForConfig(ctx context.Context, cfg config.File) {
	if cfg == nil {
		cfg = getConfigFile(r.store)
	}

	if cfg == nil {
		return
	}

	for _, backendType := range cfg.GetServer().GetBackends() {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			r.stopLDAP(ctx, cfg)
		case definitions.BackendLua:
			r.stopLua(ctx)
		case definitions.BackendCache:
		default:
			level.Warn(getLogger(r.store)).Log(definitions.LogKeyMsg, "Unknown backend")
		}
	}
}

func (r *reloadOrchestrator) stopLDAP(ctx context.Context, cfg config.File) {
	if r.store == nil || r.store.ldapLookup == nil || r.store.ldapAuth == nil || r.store.channel == nil {
		return
	}

	stopContext(r.store.ldapLookup)

	poolNames := r.store.channel.GetLdapChannel().GetPoolNames()
	for _, poolName := range poolNames {
		select {
		case <-r.store.channel.GetLdapChannel().GetLookupEndChan(poolName):
		case <-ctx.Done():
			return
		}
	}

	stopContext(r.store.ldapAuth)
	for _, poolName := range poolNames {
		if !cfg.LDAPHavePoolOnly(poolName) {
			select {
			case <-r.store.channel.GetLdapChannel().GetAuthEndChan(poolName):
			case <-ctx.Done():
				return
			}
		}
	}
}

func (r *reloadOrchestrator) stopLua(ctx context.Context) {
	if r.store == nil || r.store.lua == nil || r.store.channel == nil {
		return
	}

	stopContext(r.store.lua)

	for _, backendName := range r.store.channel.GetLuaChannel().GetBackendNames() {
		select {
		case <-r.store.channel.GetLuaChannel().GetLookupEndChan(backendName):
		case <-ctx.Done():
			return
		}
	}
}

func (r *reloadOrchestrator) reloadLogging(cfg config.File) {
	if cfg == nil {
		return
	}

	log.SetupLogging(
		cfg.GetServer().GetLog().GetLogLevel(),
		cfg.GetServer().GetLog().IsLogFormatJSON(),
		cfg.GetServer().GetLog().IsLogUsesColor(),
		cfg.GetServer().GetLog().IsAddSourceEnabled(),
		cfg.GetServer().GetInstanceName(),
	)
}

func (r *reloadOrchestrator) startWorkersForConfig(ctx context.Context, cfg config.File) {
	if r.store == nil || cfg == nil {
		return
	}

	var ldapStarted bool
	var luaStarted bool

	for _, backendType := range cfg.GetServer().GetBackends() {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			if ldapStarted {
				continue
			}

			go setupLDAPWorker(r.store, ctx, cfg, getLogger(r.store), r.store.channel)
			ldapStarted = true
		case definitions.BackendLua:
			if luaStarted {
				continue
			}

			setupLuaWorker(r.store, ctx, cfg, getLogger(r.store), r.store.redisClient, r.store.channel)

			luaStarted = true
		case definitions.BackendCache:
		default:
			level.Warn(getLogger(r.store)).Log(definitions.LogKeyMsg, "Unknown backend", "backend")
		}
	}
}

func (r *reloadOrchestrator) restartMonitoring(ctx context.Context) {
	if r.monitoringSvc == nil {
		return
	}

	restartCtx, cancel := context.WithTimeout(ctx, definitions.BackendMonitoringReloadTimeout)
	defer cancel()

	if err := r.monitoringSvc.Restart(restartCtx); err != nil {
		level.Warn(getLogger(r.store)).Log(definitions.LogKeyMsg, "Unable to restart backend monitoring", definitions.LogKeyError, err)
	}
}

// restartOrchestrator is a Restartable implementation that performs an in-process restart.
//
// The restart is intentionally more disruptive than a reload:
// it stops HTTP, stops loop services, stops workers, rebuilds Redis, then starts workers,
// loop services, and finally HTTP again.
//
// The goal is to leave the process in a state comparable to a fresh start.
type restartOrchestrator struct {
	ctx context.Context

	store         *contextStore
	actionWorkers []*action.Worker

	statsSvc       *loopsfx.StatsService
	monitoringSvc  *loopsfx.BackendMonitoringService
	connMgrSvc     *loopsfx.ConnMgrService
	redisRebuilder redifx.Rebuilder
}

func (r *restartOrchestrator) Name() string {
	return "restartOrchestrator"
}

func (r *restartOrchestrator) Order() int {
	return 100
}

func (r *restartOrchestrator) Restart(ctx context.Context) error {
	// Use a time-bounded context for stop/rebuild coordination.
	// Long-running background tasks should be started with the long-lived process context.
	opCtx, cancel := context.WithTimeout(ctx, restartTimeout)
	defer cancel()

	logger := getLogger(r.store)
	level.Info(logger).Log(definitions.LogKeyMsg, "Restarting Nauthilus", "signal", "SIGUSR1")
	start := time.Now()
	step := "init"

	defer func() {
		level.Debug(logger).Log(definitions.LogKeyMsg, "Restart finished", "step", step, "elapsed", time.Since(start))
	}()

	var restartErr error
	stoppedHTTP := false

	defer func() {
		if !stoppedHTTP {
			return
		}

		// Best-effort: ensure the process keeps serving HTTP even if the restart
		// operation fails or times out.
		if err := startHTTPServer(r.ctx, r.store); err != nil {
			level.Warn(getLogger(r.store)).Log(definitions.LogKeyMsg, "Unable to start HTTP server after restart", definitions.LogKeyError, err)
		}
	}()

	// Stop HTTP first to avoid serving requests with a partially restarted dependency graph.
	if r.store != nil && r.store.server != nil {
		step = "stop_http"
		stopContext(r.store.server)
		stoppedHTTP = true

		if r.store.signals != nil && r.store.signals.HTTPDone() != nil {
			select {
			case <-r.store.signals.HTTPDone():
			case <-opCtx.Done():
				step = "wait_http_done"
				restartErr = opCtx.Err()

				return restartErr
			}
		}

		if r.store.signals != nil && r.store.signals.HTTP3Done() != nil {
			select {
			case <-r.store.signals.HTTP3Done():
			case <-opCtx.Done():
				step = "wait_http3_done"
				restartErr = opCtx.Err()

				return restartErr
			}
		}
	}

	// Stop loops early to reduce load while dependencies restart.
	if r.statsSvc != nil {
		step = "stop_stats"
		if err := r.statsSvc.Stop(opCtx); err != nil {
			level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to stop stats service", definitions.LogKeyError, err)
		}
	}

	if r.monitoringSvc != nil {
		step = "stop_backend_monitoring"
		if err := r.monitoringSvc.Stop(opCtx); err != nil {
			level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to stop backend monitoring service", definitions.LogKeyError, err)
		}
	}

	if r.connMgrSvc != nil {
		step = "stop_connmgr"
		if err := r.connMgrSvc.Stop(opCtx); err != nil {
			level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to stop connection manager service", definitions.LogKeyError, err)
		}
	}

	reloader := &reloadOrchestrator{store: r.store, actionWorkers: r.actionWorkers}

	// Stop workers (LDAP/Lua) and action workers before rebuilding Redis.
	step = "stop_workers"
	reloader.stopWorkersForConfig(opCtx, getConfigFile(r.store))

	if r.store != nil && r.store.action != nil {
		step = "stop_action_workers"
		stopContext(r.store.action)
		for i := 0; i < len(r.actionWorkers); i++ {
			select {
			case <-r.actionWorkers[i].DoneChan:
			case <-opCtx.Done():
				step = "wait_action_workers_done"
				restartErr = opCtx.Err()
				return restartErr
			}
		}
	}

	step = "rebuild_redis_client"
	cfg := getConfigFile(r.store)

	if cfg == nil {
		level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to restart without a config snapshot")
		return fmt.Errorf("config snapshot is nil")
	}

	if r.redisRebuilder != nil {
		if err := r.redisRebuilder.Rebuild(cfg, logger); err != nil {
			level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to rebuild Redis client via DI", definitions.LogKeyError, err)
		}
	} else {
		rediscli.RebuildClient()
	}

	redisReadyCtx, redisReadyCancel := context.WithTimeout(opCtx, definitions.RestartRedisReadyTimeout)
	defer redisReadyCancel()

	step = "setup_redis"
	if err := setupRedis(redisReadyCtx, r.ctx, cfg, logger, r.store.redisClient); err != nil {
		// Best-effort: Redis readiness issues must not keep HTTP down indefinitely.
		level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to reinitialize Redis during restart", definitions.LogKeyError, err)
		restartErr = err
	}

	// Start workers (LDAP/Lua) and action workers after Redis is ready.
	step = "start_workers"
	reloader.startWorkersForConfig(r.ctx, getConfigFile(r.store))

	if r.store != nil && r.store.action != nil {
		step = "start_action_workers"
		r.store.action.ctx, r.store.action.cancel = context.WithCancel(r.ctx)
		for i := 0; i < len(r.actionWorkers); i++ {
			go r.actionWorkers[i].Work(r.store.action.ctx)
		}
	}

	if r.connMgrSvc != nil {
		step = "start_connmgr"
		if err := r.connMgrSvc.Start(r.ctx); err != nil {
			level.Error(logger).Log(definitions.LogKeyMsg, "Unable to start connection manager service", definitions.LogKeyError, err)

			restartErr = err

			return restartErr
		}
	}

	if r.monitoringSvc != nil {
		step = "start_backend_monitoring"
		if err := r.monitoringSvc.Start(r.ctx); err != nil {
			level.Error(logger).Log(definitions.LogKeyMsg, "Unable to start backend monitoring service", definitions.LogKeyError, err)

			restartErr = err

			return restartErr
		}
	}

	if r.statsSvc != nil {
		step = "start_stats"
		if err := r.statsSvc.Start(r.ctx); err != nil {
			level.Error(logger).Log(definitions.LogKeyMsg, "Unable to start stats service", definitions.LogKeyError, err)

			restartErr = err

			return restartErr
		}
	}

	// If HTTP was stopped, it will be started in the deferred cleanup above.
	step = "done"
	return restartErr
}

// newReloadOrchestrator registers the reload orchestrator as a grouped reloadable.
func newReloadOrchestrator(store *contextStore, monitoringSvc *loopsfx.BackendMonitoringService, actionWorkers []*action.Worker, redisRebuilder redifx.Rebuilder) (struct {
	fx.Out
	Reloadable reloadfx.Reloadable `group:"reloadables"`
}, error) {
	if store == nil {
		return struct {
			fx.Out
			Reloadable reloadfx.Reloadable `group:"reloadables"`
		}{}, fmt.Errorf("context store is nil")
	}

	return struct {
		fx.Out
		Reloadable reloadfx.Reloadable `group:"reloadables"`
	}{
		Reloadable: &reloadOrchestrator{store: store, actionWorkers: actionWorkers, monitoringSvc: monitoringSvc, redisRebuilder: redisRebuilder},
	}, nil
}

// newRestartOrchestrator registers the restart orchestrator as a grouped restartable.
func newRestartOrchestrator(
	ctx context.Context,
	store *contextStore,
	actionWorkers []*action.Worker,
	statsSvc *loopsfx.StatsService,
	monitoringSvc *loopsfx.BackendMonitoringService,
	connMgrSvc *loopsfx.ConnMgrService,
	redisRebuilder redifx.Rebuilder,
) (struct {
	fx.Out
	Restartable restartfx.Restartable `group:"restartables"`
}, error) {
	if store == nil {
		return struct {
			fx.Out
			Restartable restartfx.Restartable `group:"restartables"`
		}{}, fmt.Errorf("context store is nil")
	}

	return struct {
		fx.Out
		Restartable restartfx.Restartable `group:"restartables"`
	}{
		Restartable: &restartOrchestrator{
			ctx:            ctx,
			store:          store,
			actionWorkers:  actionWorkers,
			statsSvc:       statsSvc,
			monitoringSvc:  monitoringSvc,
			connMgrSvc:     connMgrSvc,
			redisRebuilder: redisRebuilder,
		},
	}, nil
}

// waitForShutdown performs time-bounded waits for shutdown-related signals and workers.
//
// This keeps behavior parity with the legacy shutdown coordinator while avoiding
// indefinite blocking during fx shutdown.
func waitForShutdown(ctx context.Context, store *contextStore, actionWorkers []*action.Worker) {
	if store != nil {
		signals := store.signals
		if signals != nil && signals.HTTPDone() != nil {
			select {
			case <-signals.HTTPDone():
			case <-ctx.Done():
				return
			}
		}
		if signals != nil && signals.HTTP3Done() != nil {
			select {
			case <-signals.HTTP3Done():
			case <-ctx.Done():
				return
			}
		}
	}

	cfg := getConfigFile(store)
	if cfg != nil && store != nil && store.channel != nil {
		for _, backendType := range cfg.GetServer().GetBackends() {
			if !waitForBackendShutdown(ctx, cfg, store.channel, backendType) {
				return
			}
		}
	}

	for i := range actionWorkers {
		select {
		case <-actionWorkers[i].DoneChan:
		case <-ctx.Done():
			return
		}
	}
}

// waitForBackendShutdown waits for backend worker goroutines to terminate.
//
// It returns true if the backend was recognized and waited on, or false if the backend
// type is unknown.
func waitForBackendShutdown(ctx context.Context, cfg config.File, channel backend.Channel, passDB *config.Backend) bool {
	switch passDB.Get() {
	case definitions.BackendLDAP:
		poolNames := channel.GetLdapChannel().GetPoolNames()
		for _, poolName := range poolNames {
			select {
			case <-channel.GetLdapChannel().GetLookupEndChan(poolName):
			case <-ctx.Done():
				return false
			}
		}

		for _, poolName := range poolNames {
			if cfg != nil && cfg.LDAPHavePoolOnly(poolName) {
				continue
			}

			select {
			case <-channel.GetLdapChannel().GetAuthEndChan(poolName):
			case <-ctx.Done():
				return false
			}
		}
	case definitions.BackendLua:
		for _, backendName := range channel.GetLuaChannel().GetBackendNames() {
			select {
			case <-channel.GetLuaChannel().GetLookupEndChan(backendName):
			case <-ctx.Done():
				return false
			}
		}
	case definitions.BackendCache:
	default:
		level.Warn(getLogger(nil)).Log(definitions.LogKeyMsg, "Unknown backend")
	}

	return true
}

// getLogger returns the injected logger if available.
//
// It falls back to `slog.Default()` to avoid relying on package-level globals.
func getLogger(store *contextStore) *slog.Logger {
	if store != nil && store.logger != nil {
		return store.logger
	}

	return slog.Default()
}

func getConfigFile(store *contextStore) config.File {
	if store != nil && store.cfgProvider != nil {
		if snap := store.cfgProvider.Current(); snap.File != nil {
			return snap.File
		}
	}

	return nil
}
