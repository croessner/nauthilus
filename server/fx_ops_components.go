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

	"github.com/croessner/nauthilus/v3/server/app/bootfx"
	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/app/loopsfx"
	"github.com/croessner/nauthilus/v3/server/app/redifx"
	"github.com/croessner/nauthilus/v3/server/app/reloadfx"
	"github.com/croessner/nauthilus/v3/server/app/restartfx"
	"github.com/croessner/nauthilus/v3/server/backend"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib/action"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/stats"

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
	// (Lua subject sources waiting for LDAP replies) and make the server appear hung.
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
		case definitions.BackendCache, definitions.BackendTest:
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

			go setupLDAPWorker(ctx, r.store, cfg, getLogger(r.store), r.store.channel)

			ldapStarted = true
		case definitions.BackendLua:
			if luaStarted {
				continue
			}

			setupLuaWorker(ctx, r.store, cfg, getLogger(r.store), r.store.redisClient, r.store.channel)

			luaStarted = true
		case definitions.BackendCache, definitions.BackendTest:
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

	stoppedHTTP, err := r.stopHTTPForRestart(opCtx, &step)
	if err != nil {
		return err
	}

	defer func() {
		r.restartHTTPAfterStop(stoppedHTTP)
	}()

	r.stopLoopServices(opCtx, logger, &step)

	reloader := &reloadOrchestrator{store: r.store, actionWorkers: r.actionWorkers}

	if err := r.stopWorkersForRestart(opCtx, reloader, &step); err != nil {
		return err
	}

	step = "rebuild_redis_client"
	cfg := getConfigFile(r.store)

	if cfg == nil {
		level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to restart without a config snapshot")
		return fmt.Errorf("config snapshot is nil")
	}

	if err := r.rebuildRedisForRestart(opCtx, cfg, logger, &step); err != nil {
		restartErr = err
	}

	r.startWorkersForRestart(reloader, &step)

	if err := r.startLoopServices(logger, &step); err != nil {
		return err
	}

	// If HTTP was stopped, it will be started in the deferred cleanup above.
	step = "done"

	return restartErr
}

// stopHTTPForRestart stops HTTP entry points before dependency graph restart work begins.
func (r *restartOrchestrator) stopHTTPForRestart(ctx context.Context, step *string) (bool, error) {
	if r.store == nil || r.store.server == nil {
		return false, nil
	}

	*step = "stop_http"

	stopContext(r.store.server)

	if err := r.waitHTTPShutdownSignals(ctx, step); err != nil {
		return true, err
	}

	return true, nil
}

// waitHTTPShutdownSignals waits for all HTTP-related shutdown signals.
func (r *restartOrchestrator) waitHTTPShutdownSignals(ctx context.Context, step *string) error {
	if r.store.signals != nil {
		if err := waitRestartDone(ctx, r.store.signals.HTTPDone(), "wait_http_done", step); err != nil {
			return err
		}

		if err := waitRestartDone(ctx, r.store.signals.HTTP3Done(), "wait_http3_done", step); err != nil {
			return err
		}
	}

	return waitRestartDone(ctx, r.store.grpcAuthorityDone, "wait_grpc_authority_done", step)
}

// restartHTTPAfterStop restarts HTTP best-effort after a restart path stopped it.
func (r *restartOrchestrator) restartHTTPAfterStop(stoppedHTTP bool) {
	if !stoppedHTTP {
		return
	}

	// Best-effort: ensure the process keeps serving HTTP even if the restart
	// operation fails or times out.
	if err := startHTTPServerWithOptions(r.ctx, r.store, httpServerStartOptions{continueHTTPOnGRPCAuthorityError: true}); err != nil {
		level.Warn(getLogger(r.store)).Log(definitions.LogKeyMsg, "Unable to start HTTP server after restart", definitions.LogKeyError, err)
	}
}

// stopLoopServices stops optional loop services before worker and Redis restart work.
func (r *restartOrchestrator) stopLoopServices(ctx context.Context, logger *slog.Logger, step *string) {
	if r.statsSvc != nil {
		*step = "stop_stats"

		if err := r.statsSvc.Stop(ctx); err != nil {
			level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to stop stats service", definitions.LogKeyError, err)
		}
	}

	if r.monitoringSvc != nil {
		*step = "stop_backend_monitoring"

		if err := r.monitoringSvc.Stop(ctx); err != nil {
			level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to stop backend monitoring service", definitions.LogKeyError, err)
		}
	}

	if r.connMgrSvc != nil {
		*step = "stop_connmgr"

		if err := r.connMgrSvc.Stop(ctx); err != nil {
			level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to stop connection manager service", definitions.LogKeyError, err)
		}
	}
}

// stopWorkersForRestart stops backend and action workers before Redis is rebuilt.
func (r *restartOrchestrator) stopWorkersForRestart(ctx context.Context, reloader *reloadOrchestrator, step *string) error {
	*step = "stop_workers"

	reloader.stopWorkersForConfig(ctx, getConfigFile(r.store))

	if r.store == nil || r.store.action == nil {
		return nil
	}

	*step = "stop_action_workers"

	stopContext(r.store.action)

	if waitForActionWorkers(ctx, r.actionWorkers) {
		return nil
	}

	*step = "wait_action_workers_done"

	return ctx.Err()
}

// rebuildRedisForRestart rebuilds the Redis client and reruns Redis setup for restart.
func (r *restartOrchestrator) rebuildRedisForRestart(ctx context.Context, cfg config.File, logger *slog.Logger, step *string) error {
	if r.redisRebuilder != nil {
		if err := r.redisRebuilder.Rebuild(cfg, logger); err != nil {
			level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to rebuild Redis client via DI", definitions.LogKeyError, err)
		}
	} else {
		rediscli.RebuildClient()
	}

	redisReadyCtx, redisReadyCancel := context.WithTimeout(ctx, definitions.RestartRedisReadyTimeout)
	defer redisReadyCancel()

	*step = "setup_redis"

	if err := setupRedis(redisReadyCtx, r.ctx, cfg, logger, r.store.redisClient); err != nil {
		// Best-effort: Redis readiness issues must not keep HTTP down indefinitely.
		level.Warn(logger).Log(definitions.LogKeyMsg, "Unable to reinitialize Redis during restart", definitions.LogKeyError, err)

		return err
	}

	return nil
}

// startWorkersForRestart starts backend and action workers after Redis setup.
func (r *restartOrchestrator) startWorkersForRestart(reloader *reloadOrchestrator, step *string) {
	*step = "start_workers"

	reloader.startWorkersForConfig(r.ctx, getConfigFile(r.store))

	if r.store == nil || r.store.action == nil {
		return
	}

	*step = "start_action_workers"
	r.store.action.ctx, r.store.action.cancel = context.WithCancel(r.ctx)

	for i := 0; i < len(r.actionWorkers); i++ {
		go r.actionWorkers[i].Work(r.store.action.ctx)
	}
}

// startLoopServices starts optional loop services after workers are available again.
func (r *restartOrchestrator) startLoopServices(logger *slog.Logger, step *string) error {
	if r.connMgrSvc != nil {
		*step = "start_connmgr"

		if err := r.connMgrSvc.Start(r.ctx); err != nil {
			level.Error(logger).Log(definitions.LogKeyMsg, "Unable to start connection manager service", definitions.LogKeyError, err)

			return err
		}
	}

	if r.monitoringSvc != nil {
		*step = "start_backend_monitoring"

		if err := r.monitoringSvc.Start(r.ctx); err != nil {
			level.Error(logger).Log(definitions.LogKeyMsg, "Unable to start backend monitoring service", definitions.LogKeyError, err)

			return err
		}
	}

	if r.statsSvc != nil {
		*step = "start_stats"

		if err := r.statsSvc.Start(r.ctx); err != nil {
			level.Error(logger).Log(definitions.LogKeyMsg, "Unable to start stats service", definitions.LogKeyError, err)

			return err
		}
	}

	return nil
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
	if !waitForServerShutdown(ctx, store) {
		return
	}

	if !waitForConfiguredBackendShutdowns(ctx, store) {
		return
	}

	waitForActionWorkers(ctx, actionWorkers)
}

// waitForBackendShutdown waits for backend worker goroutines to terminate.
//
// It returns true if the backend was recognized and waited on, or false if the backend
// type is unknown.
func waitForBackendShutdown(ctx context.Context, cfg config.File, channel backend.Channel, passDB *config.Backend) bool {
	switch passDB.Get() {
	case definitions.BackendLDAP:
		return waitForLDAPBackendShutdown(ctx, cfg, channel.GetLdapChannel())
	case definitions.BackendLua:
		return waitForLuaBackendShutdown(ctx, channel.GetLuaChannel())
	case definitions.BackendCache, definitions.BackendTest:
	default:
		level.Warn(getLogger(nil)).Log(definitions.LogKeyMsg, "Unknown backend")
	}

	return true
}

// waitForServerShutdown waits for HTTP and gRPC authority shutdown signals.
func waitForServerShutdown(ctx context.Context, store *contextStore) bool {
	if store == nil {
		return true
	}

	if store.signals != nil {
		if !waitForDone(ctx, store.signals.HTTPDone()) {
			return false
		}

		if !waitForDone(ctx, store.signals.HTTP3Done()) {
			return false
		}
	}

	return waitForDone(ctx, store.grpcAuthorityDone)
}

// waitForConfiguredBackendShutdowns waits for all configured backend workers.
func waitForConfiguredBackendShutdowns(ctx context.Context, store *contextStore) bool {
	cfg := getConfigFile(store)
	if cfg == nil || store == nil || store.channel == nil {
		return true
	}

	for _, backendType := range cfg.GetServer().GetBackends() {
		if !waitForBackendShutdown(ctx, cfg, store.channel, backendType) {
			return false
		}
	}

	return true
}

// waitForLDAPBackendShutdown waits for LDAP lookup and auth worker shutdowns.
func waitForLDAPBackendShutdown(ctx context.Context, cfg config.File, ldapChannel backend.LDAPChannel) bool {
	poolNames := ldapChannel.GetPoolNames()

	for _, poolName := range poolNames {
		if !waitForDone(ctx, ldapChannel.GetLookupEndChan(poolName)) {
			return false
		}
	}

	for _, poolName := range poolNames {
		if cfg != nil && cfg.LDAPHavePoolOnly(poolName) {
			continue
		}

		if !waitForDone(ctx, ldapChannel.GetAuthEndChan(poolName)) {
			return false
		}
	}

	return true
}

// waitForLuaBackendShutdown waits for Lua lookup worker shutdowns.
func waitForLuaBackendShutdown(ctx context.Context, luaChannel backend.LuaChannel) bool {
	for _, backendName := range luaChannel.GetBackendNames() {
		if !waitForDone(ctx, luaChannel.GetLookupEndChan(backendName)) {
			return false
		}
	}

	return true
}

// waitForActionWorkers waits until all action workers report completion.
func waitForActionWorkers(ctx context.Context, actionWorkers []*action.Worker) bool {
	for i := range actionWorkers {
		if !waitForDone(ctx, actionWorkers[i].DoneChan) {
			return false
		}
	}

	return true
}

// waitRestartDone waits for a restart signal and records the timeout step.
func waitRestartDone[T any](ctx context.Context, done <-chan T, timeoutStep string, step *string) error {
	if waitForDone(ctx, done) {
		return nil
	}

	*step = timeoutStep

	return ctx.Err()
}

// waitForDone waits for a completion channel unless the context ends first.
func waitForDone[T any](ctx context.Context, done <-chan T) bool {
	if done == nil {
		return true
	}

	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
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
