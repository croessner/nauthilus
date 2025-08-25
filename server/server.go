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
	stderrors "errors"
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/lualib/hook"
	"github.com/croessner/nauthilus/server/monitoring"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	kitlog "github.com/go-kit/log"
	"github.com/go-kit/log/level"
	jsoniter "github.com/json-iterator/go"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"golang.org/x/text/language"
)

// json is a package-level variable for jsoniter with standard configuration
var json = jsoniter.ConfigFastest

// contextTuple represents a tuple that contains a context and a cancel function.
// This type is used for managing contexts and cancellations in various parts of the application.
type contextTuple struct {
	ctx    context.Context
	cancel context.CancelFunc
}

type backendServersAlive struct {
	servers []*config.BackendServer
	mu      sync.Mutex
}

// contextStore is a custom structure in which instances of contextTuple are stored for various functionalities.
// The structure contains the following fields: ldapLookup, ldapAuth, lua, action, backendServerMonitoring and server.
// Each field is a pointer to an instance of contextTuple type. This structure allows for efficient context storage for different processes.
type contextStore struct {
	ldapLookup              *contextTuple
	ldapAuth                *contextTuple
	lua                     *contextTuple
	action                  *contextTuple
	backendServerMonitoring *contextTuple
	server                  *contextTuple
}

// newContextStore creates and initializes a new instance of the contextStore structure and returns a pointer to it.
func newContextStore() *contextStore {
	store := &contextStore{}

	return store
}

// newContextTuple creates a new contextTuple with a derived context and cancel function from the provided parent context.
// It manages the lifecycle of the derived context and its cancellation.
func newContextTuple(ctx context.Context) *contextTuple {
	tuple := &contextTuple{}
	tuple.ctx, tuple.cancel = context.WithCancel(ctx)

	return tuple
}

// setupConfiguration initializes the application GetEnvironment() by configuring settings, loading resources, and setting up logging.
func setupConfiguration() (err error) {
	config.NewEnvironmentConfig()

	setTimeZone()

	// If a specific configuration file is provided via the -config flag, check if it exists
	if config.ConfigFilePath != "" {
		if _, err := os.Stat(config.ConfigFilePath); os.IsNotExist(err) {
			return fmt.Errorf("specified configuration file does not exist: %s", config.ConfigFilePath)
		}
	}

	file, err := config.NewFile()
	if err != nil {
		return fmt.Errorf("unable to load config file: %w", err)
	}

	if file.GetServer().Frontend.Enabled {
		loadLanguageBundles()
	}

	log.SetupLogging(
		file.GetServer().GetLog().GetLogLevel(),
		file.GetServer().GetLog().IsLogFormatJSON(),
		file.GetServer().GetLog().IsLogUsesColor(),
		file.GetServer().GetInstanceName(),
	)
	stdlog.SetOutput(kitlog.NewStdlibAdapter(log.Logger))

	return nil
}

// loadLanguageBundles initializes the core language bundle and loads language files for English, German, and French.
func loadLanguageBundles() {
	core.LangBundle = i18n.NewBundle(language.English)

	core.LangBundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	loadLanguageBundle("en")
	loadLanguageBundle("de")
	loadLanguageBundle("fr")
}

// loadLanguageBundle loads a language-specific JSON file into the language bundle for localization purposes.
// It requires the language code `lang` and panics if the file cannot be loaded or parsed.
func loadLanguageBundle(lang string) {
	if _, err := core.LangBundle.LoadMessageFile(viper.GetString("language_resources") + "/" + lang + ".json"); err != nil {
		panic(err.Error())
	}
}

// setTimeZone configures the application's time zone based on the TZ GetEnvironment() variable, logging any errors encountered.
func setTimeZone() {
	var err error

	// Manually set time zone
	if tz := os.Getenv("TZ"); tz != "" {
		if time.Local, err = time.LoadLocation(tz); err != nil {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Error loading location '%s': %v", tz, err),
			)
		}
	}
}

// setupLuaScripts pre-compiles Lua scripts for features, filters, initialization, and hooks, returning an error on failure.
func setupLuaScripts() error {
	if err := PreCompileFeatures(); err != nil {
		return err
	}

	if err := PreCompileFilters(); err != nil {
		return err
	}

	if err := PreCompileInit(); err != nil {
		return err
	}

	if err := PreCompileHooks(); err != nil {
		return err
	}

	return nil
}

// PreCompileFeatures pre-compiles Lua features if the Lua feature is enabled in the configuration.
// Returns an error if the pre-compilation of Lua features fails, otherwise returns nil.
func PreCompileFeatures() error {
	if !config.GetFile().HasFeature(definitions.FeatureLua) {
		return nil
	}

	if err := feature.PreCompileLuaFeatures(); err != nil {
		return err
	}

	return nil
}

// PreCompileFilters pre-compiles Lua filters if they are enabled in the configuration.
// Returns an error if the pre-compilation fails, otherwise returns nil.
func PreCompileFilters() error {
	if !config.GetFile().HaveLuaFilters() {
		return nil
	}

	if err := filter.PreCompileLuaFilters(); err != nil {
		return err
	}

	return nil
}

// PreCompileInit pre-compiles the Lua initialization scripts if specified in the configuration. Returns an error if it fails.
func PreCompileInit() error {
	if !config.GetFile().HaveLuaInit() {
		return nil
	}

	// Get all init script paths
	initScriptPaths := config.GetFile().GetLuaInitScriptPaths()

	// Compile each init script
	for _, scriptPath := range initScriptPaths {
		if err := hook.PreCompileLuaScript(scriptPath); err != nil {
			return err
		}
	}

	return nil
}

// PreCompileHooks pre-compiles Lua hooks if they are enabled in the configuration; returns an error on failure or nil otherwise.
func PreCompileHooks() error {
	if !config.GetFile().HaveLuaHooks() {
		return nil
	}

	if err := hook.PreCompileLuaHooks(); err != nil {
		return err
	}

	return nil
}

// handleSignals sets up concurrent signal handlers for termination, reload, and user-defined signals.
// It receives a context, cancel function, context store, statistics ticker, monitoring ticker, and action workers as parameters.
func handleSignals(ctx context.Context, cancel context.CancelFunc, store *contextStore, statsTicker *time.Ticker, ngxMonitoringTicker **time.Ticker, actionWorkers []*action.Worker) {
	go handleTerminateSignal(ctx, cancel, statsTicker, *ngxMonitoringTicker, actionWorkers)
	go handleUsr1Signal(ctx, store)
	go handleReloadSignal(ctx, store, ngxMonitoringTicker, actionWorkers)
}

// closeChannels closes the HTTPEndChan and WorkerEndChan channels.
func closeChannels() {
	close(core.HTTPEndChan)
	close(core.HTTP3EndChan)
}

// handleTerminateSignal handles termination signals like SIGINT and SIGTERM for gracefully shutting down the application.
// It cancels context, stops tickers, waits for HTTP servers and action workers to conclude, and saves stats to Redis.
func handleTerminateSignal(ctx context.Context, cancel context.CancelFunc, statsTicker *time.Ticker, ngxMonitoringTicker *time.Ticker, actionWorkers []*action.Worker) {
	sigsTerminate := make(chan os.Signal, 1)

	signal.Notify(sigsTerminate, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigsTerminate

	level.Info(log.Logger).Log(definitions.LogKeyMsg, "Shutting down Nauthilus", "signal", sig)

	cancel()

	// Wait for HTTP server termination
	<-core.HTTPEndChan

	if config.GetFile().GetServer().IsHTTP3Enabled() {
		<-core.HTTP3EndChan
	}

	for _, backendType := range config.GetFile().GetServer().GetBackends() {
		handleBackend(backendType)
	}

	waitForActionWorkers(actionWorkers)

	// Sync some Prometheus data to Redis
	core.SaveStatsToRedis(ctx)

	level.Debug(log.Logger).Log(definitions.LogKeyMsg, "Shutdown complete")

	// Stop background janitors and process-wide resources
	lualib.StopGlobalCache()

	closeChannels()

	statsTicker.Stop()
	ngxMonitoringTicker.Stop()
}

// handleUsr1Signal listens for SIGUSR1 signals to trigger server restarts for updating or refreshing server processes.
func handleUsr1Signal(ctx context.Context, store *contextStore) {
	sigsReload := make(chan os.Signal, 1)

	signal.Notify(sigsReload, syscall.SIGUSR1)

	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigsReload:
			handleServerRestart(ctx, store, sig)
		}
	}
}

// handleReloadSignal listens for SIGHUP signals to initiate configuration reloads for various services in the application.
// It operates within a context, responding to cancellation or signal-triggered reloads as appropriate.
func handleReloadSignal(ctx context.Context, store *contextStore, ngxMonitoringTicker **time.Ticker, actionWorkers []*action.Worker) {
	sigsReload := make(chan os.Signal, 1)

	signal.Notify(sigsReload, syscall.SIGHUP)

	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigsReload:
			handleReload(ctx, store, sig, ngxMonitoringTicker, actionWorkers)
		}
	}
}

// handleBackend gracefully handles shutdown or cleanup for the specified backend type based on the passed configuration.
func handleBackend(passDB *config.Backend) {
	switch passDB.Get() {
	case definitions.BackendLDAP:
		poolNames := backend.GetChannel().GetLdapChannel().GetPoolNames()

		for _, poolName := range poolNames {
			<-backend.GetChannel().GetLdapChannel().GetLookupEndChan(poolName)
		}

		for _, poolName := range poolNames {
			if !config.GetFile().LDAPHavePoolOnly(poolName) {
				<-backend.GetChannel().GetLdapChannel().GetAuthEndChan(poolName)
			}
		}
	case definitions.BackendLua:
		for _, backendName := range backend.GetChannel().GetLuaChannel().GetBackendNames() {
			<-backend.GetChannel().GetLuaChannel().GetLookupEndChan(backendName)
		}
	case definitions.BackendCache:
	default:
		level.Warn(log.Logger).Log(definitions.LogKeyMsg, "Unknown backend")
	}
}

// handleLDAPBackend manages the shutdown process for the LDAP backend by stopping contexts and waiting for termination signals.
func handleLDAPBackend(lookup, auth *contextTuple) {
	stopContext(lookup)

	poolNames := backend.GetChannel().GetLdapChannel().GetPoolNames()

	for _, poolName := range poolNames {
		<-backend.GetChannel().GetLdapChannel().GetLookupEndChan(poolName)
	}

	stopContext(auth)

	for _, poolName := range poolNames {
		if !config.GetFile().LDAPHavePoolOnly(poolName) {
			<-backend.GetChannel().GetLdapChannel().GetAuthEndChan(poolName)
		}
	}
}

// handleLuaBackend manages the shutdown process for the Lua backend by stopping its context and waiting for termination signals.
func handleLuaBackend(lua *contextTuple) {
	stopContext(lua)

	for _, backendName := range backend.GetChannel().GetLuaChannel().GetBackendNames() {
		<-backend.GetChannel().GetLuaChannel().GetLookupEndChan(backendName)
	}
}

// stopAndRestartActionWorker stops the current action context, waits for workers to complete, and restarts them with a new context.
func stopAndRestartActionWorker(actionWorkers []*action.Worker, act *contextTuple, ctx context.Context) {
	stopContext(act)

	waitForActionWorkers(actionWorkers)

	act.ctx, act.cancel = context.WithCancel(ctx)

	startActionWorker(actionWorkers, act)
}

// stopAndRestartRedis gracefully stops the Redis read and write clients, then reinitializes the Redis setup.
func stopAndRestartRedis(ctx context.Context) {
	rediscli.GetClient().Close()

	setupRedis(ctx)
}

// waitForActionWorkers waits for the completion of all action workers.
// It takes in an array of action workers and waits for each worker's DoneChan to receive a value.
func waitForActionWorkers(actionWorkers []*action.Worker) {
	for i := 0; i < len(actionWorkers); i++ {
		<-actionWorkers[i].DoneChan
	}
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

// startLDAPWorkers initializes and starts LDAP worker routines for lookup and authentication based on the configuration.
// It launches the `LDAPMainWorker` for processing LDAP requests and, if applicable, `LDAPAuthWorker` for authentication.
func startLDAPWorkers(store *contextStore) {
	for _, ldapBackend := range config.GetFile().GetServer().GetBackends() {
		if ldapBackend.GetName() != "" && ldapBackend.Get() != definitions.BackendLDAP {
			continue
		}

		backend.GetChannel().GetLdapChannel().AddChannel(ldapBackend.GetName())
		backend.LDAPMainWorker(store.ldapLookup.ctx, ldapBackend.GetName())

		if !config.GetFile().LDAPHavePoolOnly(ldapBackend.GetName()) {
			backend.LDAPAuthWorker(store.ldapAuth.ctx, ldapBackend.GetName())
		}
	}
}

// startLuaWorkers starts a goroutine that runs the backend.LuaMainWorker function
func startLuaWorkers(store *contextStore) {
	for _, luaBackend := range config.GetFile().GetServer().GetBackends() {
		if luaBackend.GetName() != "" && luaBackend.Get() != definitions.BackendLua {
			continue
		}

		backend.GetChannel().GetLuaChannel().AddChannel(luaBackend.GetName())
		backend.LuaMainWorker(store.lua.ctx, luaBackend.GetName())
	}
}

// handleServerRestart handles the server restart process. It stops the server, waits for the HTTP server to stop,
// and then starts the HTTP server again with the given context and contextStore.
func handleServerRestart(ctx context.Context, store *contextStore, sig os.Signal) {
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Restarting Nauthilus", "signal", sig,
	)

	stopContext(store.server)

	<-core.HTTPEndChan

	if config.GetFile().GetServer().IsHTTP3Enabled() {
		<-core.HTTP3EndChan
	}

	startHTTPServer(ctx, store)
}

// handleReload reloads the server configurations, restarts backend workers, and applies the new settings dynamically.
func handleReload(ctx context.Context, store *contextStore, sig os.Signal, ngxMonitoringTicker **time.Ticker, actionWorkers []*action.Worker) {
	var (
		ldapStopped bool
		ldapStarted bool
		luaStopped  bool
		luaStarted  bool
	)

	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Reloading Nauthilus", "signal", sig,
	)

	for _, backendType := range config.GetFile().GetServer().GetBackends() {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			if ldapStopped {
				continue
			}

			handleLDAPBackend(store.ldapLookup, store.ldapAuth)

			ldapStopped = true
		case definitions.BackendLua:
			if luaStopped {
				continue
			}

			handleLuaBackend(store.lua)

			luaStopped = true
		case definitions.BackendCache:
		default:
			level.Warn(log.Logger).Log(definitions.LogKeyMsg, "Unknown backend")
		}
	}

	stopAndRestartActionWorker(actionWorkers, store.action, ctx)
	stopAndRestartRedis(ctx)

	if err := config.ReloadConfigFile(); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, err,
		)
	} else {
		log.SetupLogging(
			config.GetFile().GetServer().GetLog().GetLogLevel(),
			config.GetFile().GetServer().GetLog().IsLogFormatJSON(),
			config.GetFile().GetServer().GetLog().IsLogUsesColor(),
			config.GetFile().GetServer().GetInstanceName(),
		)

		debugLoadableConfig()
	}

	if err := setupLuaScripts(); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, "Unable to setup Lua scripts",
			definitions.LogKeyMsg, err,
		)
	}

	enableBlockProfile()

	for _, backendType := range config.GetFile().GetServer().GetBackends() {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			if ldapStarted {
				continue
			}

			setupLDAPWorker(store, ctx)

			ldapStarted = true
		case definitions.BackendLua:
			if luaStarted {
				continue
			}

			setupLuaWorker(store, ctx)

			luaStarted = true
		case definitions.BackendCache:
		default:
			level.Warn(log.Logger).Log(definitions.LogKeyMsg, "Unknown backend")
		}
	}

	restartNgxMonitoring(ctx, store, ngxMonitoringTicker)

	stats.GetReloader().Reload()

	level.Debug(log.Logger).Log(
		definitions.LogKeyMsg, "Reload complete",
	)
}

// initializeActionWorkers creates and initializes a slice of action workers based on the maximum workers configuration.
func initializeActionWorkers() []*action.Worker {
	var workers []*action.Worker

	for i := 0; i < int(config.GetEnvironment().GetMaxActionWorkers()); i++ {
		workers = append(workers, action.NewWorker())
	}

	return workers
}

// setupWorkers initializes action workers and backend workers (LDAP, Lua, etc.) based on the provided configuration.
func setupWorkers(ctx context.Context, store *contextStore, actionWorkers []*action.Worker) {
	var (
		ldapStarted bool
		luaStarted  bool
	)

	startActionWorker(actionWorkers, store.action)

	for _, backendType := range config.GetFile().GetServer().GetBackends() {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			if ldapStarted {
				continue
			}

			setupLDAPWorker(store, ctx)

			ldapStarted = true
		case definitions.BackendLua:
			if luaStarted {
				continue
			}

			setupLuaWorker(store, ctx)

			luaStarted = true
		case definitions.BackendCache:
		default:
			level.Warn(log.Logger).Log(definitions.LogKeyMsg, "Unknown backend", "backend")
		}
	}
}

// setupLDAPWorker initializes the LDAP worker contexts and starts LDAP worker routines for processing requests and authentication.
func setupLDAPWorker(store *contextStore, ctx context.Context) {
	store.ldapLookup = newContextTuple(ctx)
	store.ldapAuth = newContextTuple(ctx)

	startLDAPWorkers(store)
}

// setupLuaWorker initializes the Lua worker context, channels, and starts the Lua worker goroutine.
func setupLuaWorker(store *contextStore, ctx context.Context) {
	store.lua = newContextTuple(ctx)

	startLuaWorkers(store)
}

// checkRedisConnections validates the availability of both write and read Redis connections using Ping commands.
func checkRedisConnections(ctx context.Context) bool {
	if rediscli.GetClient().GetWriteHandle() == nil {
		return false
	}

	if err := rediscli.GetClient().GetWriteHandle().Ping(ctx).Err(); err != nil {
		return false
	}

	if rediscli.GetClient().GetReadHandle() == nil {
		return false
	}

	if err := rediscli.GetClient().GetReadHandle().Ping(ctx).Err(); err != nil {
		return false
	}

	return true
}

// setupRedis sets up the Redis client and its replicas. It ensures connections are valid with a retry mechanism on failure.
func setupRedis(ctx context.Context) {
	redisLogger := &util.RedisLogger{}
	redis.SetLogger(redisLogger)

	// Retry mechanism to ensure the Redis connections are usable
	maxRetries := 10
	retryInterval := 5 * time.Second

	for retries := 0; retries < maxRetries; retries++ {
		if checkRedisConnections(ctx) {
			go core.UpdateRedisPoolStats()
			go rediscli.UpdateRedisServerMetrics(ctx)

			// Upload all Lua scripts to Redis at startup
			go func() {
				err := rediscli.UploadAllScripts(ctx)
				if err != nil {
					level.Warn(log.Logger).Log(
						definitions.LogKeyMsg, "Failed to upload all Redis Lua scripts at startup",
						"error", err,
					)
				}
			}()

			return
		}

		level.Warn(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Redis not ready yet. Retry %d/%d", retries+1, maxRetries))

		time.Sleep(retryInterval)
	}

	panic("Failed to establish Redis connections after max retries")
}

// startHTTPServer starts the HTTP server by initializing the context, setting up channels, and launching the HTTP application.
func startHTTPServer(ctx context.Context, store *contextStore) {
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Starting Nauthilus HTTP server",
		"license", "GPL-3.0",
		"author", "Christian Rößner",
		"homepage", "https://nauthilus.org",
		"copyright", "2025",
		"version", version,
		"build_time", buildTime,
	)

	store.server = newContextTuple(ctx)

	if core.HTTPEndChan == nil {
		core.HTTPEndChan = make(chan core.Done)
	}

	if config.GetFile().GetServer().IsHTTP3Enabled() {
		if core.HTTP3EndChan == nil {
			core.HTTP3EndChan = make(chan core.Done)
		}
	}

	go core.HTTPApp(store.server.ctx)
}

// startStatsLoop runs a loop that periodically gathers and stores system statistics using a given ticker and context.
// It measures CPU usage, prints memory statistics, and saves stats to Redis.
// The function terminates gracefully when the provided context is canceled.
// Returns an error if the context is canceled.
func startStatsLoop(ctx context.Context, ticker *time.Ticker) error {
	go stats.MeasureCPU(ctx)

	for {
		select {
		case <-ticker.C:
			stats.PrintStats()
			core.SaveStatsToRedis(ctx)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// logBackendServerError logs an error when a backend server is down, with the server details and error message as context.
func logBackendServerError(server *config.BackendServer, err error) {
	level.Error(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Backend server failed: %s:%d (%s) - Error: %v",
			server.Host, server.Port, server.Protocol, err),
		definitions.LogKeyBackendServer, server,
	)
}

// logBackendServerDebug logs debug information about a backend server, primarily its availability status.
func logBackendServerDebug(server *config.BackendServer) {
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Backend server alive: %s:%d (%s)",
			server.Host, server.Port, server.Protocol),
		definitions.LogKeyBackendServer, server,
	)
}

// loopBackendServersHealthCheck checks the health of backend servers in parallel and updates their liveness status.
// It compares the current liveness state with the previous state and updates the BackendServers if there are changes.
// Returns the updated backendServersAlive object.
func loopBackendServersHealthCheck(servers []*config.BackendServer, oldBackendServers *backendServersAlive) *backendServersAlive {
	var wg sync.WaitGroup

	wg.Add(len(servers))

	backendServersLiveness := &backendServersAlive{}

	stats.GetMetrics().GetBackendServerStatus().WithLabelValues("wanted").Set(float64(len(servers)))

	for _, server := range servers {
		go func(server *config.BackendServer) {
			err := monitoring.NewMonitor().CheckBackendConnection(server)

			backendServersLiveness.mu.Lock()

			defer backendServersLiveness.mu.Unlock()

			if err != nil {
				logBackendServerError(server, err)
			} else {
				backendServersLiveness.servers = append(backendServersLiveness.servers, server)

				logBackendServerDebug(server)
			}

			wg.Done()
		}(server)
	}

	wg.Wait()

	stats.GetMetrics().GetBackendServerStatus().WithLabelValues("alive").Set(float64(len(backendServersLiveness.servers)))

	if !compareBackendServers(backendServersLiveness.servers, oldBackendServers.servers) {
		core.BackendServers.Update(backendServersLiveness.servers)

		oldBackendServers.servers = backendServersLiveness.servers
	}

	return oldBackendServers
}

// compareBackendServers compares two slices of BackendServer pointers and returns true if they contain the same elements.
func compareBackendServers(servers []*config.BackendServer, servers2 []*config.BackendServer) bool {
	if len(servers) != len(servers2) {
		return false
	}

	foundServer := 0
	for _, server := range servers {
		for _, server2 := range servers2 {
			if server == server2 {
				foundServer++

				continue
			}
		}
	}

	if len(servers) != foundServer {
		return false
	}

	return true
}

// monitoringConfig retrieves and validates the backend server monitoring configuration if the feature is enabled.
// Returns a slice of backend server configurations or an error if the feature is disabled or no servers are defined.
func monitoringConfig() ([]*config.BackendServer, error) {
	if !config.GetFile().HasFeature(definitions.FeatureBackendServersMonitoring) {
		return nil, errors.ErrFeatureBackendServersMonitoringDisabled
	}

	backendServers := config.GetFile().GetBackendServers()
	if len(backendServers) == 0 {
		return nil, errors.ErrMonitoringBackendServersEmpty
	}

	return backendServers, nil
}

// runBackendServerMonitoring initializes and starts the backend server monitoring process.
// Sets up the monitoring context and triggers the backend server monitoring loop.
func runBackendServerMonitoring(ctx context.Context, store *contextStore, monitoringTicker *time.Ticker) {
	store.backendServerMonitoring = newContextTuple(ctx)

	if err := startBackendServerMonitoring(store, monitoringTicker); err != nil {
		handleMonitoringError(err)
	}
}

// startBackendServerMonitoring initializes and manages the backend server monitoring process with a provided ticker.
// It retrieves backend server configurations, validates them, schedules health checks, and updates server statuses.
func startBackendServerMonitoring(store *contextStore, ticker *time.Ticker) error {
	backendServers, err := monitoringConfig()
	if err != nil {
		return err
	}

	oldBackendServers := &backendServersAlive{servers: backendServers}

	core.BackendServers.Update(backendServers)
	oldBackendServers = loopBackendServersHealthCheck(backendServers, oldBackendServers)

	for {
		select {
		case <-ticker.C:
			oldBackendServers = loopBackendServersHealthCheck(backendServers, oldBackendServers)
		case <-store.backendServerMonitoring.ctx.Done():
			return store.backendServerMonitoring.ctx.Err()
		}
	}
}

// handleMonitoringError handles errors related to backend server monitoring.
// Logs specific messages based on the error type and the feature activation status.
func handleMonitoringError(err error) {
	if !config.GetFile().HasFeature(definitions.FeatureBackendServersMonitoring) {
		if stderrors.Is(err, errors.ErrFeatureBackendServersMonitoringDisabled) {
			level.Info(log.Logger).Log(definitions.LogKeyMsg, "Monitoring feature is not enabled")
		}
	} else if stderrors.Is(err, errors.ErrMonitoringBackendServersEmpty) {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, "Monitoring backend servers are not configured")
	}
}

// restartNgxMonitoring stops the current monitoring ticker and cancels the backend server monitoring context.
// It creates a new ticker with a predefined delay and starts backend server monitoring in a separate goroutine.
func restartNgxMonitoring(ctx context.Context, store *contextStore, monitoringTicker **time.Ticker) {
	(*monitoringTicker).Stop()
	store.backendServerMonitoring.cancel()

	*monitoringTicker = time.NewTicker(definitions.BackendServerMonitoringDelay * time.Second)

	go runBackendServerMonitoring(ctx, store, *monitoringTicker)
}

// enableBlockProfile activates the block profiling feature if the verbosity level is set to debug.
func enableBlockProfile() {
	if config.GetFile().GetServer().GetInsights().IsBlockProfileEnabled() {
		runtime.SetBlockProfileRate(1)
	} else {
		runtime.SetBlockProfileRate(-1)
	}
}

// debugLoadableConfig logs the current configuration for debugging, including features such as RBLs, TLS encryption, relay domains,
// backend server monitoring, brute force detection, OAuth2, and LDAP settings if they are configured.
func debugLoadableConfig() {
	if config.GetFile().GetRBLs() != nil {
		level.Debug(log.Logger).Log(definitions.FeatureRBL, fmt.Sprintf("%+v", config.GetFile().GetRBLs()))
	}

	if config.GetFile().GetClearTextList() != nil {
		level.Debug(log.Logger).Log(definitions.FeatureTLSEncryption, fmt.Sprintf("%+v", config.GetFile().GetClearTextList()))
	}

	if config.GetFile().GetRelayDomains() != nil {
		level.Debug(log.Logger).Log(definitions.FeatureRelayDomains, fmt.Sprintf("%+v", config.GetFile().GetRelayDomains()))
	}

	if config.GetFile().GetBackendServerMonitoring() != nil {
		level.Debug(log.Logger).Log(definitions.FeatureBackendServersMonitoring, fmt.Sprintf("%+v", config.GetFile().GetBackendServerMonitoring()))
	}

	if config.GetFile().GetBruteForce() != nil {
		level.Debug(log.Logger).Log(definitions.LogKeyBruteForce, fmt.Sprintf("%+v", config.GetFile().GetBruteForce()))
	}

	if config.GetFile().GetOauth2() != nil {
		level.Debug(log.Logger).Log("oauth2", fmt.Sprintf("%+v", config.GetFile().GetOauth2()))
	}

	if config.GetFile().GetLDAP() != nil {
		level.Debug(log.Logger).Log("ldap", fmt.Sprintf("%+v", config.GetFile().GetLDAP().GetConfig()))
	}
}

// parseFlagsAndPrintVersion parses command-line flags and prints the version information if the "version" flag is set.
func parseFlagsAndPrintVersion() {
	var versionFlag = flag.Bool("version", false, "print version and exit")
	var configFlag = flag.String("config", "", "path to configuration file")
	var configFormatFlag = flag.String("config-format", "yaml", "configuration file format (yaml, json, toml, etc.)")

	flag.Parse()

	if *versionFlag {
		fmt.Println("Version: ", version)

		os.Exit(0)
	}

	if *configFlag != "" {
		config.ConfigFilePath = *configFlag

		viper.SetConfigFile(*configFlag)
	}

	// Set the configuration format
	viper.SetConfigType(*configFormatFlag)
}

// initializeInstanceInfo sets the version and instance name metrics used for monitoring and debugging.
func initializeInstanceInfo() {
	infoMetric := stats.GetMetrics().GetInstanceInfo().With(prometheus.Labels{"instance_name": config.GetFile().GetServer().GetInstanceName(), "version": version})

	infoMetric.Set(1)
}

// initializeHTTPClients initializes the HTTP clients for core, backend, action, callback, filter, and feature packages.
func initializeHTTPClients() {
	if config.GetFile().GetServer().Frontend.Enabled {
		core.InitHTTPClient()
	}

	backend.InitHTTPClient()
	action.InitHTTPClient()
	filter.InitHTTPClient()
	feature.InitHTTPClient()
	hook.InitHTTPClient()
}

// runConnectionManager initializes the ConnectionManager, registers the server address, and starts a ticker to update connection counts.
func runConnectionManager(ctx context.Context) {
	// Only run connection monitoring if it's enabled in the configuration
	if !config.GetFile().GetServer().GetInsights().IsMonitorConnectionsEnabled() {
		level.Info(log.Logger).Log(definitions.LogKeyMsg, "Connection monitoring is disabled")

		return
	}

	level.Info(log.Logger).Log(definitions.LogKeyMsg, "Starting connection monitoring")

	manager := connmgr.GetConnectionManager()

	manager.Register(ctx, config.GetFile().GetServer().Address, "local", "HTTP server")

	go manager.StartTicker(5 * time.Second)
	go stats.UpdateGenericConnections()

	manager.StartMonitoring(ctx)
}

// runLuaInitScript executes the Lua initialization scripts if they're present in the GetFile().
func runLuaInitScript(ctx context.Context) {
	if config.GetFile().HaveLuaInit() {
		// Get all init script paths
		initScriptPaths := config.GetFile().GetLuaInitScriptPaths()

		// Run each init script
		for _, scriptPath := range initScriptPaths {
			hook.RunLuaInit(ctx, scriptPath)
		}
	}
}

// inititalizeBruteForceTolerate initializes brute force tolerance by setting the provided context to the Tolerate instance.
func inititalizeBruteForceTolerate(ctx context.Context) {
	go tolerate.GetTolerate().StartHouseKeeping(ctx)
}
