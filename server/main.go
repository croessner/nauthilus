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
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
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
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"golang.org/x/text/language"
)

var version = "dev"

var versionFlag = flag.Bool("version", false, "print version and exit")

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

// newContextStore creates a new instance of a contextStore.
// It initializes the fields of the contextStore struct and returns a pointer to the created instance.
//
//	func newContextStore() *contextStore {
//		store := &contextStore{}
//
//		return store
//	}
func newContextStore() *contextStore {
	store := &contextStore{}

	return store
}

// newContextTuple creates a new instance of a contextTuple.
// It initializes the fields of the contextTuple struct with a context and a cancel function,
// using the provided context as the parent context.
// It returns a pointer to the created instance of contextTuple.
func newContextTuple(ctx context.Context) *contextTuple {
	tuple := &contextTuple{}
	tuple.ctx, tuple.cancel = context.WithCancel(ctx)

	return tuple
}

// setupEnvironment loads and sets up the environment for the application.
// It performs the following tasks:
// - Calls config.NewConfig() to initialize the global variable config.EnvConfig.
// - Calls loadLanguageBundles() to load language bundles.
// - Calls log.SetupLogging() to configure the log settings using the values from config.EnvConfig.
// - Configures the standard library logger stdlog to output logs to log.Logger.
// - Calls setTimeZone() to set the time zone.
// - Calls config.NewConfigFile() to initialize the global variable config.LoadableConfig.
//
// If any error occurs during the environment setup, an appropriate error message is returned.
//
// Example usage:
//
//	err := setupEnvironment()
//	if err != nil {
//		// handle error
//	}
func setupEnvironment() (err error) {
	config.EnvConfig = config.NewConfig()

	loadLanguageBundles()

	setTimeZone()

	config.LoadableConfig, err = config.NewConfigFile()
	if err != nil {
		return fmt.Errorf("unable to load config file: %w", err)
	}

	log.SetupLogging(
		config.LoadableConfig.Server.Log.Level.Level(),
		config.LoadableConfig.Server.Log.JSON,
		config.LoadableConfig.Server.Log.Color,
		config.LoadableConfig.Server.InstanceName,
	)
	stdlog.SetOutput(kitlog.NewStdlibAdapter(log.Logger))

	return nil
}

// loadLanguageBundles initializes the core language bundle with English as the base language,
// sets the unmarshal function for JSON data, and loads additional language
// bundles for English (en), German (de), and French (fr).
func loadLanguageBundles() {
	core.LangBundle = i18n.NewBundle(language.English)

	core.LangBundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	loadLanguageBundle("en")
	loadLanguageBundle("de")
	loadLanguageBundle("fr")
}

// loadLanguageBundle is a function used to load a specific language bundle into the system.
// It takes as parameter a string which represents the language for which the bundle is to be loaded.
// The function looks up the requested language file in the directory retrieved from the configuration ("language_resources").
// If the language file is found, it is loaded into the system's language bundle core.LangBundle, otherwise, it causes the system to panic with the related error message.
//
// Parameters:
//
// lang: A string that represents the language for the bundle that needs to be loaded.
//
// Returns:
//
// This function does not return a value.
//
// Example Usage:
//
// loadLanguageBundle("en-US")
func loadLanguageBundle(lang string) {
	if _, err := core.LangBundle.LoadMessageFile(viper.GetString("language_resources") + "/" + lang + ".json"); err != nil {
		panic(err.Error())
	}
}

// setTimeZone sets the time zone manually by loading the time location from the "TZ" environment variable.
// If the "TZ" environment variable is not empty, it tries to load the time location.
// If an error occurs while loading the location, it logs the error using the default error logger.
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

// setupLuaScripts prepares features, filters and the callback for compilation and performs error checking.
// It sequentially runs the PreCompileFeatures, PreCompileFilters and PreCompileCallback methods.
// If those methods return an error, the setupLuaScripts method will propagate that error up the stack.
// If the pre-compilation is successful, it will return nil.
func setupLuaScripts() error {
	if err := PreCompileFeatures(); err != nil {
		return err
	}

	if err := PreCompileFilters(); err != nil {
		return err
	}

	if err := PreCompileCallback(); err != nil {
		return err
	}

	if err := PreCompileInit(); err != nil {
		return err
	}

	return nil
}

// PreCompileFeatures pre-compiles the features for the application based on the configuration.
// If the application is configured without the Lua features (definitions.FeatureLua), it performs no operation and returns nil.
// If the application is configured with the Lua features, it attempts to pre-compile the Lua features.
// If pre-compilation of the Lua features encounters any errors, it returns the error. Otherwise, it returns nil.
func PreCompileFeatures() error {
	if !config.LoadableConfig.HasFeature(definitions.FeatureLua) {
		return nil
	}

	if err := feature.PreCompileLuaFeatures(); err != nil {
		return err
	}

	return nil
}

// PreCompileFilters is a function that compiles all the Filter scripts in Lua language.
// If the configuration does not specify Lua or there are no Filter scripts in Lua,
// the function will not do anything and will return nil. If there is an error during
// the compilation of any Lua filter, the function will return that error.
func PreCompileFilters() error {
	if !config.LoadableConfig.HaveLuaFilters() {
		return nil
	}

	if err := filter.PreCompileLuaFilters(); err != nil {
		return err
	}

	return nil
}

// PreCompileCallback pre-compiles the Lua callback script if present in the configuration.
// It checks if the Lua callback is enabled in the LoadableConfig.
// If enabled, it pre-compiles the Lua callback script using hook.PreCompileLuaScript.
// Returns an error if the pre-compilation fails, else returns nil.
func PreCompileCallback() error {
	if !config.LoadableConfig.HaveLuaCallback() {
		return nil
	}

	if err := hook.PreCompileLuaScript(config.LoadableConfig.GetLuaCallbackScriptPath()); err != nil {
		return err
	}

	return nil
}

// PreCompileInit pre-compiles the Lua init script if present in the configuration.
// It checks if the Lua init is enabled in the LoadableConfig.
// If enabled, it pre-compiles the Lua init script using hook.PreCompileLuaScript.
// Returns an error if the pre-compilation fails, else returns nil.
func PreCompileInit() error {
	if !config.LoadableConfig.HaveLuaInit() {
		return nil
	}

	if err := hook.PreCompileLuaScript(config.LoadableConfig.GetLuaInitScriptPath()); err != nil {
		return err
	}

	return nil
}

// handleSignals starts two goroutines to listen for termination and reload signals respectively.
// On a termination signal, it will cancel the provided context, stop the statsTicker and stop all actionWorkers.
// On a reload signal, it will reload the stored context and restart all actionWorkers.
//
// Arguments:
// - ctx : The primary application context, cancellation of which leads to application shutdown.
// - cancel : The function to call in order to cancel the provided context. Typically, it's the cancel function returned from context.WithCancel(ctx).
// - store : contextStore instance where application contexts are managed.
// - statsTicker : Time ticker for stats data. It's stopped on termination signal.
// - actionWorkers : A slice of action.Worker pointers. All workers are stopped on termination signal and restarted on reload signal.
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

// handleTerminateSignal handles the termination signal (SIGINT or SIGTERM) and performs cleanup tasks before shutting down the program.
// The cancel function is used to cancel any ongoing context operations.
// The statsTicker is a ticker used for periodically saving statistics to Redis.
// The actionWorkers is a slice of action workers.
// It sets up a channel to receive the termination signal.
// It waits for a signal to be received.
// It logs the shutdown message along with the received signal.
// It cancels the context to stop ongoing operations.
// It waits for the HTTP server to terminate.
// It handles the backend for each backendType in the configuration.
// It waits for all action workers to complete their work.
// It syncs some Prometheus data to Redis.
// It logs the shutdown complete message.
// It terminates the Lua state pools.
// It closes all channels.
// It stops the statsTicker.
// Signature:
// func handleTerminateSignal(cancel context.CancelFunc, statsTicker *time.Ticker, actionWorkers []*action.Worker) {
func handleTerminateSignal(ctx context.Context, cancel context.CancelFunc, statsTicker *time.Ticker, ngxMonitoringTicker *time.Ticker, actionWorkers []*action.Worker) {
	sigsTerminate := make(chan os.Signal, 1)

	signal.Notify(sigsTerminate, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigsTerminate

	level.Info(log.Logger).Log(definitions.LogKeyMsg, "Shutting down Nauthilus", "signal", sig)

	cancel()

	// Wait for HTTP server termination
	<-core.HTTPEndChan

	if config.LoadableConfig.Server.HTTP3 {
		<-core.HTTP3EndChan
	}

	for _, backendType := range config.LoadableConfig.Server.Backends {
		handleBackend(backendType)
	}

	waitForActionWorkers(actionWorkers)

	// Sync some Prometheus data to Redis
	core.SaveStatsToRedis(ctx)

	level.Debug(log.Logger).Log(definitions.LogKeyMsg, "Shutdown complete")

	closeChannels()

	statsTicker.Stop()
	ngxMonitoringTicker.Stop()
}

// handleUsr1Signal listens for the SIGUSR1 signal and handles server restart.
//
// It creates a channel to receive the SIGUSR1 signal and registers it with the signal package.
// It then enters a loop to select between receiving signals and checking if the context is done.
// If the context is done, it returns and stops handling signals.
// If a SIGUSR1 signal is received, it calls the handleServerRestart function with the context, store, and signal as arguments.
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

// handleReloadSignal is a function that listens for a SIGHUP (hangup signal) from the operating system.
// When the signal is received, the function handles the reload process by calling the handleReload function.
// It takes three arguments: a context defined by the caller (ctx) which dictates the lifetime of the process,
// a pointer to a contextStore (store) which presumably stores context data used by the handler and a slice of pointers
// to action.Worker.
//
// handleReloadSignal operates in an infinite loop, continuously listening for signals until the context is cancelled.
// If the received signal is SIGHUP, the loop calls handleReload with the same context and store, plus the received signal.
//
// The function does not return anything, and it continues to run until the provided context is cancelled, at which point it exits the loop and the function.
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

// handleBackend performs a clean-up operation based on the backend system provided in the passDB configuration.
// It involves closing or terminating processes or connections related to a specified backend.
// Currently, supported backends are LDAP, MySQL, PostgreSQL, Lua, and Cache.
// For each backend, the function executes its specific clean-up process.
// It will log a warning if an unrecognized backend is given.
func handleBackend(passDB *config.Backend) {
	switch passDB.Get() {
	case definitions.BackendLDAP:
		<-backend.LDAPEndChan

		close(backend.LDAPEndChan)
		close(backend.LDAPRequestChan)

		if !config.LoadableConfig.LDAPHavePoolOnly() {
			<-backend.LDAPAuthEndChan

			close(backend.LDAPAuthEndChan)
			close(backend.LDAPAuthRequestChan)
		}
	case definitions.BackendLua:
		<-backend.LuaMainWorkerEndChan

		close(backend.LuaMainWorkerEndChan)
		close(backend.LuaRequestChan)
	case definitions.BackendCache:
	default:
		level.Warn(log.Logger).Log(definitions.LogKeyMsg, "Unknown backend")
	}
}

// handleLDAPBackend is a function to handle LDAP backend operations.
// It takes two arguments - lookup and auth contextTuple pointers.
// The function stops the contexts of the 'lookup' and 'auth' and waits for the backend LDAP operations to finish.
func handleLDAPBackend(lookup, auth *contextTuple) {
	stopContext(lookup)

	<-backend.LDAPEndChan

	if !config.LoadableConfig.LDAPHavePoolOnly() {
		stopContext(auth)

		<-backend.LDAPAuthEndChan
	}
}

// handleLuaBackend receives a contextTuple as a parameter.
// It runs stopContext on the contextTuple and waits for `LuaMainWorkerEndChan` to end.
func handleLuaBackend(lua *contextTuple) {
	stopContext(lua)

	<-backend.LuaMainWorkerEndChan
}

// stopAndRestartActionWorker is a function that stops the currently running action workers and restarts them.
// It takes three parameters: a slice of pointers to action workers, a context tuple, and a context variable.
// The function first calls the stopContext function that stops the context.
// It then enters a loop that iterates through the slice of action workers and waits for them to finish their tasks.
// After all action workers have finished their tasks, a new context with cancellation is created for the context tuple.
// Finally, the function calls startActionWorker to start the action workers with the new context.
//
// Parameters:
//   - actionWorkers: A slice of pointers to action workers that are being stopped and restarted.
//   - act: A context tuple that gets stopped and a new context with cancellation is created for it.
//   - ctx: A context variable from which a new context with cancellation is derived.
func stopAndRestartActionWorker(actionWorkers []*action.Worker, act *contextTuple, ctx context.Context) {
	stopContext(act)

	waitForActionWorkers(actionWorkers)

	act.ctx, act.cancel = context.WithCancel(ctx)

	startActionWorker(actionWorkers, act)
}

// stopAndRestartRedis stops and restarts the Redis client.
// It closes the WriteHandle and ReadHandle connections.
// If ReadHandle is not the same as WriteHandle, it also closes the ReadHandle connection.
// Then, it calls the setupRedis function to reinitialize the Redis client.
//
//	stopAndRestartRedis()
func stopAndRestartRedis(ctx context.Context) {
	rediscli.WriteHandle.Close()

	if rediscli.ReadHandle != rediscli.WriteHandle {
		rediscli.ReadHandle.Close()
	}

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

// It takes a parameter "store" of type *contextStore.
// The function spawns goroutines for the LDAPMainWorker and LDAPAuthWorker functions from the backend package, passing the associated context to each worker.
func startLDAPWorkers(store *contextStore) {
	go backend.LDAPMainWorker(store.ldapLookup.ctx)

	if !config.LoadableConfig.LDAPHavePoolOnly() {
		go backend.LDAPAuthWorker(store.ldapAuth.ctx)
	}
}

// startLuaWorker starts a goroutine that runs the backend.LuaMainWorker function
func startLuaWorker(store *contextStore) {
	go backend.LuaMainWorker(store.lua.ctx)
}

// handleServerRestart handles the server restart process. It stops the server, waits for the HTTP server to stop,
// and then starts the HTTP server again with the given context and contextStore.
func handleServerRestart(ctx context.Context, store *contextStore, sig os.Signal) {
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Restarting Nauthilus", "signal", sig,
	)

	stopContext(store.server)

	<-core.HTTPEndChan

	if config.LoadableConfig.Server.HTTP3 {
		<-core.HTTP3EndChan
	}

	startHTTPServer(ctx, store)
}

// handleReload is a function that handles the reloading of Nauthilus based on a received operating signal.
// The function works with various backends (LDAP, Lua, or Cache), and based on the specific
// backend, it will reload the related services. The function manages the necessary workers, stopping
// and restarting them as appropriate.
//
// Throughout the process, the function logs key events and handles errors. Specifically, the function logs
// a reload, configuration file reload success or failure, setup features success or failure and the conclusion
// of the reloading procedure.
//
// This function is generally invoked when a reload signal is received by Nauthilus. This signal triggers
// Nauthilus to refresh its configuration and restart services based on the updated configuration.
//
// Parameters:
//
//		ctx:   A context on which this function will operate. It represents the state that potentially includes
//	          deadlines, cancel signals, and other request-scoped values across API boundaries and between processes.
//
//		store: A contextStore containing the current state of the backend services. It holds the context
//	          for each backend state which is manipulated based on the backend during the process.
//
//		sig:   A signal that triggers the reloading of Nauthilus. sig represents the operating system
//	          signal information sent to Nauthilus.
//
//	 actionWorkers: A slice of action workers that are stopped and restarted during the process.
func handleReload(ctx context.Context, store *contextStore, sig os.Signal, ngxMonitoringTicker **time.Ticker, actionWorkers []*action.Worker) {
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Reloading Nauthilus", "signal", sig,
	)

	for _, backendType := range config.LoadableConfig.Server.Backends {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			handleLDAPBackend(store.ldapLookup, store.ldapAuth)
		case definitions.BackendLua:
			handleLuaBackend(store.lua)
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
			config.LoadableConfig.Server.Log.Level.Level(),
			config.LoadableConfig.Server.Log.JSON,
			config.LoadableConfig.Server.Log.Color,
			config.LoadableConfig.Server.InstanceName,
		)

		postEnvironmentDebug()
	}

	if err := setupLuaScripts(); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, "Unable to setup Lua scripts",
			definitions.LogKeyMsg, err,
		)
	}

	enableBlockProfile()

	for _, backendType := range config.LoadableConfig.Server.Backends {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			store.ldapLookup = newContextTuple(ctx)
			if !config.LoadableConfig.LDAPHavePoolOnly() {
				store.ldapAuth = newContextTuple(ctx)
			}

			startLDAPWorkers(store)
		case definitions.BackendLua:
			store.lua = newContextTuple(ctx)

			startLuaWorker(store)
		case definitions.BackendCache:
		default:
			level.Warn(log.Logger).Log(definitions.LogKeyMsg, "Unknown backend")
		}
	}

	restartNgxMonitoring(ctx, store, ngxMonitoringTicker)

	stats.ReloadMutex.Lock()

	stats.LastReloadTime = time.Now()

	stats.ReloadMutex.Unlock()

	level.Debug(log.Logger).Log(
		definitions.LogKeyMsg, "Reload complete",
	)
}

// initializeActionWorkers creates and initializes a slice of action workers.
// It creates `definitions.MaxActionWorkers` number of workers, each worker is created using `action.NewWorker()`.
// The workers are then appended to the `workers` slice.
// Finally, the `workers` slice is returned.
func initializeActionWorkers() []*action.Worker {
	var workers []*action.Worker

	for i := 0; i < int(config.EnvConfig.MaxActionWorkers); i++ {
		workers = append(workers, action.NewWorker())
	}

	return workers
}

// setupWorkers sets up the action workers based on the configuration and starts them in separate goroutines.
// It takes a context, a store, and a slice of action workers as parameters.
// It starts the action workers by calling the `startActionWorker` function with the appropriate parameters.
// Then, for each backendType in the `config.LoadableConfig.Server.Backends` slice, it performs the necessary setup based on the backend type.
// The setup depends on the passDB's backend type and calls corresponding setup functions, such as `setupLDAPWorker`, `setupSQLWorker`, or `setupLuaWorker`.
// If the passDB's backend is `definitions.BackendCache`, no setup is performed.
// If the passDB's backend is unknown, a warning log is generated for an unknown backend.
func setupWorkers(ctx context.Context, store *contextStore, actionWorkers []*action.Worker) {
	startActionWorker(actionWorkers, store.action)

	for _, backendType := range config.LoadableConfig.Server.Backends {
		switch backendType.Get() {
		case definitions.BackendLDAP:
			setupLDAPWorker(store, ctx)
		case definitions.BackendLua:
			setupLuaWorker(store, ctx)
		case definitions.BackendCache:
		default:
			level.Warn(log.Logger).Log(definitions.LogKeyMsg, "Unknown backend", "backend")
		}
	}
}

// setupLDAPWorker initializes LDAP workers for lookup and authentication.
// The function creates channels for handling LDAP and LDAP authentication requests,
// and a channel for signaling that the processing of these requests is finished.
// The size of these channels is determined by the configuration values 'LookupPoolSize' and 'AuthPoolSize'.
// These channels and contexts are then stored in the provided context store,
// and the LDAP workers are started.
//
// Parameters:
// - `store`: a pointer to the contextStore which will hold the context for the LDAP workers
// - `ctx`: The context under which the LDAP workers should operate
func setupLDAPWorker(store *contextStore, ctx context.Context) {
	lookupPoolSize := config.LoadableConfig.LDAP.Config.LookupPoolSize

	backend.LDAPRequestChan = make(chan *backend.LDAPRequest, lookupPoolSize)
	backend.LDAPEndChan = make(chan backend.Done)
	store.ldapLookup = newContextTuple(ctx)

	if !config.LoadableConfig.LDAPHavePoolOnly() {
		authPoolSize := config.LoadableConfig.LDAP.Config.AuthPoolSize

		backend.LDAPAuthRequestChan = make(chan *backend.LDAPAuthRequest, authPoolSize)
		backend.LDAPAuthEndChan = make(chan backend.Done)
		store.ldapAuth = newContextTuple(ctx)
	}

	startLDAPWorkers(store)
}

// setupLuaWorker initializes a Lua worker with the help of channels.
// It configures communication channels for handling Lua requests and signaling when the worker has finished its tasks.
// The function receives a store of type *contextStore and a context as arguments.
// The context store is modified within the function where it initializes the LuaContext based on the provided context.
// The Lua worker is then started with the initialized context.
func setupLuaWorker(store *contextStore, ctx context.Context) {
	backend.LuaRequestChan = make(chan *backend.LuaRequest, definitions.MaxChannelSize)
	backend.LuaMainWorkerEndChan = make(chan backend.Done)

	store.lua = newContextTuple(ctx)

	startLuaWorker(store)
}

// checkRedisConnections checks the health of Redis read and write connections.
// It pings both the write and read Redis handles. If any handle is nil or the ping fails, it returns false.
// Otherwise, it returns true.
func checkRedisConnections(ctx context.Context) bool {
	if rediscli.WriteHandle == nil {
		return false
	}

	if err := rediscli.WriteHandle.Ping(ctx).Err(); err != nil {
		return false
	}

	if rediscli.ReadHandle == nil {
		return false
	}

	if err := rediscli.ReadHandle.Ping(ctx).Err(); err != nil {
		return false
	}

	return true
}

// setupRedis sets up the Redis client and its replicas. It ensures connections are valid with a retry mechanism on failure.
func setupRedis(ctx context.Context) {
	redisLogger := &util.RedisLogger{}
	redis.SetLogger(redisLogger)

	rediscli.WriteHandle = rediscli.NewRedisClient()
	rediscli.ReadHandle = rediscli.NewRedisReplicaClient()

	if rediscli.ReadHandle == nil {
		rediscli.ReadHandle = rediscli.WriteHandle
	}

	// Retry mechanism to ensure the Redis connections are usable
	maxRetries := 10
	retryInterval := 5 * time.Second

	for retries := 0; retries < maxRetries; retries++ {
		if checkRedisConnections(ctx) {
			go core.UpdateRedisPoolStats()

			return
		}

		level.Warn(log.Logger).Log(definitions.LogKeyMsg, fmt.Sprintf("Redis not ready yet. Retry %d/%d", retries+1, maxRetries))

		time.Sleep(retryInterval)
	}

	panic("Failed to establish Redis connections after max retries")
}

// startHTTPServer is a function that starts the HTTP server.
// It takes a context.Context as an argument which is used for HTTPApp.
// It indirectly initiates HTTPApp function from the 'core' package that starts the HTTP server.
// After starting the HTTP server it logs the message "Starting Nauthilus HTTP server" along with its version.
// The server is started as a goroutine and runs asynchronously in the background.
// Any signal sent to close the server is sent through the HTTPEndChan channel of type Done.
func startHTTPServer(ctx context.Context, store *contextStore) {
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Starting Nauthilus HTTP server",
		"version", version,
	)

	store.server = newContextTuple(ctx)

	if core.HTTPEndChan == nil {
		core.HTTPEndChan = make(chan core.Done)
	}

	if config.LoadableConfig.Server.HTTP3 {
		if core.HTTP3EndChan == nil {
			core.HTTP3EndChan = make(chan core.Done)
		}
	}

	go core.HTTPApp(store.server.ctx)
}

// startStatsLoop runs a continuous loop that periodically executes core.PrintStats(), core.SaveStatsToRedis(), and logLuaStatePoolDebug().
// It uses a ticker to determine the interval between executions. The loop continues executing until the done channel receives a value.
//
// It returns ctx.Err() upon a ctx.Done signal.
//
// Usage:
//
//	statsTicker := time.NewTicker(global.StatsDelay * time.Second)
//	statsEndChan := make(chan bool)
//	startStatsLoop(statsTicker, statsEndChan)
//
// Example:
//
//	statsTicker := time.NewTicker(5 * time.Second)
//	statsEndChan := make(chan bool)
//
//	go startStatsLoop(statsTicker, statsEndChan)
//
//	time.Sleep(30 * time.Second)
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

// logBackendServerError logs an error originating from Backend Server,
// detailing the server configuration at the time of the error.
// The logged details include error message, protocol used by the server,
// and the IP address and Port used by the Backend Server.
//
// Parameters:
//
//	server: a pointer to the configuration of the Backend Server at the time of the error
//	err: the error that has occurred
func logBackendServerError(server *config.BackendServer, err error) {
	level.Error(log.Logger).Log(
		definitions.LogKeyMsg, err,
		definitions.LogKeyMsg, "Server down",
		definitions.LogKeyProtocol, server.Protocol,
		definitions.LogKeyBackendServerIP, server.IP,
		definitions.LogKeyBackendServerPort, server.Port,
	)
}

// logBackendServerDebug logs debug information for a backend server. It uses the util.DebugModule function to log the debug message and key-value pairs.
// Parameters:
// - server: a pointer to the BackendServer struct that contains the server information.
// Example usage:
//
//	logBackendServerDebug(server)
func logBackendServerDebug(server *config.BackendServer) {
	util.DebugModule(
		definitions.DbgFeature,
		definitions.LogKeyMsg, "Server alive",
		definitions.LogKeyProtocol, server.Protocol,
		definitions.LogKeyBackendServerIP, server.IP,
		definitions.LogKeyBackendServerPort, server.Port,
	)
}

// loopBackendServersHealthCheck iterates over a slice of BackendServer objects, checks the availability of each server,
// and updates the BackendServers collection if necessary.
//
// Parameters:
// - servers: A slice of BackendServer objects representing the backend servers to be monitored.
//
// type backendServersAlive: A struct that holds information related to the monitoring process.
// - update: A boolean flag indicating whether any backend server failed to respond.
// - servers: A slice of BackendServer objects representing the available backend servers.
// - mu: A mutex used for synchronizing access to the backendServersAlive struct fields.
//
// var wg: A WaitGroup used to wait for all goroutines to finish.
//
// ngxAlive: An instance of the backendServersAlive struct.
//
// Iterates over each server in the servers slice using a goroutine.
// - For each server, it checks the connectivity using the checkBackendConnection function.
// - Acquires a lock on ngxAlive.mu to prevent concurrent writes.
// - If an error occurs, sets ngxAlive.update to true and logs the error using the logBackendServerError function.
// - If no error occurs, appends the server to ngxAlive.servers.
// - Decrements the WaitGroup counter by calling wg.Done().
//
// Waits for all goroutines to finish by calling wg.Wait().
//
// If ngxAlive.update is true, it updates the BackendServers collection using the core.BackendServers.Update method.
func loopBackendServersHealthCheck(servers []*config.BackendServer, oldBackendServers *backendServersAlive) *backendServersAlive {
	var wg sync.WaitGroup

	wg.Add(len(servers))

	backendServersLiveness := &backendServersAlive{}

	stats.BackendServerStatus.WithLabelValues("wanted").Set(float64(len(servers)))

	for _, server := range servers {
		go func(server *config.BackendServer) {
			err := monitoring.NewMonitor().CheckBackendConnection(server.IP, server.Port, server.HAProxyV2, server.TLS)

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

	stats.BackendServerStatus.WithLabelValues("alive").Set(float64(len(backendServersLiveness.servers)))

	if !compareBackendServers(backendServersLiveness.servers, oldBackendServers.servers) {
		core.BackendServers.Update(backendServersLiveness.servers)

		oldBackendServers.servers = backendServersLiveness.servers
	}

	return oldBackendServers
}

// compareBackendServers compares two slices of BackendServer objects and returns true if all the corresponding elements are equal in both slices. Otherwise, it returns false.
//
// Parameters:
// - servers: A slice of BackendServer objects.
// - servers2: Another slice of BackendServer objects.
//
// Returns true if all elements are equal in both slices.
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

// monitoringConfig checks if the backendServerMonitoring monitoring feature is enabled.
// If enabled, it gets the backend servers from the LoadableConfig.
// If there are no backend servers or the feature is not enabled, it returns an error.
// It returns a list with backend servers or an error.
func monitoringConfig() ([]*config.BackendServer, error) {
	if !config.LoadableConfig.HasFeature(definitions.FeatureBackendServersMonitoring) {
		return nil, errors.ErrFeatureBackendServersMonitoringDisabled
	}

	backendServers := config.LoadableConfig.GetBackendServers()
	if len(backendServers) == 0 {
		return nil, errors.ErrMonitoringBackendServersEmpty
	}

	return backendServers, nil
}

// runBackendServerMonitoring sets a new context for monitoring and initiates the monitoring.
// The function requires three parameters: a base context ctx, a store of context objects, and a ticker for monitoring.
// It creates a new context specifically for monitoring with its own cancellation function and stores these in the context store.
// It then attempts to start monitoring using the startBackendServerMonitoring function.
// If an error occurs during the start of monitoring, it is handled by the handleMonitoringError function.
//
// ctx is the base context from which the monitoring-specific context is derived.
// store is a store for context objects that can hold the specific context for monitoring.
// monitoringTicker is a ticker that triggers the monitoring at regular intervals.
func runBackendServerMonitoring(ctx context.Context, store *contextStore, monitoringTicker *time.Ticker) {
	store.backendServerMonitoring = newContextTuple(ctx)

	if err := startBackendServerMonitoring(store, monitoringTicker); err != nil {
		handleMonitoringError(err)
	}
}

// startBackendServerMonitoring initiates the monitoring of backend servers. It takes a contextStore
// and a ticker as arguments. The contextStore is used to manage context-specific values across API boundaries
// and between processes, and the ticker is used to trigger backend server assessment at regular intervals.
// The function first validates the backend server monitoring configuration and updates the BackendServers in the
// core package as necessary. It then enters a loop which repeatedly evaluates the status of the backend servers
// at intervals defined by the ticker. The loop continues until the context is cancelled.
//
// Arguments:
// - store: A pointer to a contextStore instance. Used to manage context-specific values.
// - ticker: A pointer to a time.Ticker instance. Used to trigger backend server assessments at regular intervals.
//
// Returns:
// Returns an error if the backend server monitoring configuration verification fails or if the context is cancelled.
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

// handleMonitoringError is a function that handles errors related
// to the backend server monitoring feature. If the backend server monitoring feature is
// not enabled, it logs an informational message. If there are no
// configured backend servers for monitoring, it logs an error message.
func handleMonitoringError(err error) {
	if !config.LoadableConfig.HasFeature(definitions.FeatureBackendServersMonitoring) {
		if stderrors.Is(err, errors.ErrFeatureBackendServersMonitoringDisabled) {
			level.Info(log.Logger).Log(definitions.LogKeyMsg, "Monitoring feature is not enabled")
		}
	} else if stderrors.Is(err, errors.ErrMonitoringBackendServersEmpty) {
		level.Error(log.Logger).Log(definitions.LogKeyMsg, "Monitoring backend servers are not configured")
	}
}

// restartNgxMonitoring stops the current monitoring ticker, cancels the backendServerMonitoring context from the store,
// then starts a new monitoring ticker and begins monitoring backendServerMonitoring again in a new goroutine.
// This function is useful when you need to restart the backendServerMonitoring monitoring process for any reason, like configuration changes.
//
// Params:
// - ctx: The context in which we run monitoring. Can be used to stop monitoring externally.
// - store: A reference to the contextStore, which holds the cancel function for the backendServerMonitoring context.
// - ngxMonitoring: A double pointer to a time Ticker, which we stop and replace with a new Ticker.
func restartNgxMonitoring(ctx context.Context, store *contextStore, monitoringTicker **time.Ticker) {
	(*monitoringTicker).Stop()
	store.backendServerMonitoring.cancel()

	*monitoringTicker = time.NewTicker(definitions.BackendServerMonitoringDelay * time.Second)

	go runBackendServerMonitoring(ctx, store, *monitoringTicker)
}

// enableBlockProfile activates the block profiling feature if the verbosity level is set to debug.
func enableBlockProfile() {
	if config.LoadableConfig.GetServerInsightsEnableBlockProfile() {
		runtime.SetBlockProfileRate(1)
	} else {
		runtime.SetBlockProfileRate(-1)
	}
}

func postEnvironmentDebug() {
	if config.LoadableConfig.RBLs != nil {
		level.Debug(log.Logger).Log(definitions.FeatureRBL, fmt.Sprintf("%+v", config.LoadableConfig.RBLs))
	}

	if config.LoadableConfig.ClearTextList != nil {
		level.Debug(log.Logger).Log(definitions.FeatureTLSEncryption, fmt.Sprintf("%+v", config.LoadableConfig.ClearTextList))
	}

	if config.LoadableConfig.RelayDomains != nil {
		level.Debug(log.Logger).Log(definitions.FeatureRelayDomains, fmt.Sprintf("%+v", config.LoadableConfig.RelayDomains))
	}

	if config.LoadableConfig.BackendServerMonitoring != nil {
		level.Debug(log.Logger).Log(definitions.FeatureBackendServersMonitoring, fmt.Sprintf("%+v", config.LoadableConfig.BackendServerMonitoring))
	}

	if config.LoadableConfig.BruteForce != nil {
		level.Debug(log.Logger).Log(definitions.LogKeyBruteForce, fmt.Sprintf("%+v", config.LoadableConfig.BruteForce))
	}

	if config.LoadableConfig.Oauth2 != nil {
		level.Debug(log.Logger).Log("oauth2", fmt.Sprintf("%+v", config.LoadableConfig.Oauth2))
	}

	if config.LoadableConfig.LDAP != nil {
		level.Debug(log.Logger).Log("ldap", fmt.Sprintf("%+v", config.LoadableConfig.LDAP.Config))
	}
}

// parseFlagsAndPrintVersion parses command line flags and print the version
// of the application if the version flag (-version) is set.
// If the version flag is set, it will print the current version and exit the
// application.
func parseFlagsAndPrintVersion() {
	flag.Parse()

	if *versionFlag {
		fmt.Println("Version: ", version)

		os.Exit(0)
	}
}

// initializeInstanceInfo initializes the InstanceInfo metric with the instance name and version.
//
// It creates a labels map with "instance" and "version" as keys and the corresponding values from
// config.LoadableConfig.Server.InstanceName and version as values.
// Then, it retrieves the InstanceInfo metric using the labels and assigns it to infoMetric.
// Finally, it sets the value of infoMetric to 1.
func initializeInstanceInfo() {
	infoMetric := stats.InstanceInfo.With(prometheus.Labels{"instance_name": config.LoadableConfig.Server.InstanceName, "version": version})

	infoMetric.Set(1)
}

// initializeHTTPClients initializes the HTTP clients for core, backend, action, callback, filter, and feature packages.
func initializeHTTPClients() {
	core.InitHTTPClient()
	backend.InitHTTPClient()
	action.InitHTTPClient()
	hook.InitHTTPClient()
	filter.InitHTTPClient()
	feature.InitHTTPClient()
}

// runConnectionManager initializes the ConnectionManager, registers the server address, and starts a ticker to update connection counts.
func runConnectionManager(ctx context.Context) {
	manager := connmgr.GetConnectionManager()

	manager.Register(ctx, config.LoadableConfig.Server.Address, "local", "HTTP server")

	go manager.StartTicker(5 * time.Second)
	go stats.UpdateGenericConnections()

	manager.StartMonitoring(ctx)
}

// runLuaaInitScript executes the Lua initialization script if it's present in the LoadableConfig.
func runLuaaInitScript(ctx context.Context) {
	if config.LoadableConfig.HaveLuaInit() {
		hook.RunLuaInit(ctx, config.LoadableConfig.GetLuaInitScriptPath())
	}
}

// main initializes the application and manages the lifecycle of various components.
//
// It first sets up the environment and checks if any errors occurred during the process. If an error is encountered, it's logged and the application terminates.
// If the environment setup is successful, the function proceeds to setting up the features. Similar to environment setup, any errors here will be logged and the application will terminate.
// Once the environment and features are established, a new context is created with a cancellation function to manage the lifecycle of the program.
// A variety of key components are then initialized. These include workers, signal handlers, Redis, HTTP server, and a stats loop.
// A ticker for stats is also created that triggers at the specified StatsDelay interval.
//
// The application is designed with a focus on managing and handling concurrent processes and operations.
// Each component has its own lifecycle with dependencies managed and taken care of.
func main() {
	parseFlagsAndPrintVersion()

	ctx, cancel := context.WithCancel(context.Background())

	if err := setupEnvironment(); err != nil {
		stdlog.Fatalln("Unable to setup the environment. Error:", err)
	}

	initializeInstanceInfo()
	postEnvironmentDebug()

	if err := setupLuaScripts(); err != nil {
		stdlog.Fatalln("Unable to setup Lua scripts. Error:", err)
	}

	enableBlockProfile()

	statsTicker := time.NewTicker(definitions.StatsDelay * time.Second)
	monitoringTicker := time.NewTicker(definitions.BackendServerMonitoringDelay * time.Second)
	store := newContextStore()

	store.action = newContextTuple(ctx)

	actionWorkers := initializeActionWorkers()

	initializeHTTPClients()
	setupWorkers(ctx, store, actionWorkers)
	handleSignals(ctx, cancel, store, statsTicker, &monitoringTicker, actionWorkers)
	setupRedis(ctx)
	runLuaaInitScript(ctx)
	core.LoadStatsFromRedis(ctx)
	startHTTPServer(ctx, store)
	runConnectionManager(ctx)

	// Backend server monitoring feature
	go runBackendServerMonitoring(ctx, store, monitoringTicker)

	startStatsLoop(ctx, statsTicker)

	os.Exit(0)
}
