package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	logStdLib "log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-redis/redis/v8"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/spf13/viper"
	"golang.org/x/text/language"
)

const version = "@@gittag@@-@@gitcommit@@"

// contextTuple represents a tuple that contains a context and a cancel function.
// This type is used for managing contexts and cancellations in various parts of the application.
type contextTuple struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// contextStore is a custom structure in which instances of contextTuple are stored for various functionalities.
// The structure contains the following fields: ldapLookup, ldapAuth, lua, sql, action and nginx.
// Each field is a pointer to an instance of contextTuple type. This structure allows for efficient context storage for different processes.
type contextStore struct {
	ldapLookup *contextTuple
	ldapAuth   *contextTuple
	lua        *contextTuple
	sql        *contextTuple
	action     *contextTuple
	nginx      *contextTuple
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
// - Calls logging.SetupLogging() to configure the logging settings using the values from config.EnvConfig.
// - Configures the standard library logger logStdLib to output logs to logging.DefaultErrLogger.
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
	config.EnvConfig, err = config.NewConfig()
	if err != nil {
		return fmt.Errorf("unable to load EnvConfig: %w", err)
	}

	loadLanguageBundles()

	logging.SetupLogging(config.EnvConfig.Verbosity.Level(), config.EnvConfig.LogJSON, config.EnvConfig.InstanceName)
	logStdLib.SetOutput(log.NewStdlibAdapter(logging.DefaultErrLogger))

	setTimeZone()

	config.LoadableConfig, err = config.NewConfigFile()
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(
			global.LogKeyWarning, err,
		)

		return fmt.Errorf("unable to load ConfigFile: %w", err)
	}

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
			level.Error(logging.DefaultErrLogger).Log(
				global.LogKeyError, fmt.Sprintf("Error loading location '%s': %v", tz, err),
			)
		}
	}
}

// setupFeatures prepares the feature and filter for compilation and performs error checking.
// It sequentially runs the PreCompileFeatures and PreCompileFilters methods.
// If those methods return an error, the setupFeatures method will propagated that error up the stack.
// If the pre-compilation is successful, it will return nil.
func setupFeatures() error {
	if err := PreCompileFeatures(); err != nil {
		return err
	}

	if err := PreCompileFilters(); err != nil {
		return err
	}

	return nil
}

// PreCompileFeatures pre-compiles the features for the application based on the configuration.
// If the application is configured without the Lua features (global.FeatureLua), it performs no operation and returns nil.
// If the application is configured with the Lua features, it attempts to pre-compile the Lua features.
// If pre-compilation of the Lua features encounters any errors, it returns the error. Otherwise, it returns nil.
func PreCompileFeatures() error {
	if !config.EnvConfig.HasFeature(global.FeatureLua) {
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
	if config.LoadableConfig.Lua == nil {
		return nil
	}

	if len(config.LoadableConfig.Lua.Filters) == 0 {
		return nil
	}

	if err := filter.PreCompileLuaFilters(); err != nil {
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
	go handleTerminateSignal(cancel, statsTicker, *ngxMonitoringTicker, actionWorkers)
	go handleReloadSignal(ctx, store, ngxMonitoringTicker, actionWorkers)
}

// terminateLuaStatePools shuts down the Lua state pools used by various modules.
// It calls the Shutdown method on each pool to gracefully terminate all active Lua states.
// This function should be called before exiting the application to ensure proper cleanup of resources.
// Example usage:
//
//	terminateLuaStatePools()
func terminateLuaStatePools() {
	filter.LuaPool.Shutdown()
	feature.LuaPool.Shutdown()
	action.LuaPool.Shutdown()
	backend.LuaPool.Shutdown()
}

// closeChannels closes the HTTPEndChan and WorkerEndChan channels.
func closeChannels() {
	close(core.HTTPEndChan)
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
// It handles the backend for each passDB in the configuration.
// It waits for all action workers to complete their work.
// It syncs some Prometheus data to Redis.
// It logs the shutdown complete message.
// It terminates the Lua state pools.
// It closes all channels.
// It stops the statsTicker.
// Signature:
// func handleTerminateSignal(cancel context.CancelFunc, statsTicker *time.Ticker, actionWorkers []*action.Worker) {
func handleTerminateSignal(cancel context.CancelFunc, statsTicker *time.Ticker, ngxMonitoringTicker *time.Ticker, actionWorkers []*action.Worker) {
	sigsTerminate := make(chan os.Signal, 1)

	signal.Notify(sigsTerminate, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigsTerminate

	level.Info(logging.DefaultLogger).Log(global.LogKeyMsg, "Shutting down Nauthilus", "signal", sig)

	cancel()

	// Wait for HTTP server termination
	<-core.HTTPEndChan

	for _, passDB := range config.EnvConfig.PassDBs {
		handleBackend(passDB)
	}

	waitForActionWorkers(actionWorkers)

	// Sync some Prometheus data to Redis
	core.SaveStatsToRedis()

	level.Debug(logging.DefaultLogger).Log(global.LogKeyMsg, "Shutdown complete")

	terminateLuaStatePools()
	closeChannels()

	statsTicker.Stop()
	ngxMonitoringTicker.Stop()
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
func handleBackend(passDB *config.PassDB) {
	switch passDB.Get() {
	case global.BackendLDAP:
		<-backend.LDAPEndChan
		<-backend.LDAPAuthEndChan

		close(backend.LDAPEndChan)
		close(backend.LDAPAuthEndChan)
		close(backend.LDAPRequestChan)
		close(backend.LDAPAuthRequestChan)
	case global.BackendMySQL, global.BackendPostgres:
		if backend.Database != nil && backend.Database.Conn != nil {
			backend.Database.Conn.Close()
		}
	case global.BackendLua:
		<-backend.LuaMainWorkerEndChan

		close(backend.LuaMainWorkerEndChan)
		close(backend.LuaRequestChan)
	case global.BackendCache:
	default:
		level.Warn(logging.DefaultLogger).Log(global.LogKeyWarning, "Unknown backend")
	}
}

// handleLDAPBackend is a function to handle LDAP backend operations.
// It takes three arguments - lookup and auth contextTuple pointers, and a context.
// The function stops the contexts of the 'lookup' and 'auth' and waits for the backend LDAP operations to finish.
// New cancelable contexts from the provided 'ctx' are assigned to the 'lookup' and 'auth'.
// These updated contextTuple pointers are then returned.
func handleLDAPBackend(lookup, auth *contextTuple, ctx context.Context) (*contextTuple, *contextTuple) {
	stopContext(lookup)

	<-backend.LDAPEndChan

	stopContext(auth)

	<-backend.LDAPAuthEndChan

	lookup.ctx, lookup.cancel = context.WithCancel(ctx)
	auth.ctx, auth.cancel = context.WithCancel(ctx)

	return lookup, auth
}

// handleSQLBackend is a function that operates on a context tuple and a given context.
// It closes the database connection if it exists and cancels the previously running context.
// This function then starts a new context with cancel capability and assigns it to the
// context tuple before returning the tuple.
// Input:
// - sql: a pointer to the contextTuple which holds the active context and its cancel function.
// - ctx: a context that will be used to create a new context with cancel capability.
// Output:
// - Returns a pointer to the updated contextTuple with the new context and its associated cancel function.
func handleSQLBackend(sql *contextTuple, ctx context.Context) *contextTuple {
	if backend.Database != nil && backend.Database.Conn != nil {
		backend.Database.Conn.Close()
	}

	stopContext(sql)

	sql.ctx, sql.cancel = context.WithCancel(ctx)

	return sql
}

// handleLuaBackend receives a contextTuple and a context as parameters.
// It runs stopContext on the contextTuple and waits for `LuaMainWorkerEndChan` to end.
// After that, it sets the context and cancel function of the contextTuple using the provided context parameter,
// creating a new context that can be cancelled.
// The function finally returns the modified contextTuple, with the new context bound to it.
func handleLuaBackend(lua *contextTuple, ctx context.Context) *contextTuple {
	stopContext(lua)

	<-backend.LuaMainWorkerEndChan

	lua.ctx, lua.cancel = context.WithCancel(ctx)

	return lua
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

// It takes two parameters, "lookup" of type *contextTuple and "auth" of type *contextTuple.
// The "lookup" parameter stores the context for the LDAP lookup worker, while the "auth" parameter stores the context for the LDAP authentication worker.
// The function spawns goroutines for the LDAPMainWorker and LDAPAuthWorker functions from the backend package, passing the associated context to each worker.
func startLDAPWorkers(lookup, auth *contextTuple) {
	go backend.LDAPMainWorker(lookup.ctx)
	go backend.LDAPAuthWorker(auth.ctx)
}

// startLDAPWorkers is a function that starts two separate goroutines to handle LDAP lookups and authentication.
// It does so by invoking LDAPMainWorker and LDAPAuthWorker functions from the backend package.
//
// Parameters:
// lookup: Pointer to a contextTuple containing a required context for the LDAP lookup worker.
// auth: Pointer to a contextTuple containing a required context for the LDAP authentication worker.
//
// This function doesn't return anything as the LDAP worker methods are called as goroutines and do their work separately.
func startLuaWorker(lua *contextTuple) {
	go backend.LuaMainWorker(lua.ctx)
}

// handleReload is a function that handles the reloading of Nauthilus based on a received operating signal.
// The function works with various backends (LDAP, MySQL, Postgres, Lua, or Cache), and based on the specific
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
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyMsg, "Reloading Nauthilus", "signal", sig,
	)

	for _, passDB := range config.EnvConfig.PassDBs {
		switch passDB.Get() {
		case global.BackendLDAP:
			store.ldapLookup, store.ldapAuth = handleLDAPBackend(store.ldapLookup, store.ldapAuth, ctx)
		case global.BackendMySQL, global.BackendPostgres:
			store.sql = handleSQLBackend(store.sql, ctx)
		case global.BackendLua:
			store.lua = handleLuaBackend(store.lua, ctx)
		case global.BackendCache:
		default:
			level.Warn(logging.DefaultLogger).Log(global.LogKeyWarning, "Unknown backend")
		}
	}

	stopAndRestartActionWorker(actionWorkers, store.action, ctx)

	if err := config.ReloadConfigFile(); err != nil {
		level.Error(logging.DefaultErrLogger).Log(
			global.LogKeyError, err,
		)
	}

	if err := setupFeatures(); err != nil {
		level.Error(logging.DefaultErrLogger).Log(
			global.LogKeyMsg, "Unable to setup the features",
			global.LogKeyError, err,
		)
	}

	for _, passDB := range config.EnvConfig.PassDBs {
		switch passDB.Get() {
		case global.BackendLDAP:
			startLDAPWorkers(store.ldapLookup, store.ldapAuth)
		case global.BackendMySQL, global.BackendPostgres:
			backend.Database = backend.NewDatabase(store.sql.ctx)
		case global.BackendLua:
			startLuaWorker(store.lua)
		case global.BackendCache:
		default:
			level.Warn(logging.DefaultLogger).Log(global.LogKeyWarning, "Unknown backend")
		}
	}

	restartNgxMonitoring(ctx, store, ngxMonitoringTicker)

	level.Debug(logging.DefaultLogger).Log(
		global.LogKeyMsg, "Reload complete",
	)
}

// initializeActionWorkers creates and initializes a slice of action workers.
// It creates `global.MaxActionWorkers` number of workers, each worker is created using `action.NewWorker()`.
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
// Then, for each passDB in the `config.EnvConfig.PassDBs` slice, it performs the necessary setup based on the passDB type.
// The setup depends on the passDB's backend type and calls corresponding setup functions, such as `setupLDAPWorker`, `setupSQLWorker`, or `setupLuaWorker`.
// If the passDB's backend is `global.BackendCache`, no setup is performed.
// If the passDB's backend is unknown, a warning log is generated for an unknown backend.
func setupWorkers(ctx context.Context, store *contextStore, actionWorkers []*action.Worker) {
	startActionWorker(actionWorkers, store.action)

	for _, passDB := range config.EnvConfig.PassDBs {
		switch passDB.Get() {
		case global.BackendLDAP:
			setupLDAPWorker(store, ctx)
		case global.BackendMySQL, global.BackendPostgres, global.BackendSQL:
			setupSQLWorker(store, ctx, passDB)
		case global.BackendLua:
			setupLuaWorker(store, ctx)
		case global.BackendCache:
		default:
			level.Warn(logging.DefaultLogger).Log(global.LogKeyWarning, "Unknown backend", "backend")
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
	authPoolSize := config.LoadableConfig.LDAP.Config.AuthPoolSize

	backend.LDAPRequestChan = make(chan *backend.LDAPRequest, lookupPoolSize)
	backend.LDAPAuthRequestChan = make(chan *backend.LDAPAuthRequest, authPoolSize)
	backend.LDAPEndChan = make(chan backend.Done)
	backend.LDAPAuthEndChan = make(chan backend.Done)

	store.ldapLookup = newContextTuple(ctx)
	store.ldapAuth = newContextTuple(ctx)

	startLDAPWorkers(store.ldapLookup, store.ldapAuth)
}

// setupSQLWorker configures a SQL worker given a context store, a context, and a PassDB configuration.
// It sets the store's sql to a new context tuple created with the input context, and the backend's Database to a new database instance.
// If a database already exists, it logs a warning stating that only one SQLConf Database is allowed and doesn't proceed with
func setupSQLWorker(store *contextStore, ctx context.Context, passDB *config.PassDB) {
	if backend.Database != nil {
		level.Warn(logging.DefaultLogger).Log(
			global.LogKeyWarning, "Currently only one SQLConf Database is allowed!",
			"skipping", passDB)

		return
	}

	store.sql = newContextTuple(ctx)
	backend.Database = backend.NewDatabase(store.sql.ctx)
}

// setupLuaWorker initializes a Lua worker with the help of channels.
// It configures communication channels for handling Lua requests and signaling when the worker has finished its tasks.
// The function receives a store of type *contextStore and a context as arguments.
// The context store is modified within the function where it initializes the LuaContext based on the provided context.
// The Lua worker is then started with the initialized context.
func setupLuaWorker(store *contextStore, ctx context.Context) {
	backend.LuaRequestChan = make(chan *backend.LuaRequest, global.MaxChannelSize)
	backend.LuaMainWorkerEndChan = make(chan backend.Done)

	store.lua = newContextTuple(ctx)

	startLuaWorker(store.lua)
}

// setupRedis initializes the Redis clients for the main and replica instances.
// First, it sets the logger for redis to a new RedisLogger instance.
// Then, it assigns a new RedisClient to RedisHandle, and a RedisReplicaClient to RedisHandleReplica.
// If the initialization of RedisReplicaClient fails, RedisHandle is used as a fallback.
func setupRedis() {
	redisLogger := &util.RedisLogger{}
	redis.SetLogger(redisLogger)

	backend.RedisHandle = util.NewRedisClient()
	backend.RedisHandleReplica = util.NewRedisReplicaClient()

	if backend.RedisHandleReplica == nil {
		backend.RedisHandleReplica = backend.RedisHandle
	}
}

// startHTTPServer is a function that starts the HTTP server.
// It takes a context.Context as an argument which is used for HTTPApp.
// It indirectly initiates HTTPApp function from the 'core' package that starts the HTTP server.
// After starting the HTTP server it logs the message "Starting Nauthilus HTTP server" along with its version.
// The server is started as a goroutine and runs asynchronously in the background.
// Any signal sent to close the server is sent through the HTTPEndChan channel of type Done.
func startHTTPServer(ctx context.Context) {
	level.Info(logging.DefaultLogger).Log(
		global.LogKeyMsg, "Starting Nauthilus HTTP server",
		"version", version,
	)

	core.HTTPEndChan = make(chan core.Done)

	go core.HTTPApp(ctx)
}

// logLuaStatePoolDebug logs the statistics of different Lua state pools.
// It calls the LogStatistics function of each Lua state pool.
func logLuaStatePoolDebug() {
	feature.LuaPool.LogStatistics("feature")
	backend.LuaPool.LogStatistics("backend")
	filter.LuaPool.LogStatistics("filter")
	action.LuaPool.LogStatistics("action")
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
			core.SaveStatsToRedis()

			logLuaStatePoolDebug()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// checkNgxBackendServer checks the availability of a backend server by trying to establish a TCP connection with the specified IP address and port.
// It returns an error if the connection cannot be established within the timeout period.
// The function does not retry the connection and closes the connection before returning.
func checkNgxBackendServer(ipAddress string, port int) error {
	timeout := 5 * time.Second

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ipAddress, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return err
	}

	defer conn.Close()

	return nil
}

// logNgxBackendError logs an error originating from Nginx Backend Server,
// detailing the server configuration at the time of the error.
// The logged details include error message, protocol used by the server,
// and the IP address and Port used by the Nginx Backend Server.
//
// Parameters:
//
//	server: a pointer to the configuration of the Nginx Backend Server at the time of the error
//	err: the error that has occurred
func logNgxBackendError(server *config.NginxBackendServer, err error) {
	level.Error(logging.DefaultErrLogger).Log(
		global.LogKeyError, err,
		global.LogKeyMsg, "Server doen",
		global.LogKeyProtocol, server.Protocol,
		global.LogKeyNgxBackendIP, server.IP,
		global.LogKeyNgxBackendPort, server.Port,
	)
}

// logNgxBackendDebug logs debug information for an Nginx backend server. It uses the util.DebugModule function to log the debug message and key-value pairs.
// Parameters:
// - server: a pointer to the NginxBackendServer struct that contains the server information.
// Example usage:
//
//	logNgxBackendDebug(server)
func logNgxBackendDebug(server *config.NginxBackendServer) {
	util.DebugModule(
		global.DbgFeature,
		global.LogKeyMsg, "Server alive",
		global.LogKeyProtocol, server.Protocol,
		global.LogKeyNgxBackendIP, server.IP,
		global.LogKeyNgxBackendPort, server.Port,
	)
}

// loopNgxBackendServers iterates over a slice of NginxBackendServer objects, checks the availability of each server,
// and updates the NginxBackendServers collection if necessary.
//
// Parameters:
// - servers: A slice of NginxBackendServer objects representing the backend servers to be monitored.
//
// type nginxServers: A struct that holds information related to the monitoring process.
// - update: A boolean flag indicating whether any backend server failed to respond.
// - servers: A slice of NginxBackendServer objects representing the available backend servers.
// - mu: A mutex used for synchronizing access to the nginxServers struct fields.
//
// var wg: A WaitGroup used to wait for all goroutines to finish.
//
// ngxAlive: An instance of the nginxServers struct.
//
// Iterates over each server in the servers slice using a goroutine.
// - For each server, it checks the connectivity using the checkNgxBackendServer function.
// - Acquires a lock on ngxAlive.mu to prevent concurrent writes.
// - If an error occurs, sets ngxAlive.update to true and logs the error using the logNgxBackendError function.
// - If no error occurs, appends the server to ngxAlive.servers.
// - Decrements the WaitGroup counter by calling wg.Done().
//
// Waits for all goroutines to finish by calling wg.Wait().
//
// If ngxAlive.update is true, it updates the NginxBackendServers collection using the core.NginxBackendServers.Update method.
func loopNgxBackendServers(servers []*config.NginxBackendServer) {
	type nginxServers struct {
		update  bool
		servers []*config.NginxBackendServer
		mu      sync.Mutex
	}

	var wg sync.WaitGroup

	wg.Add(len(servers))

	ngxAlive := &nginxServers{}

	for _, server := range servers {
		go func(server *config.NginxBackendServer) {
			err := checkNgxBackendServer(server.IP, server.Port)

			ngxAlive.mu.Lock()

			defer ngxAlive.mu.Unlock()

			if err != nil {
				ngxAlive.update = true

				logNgxBackendError(server, err)
			} else {
				ngxAlive.servers = append(ngxAlive.servers, server)

				logNgxBackendDebug(server)
			}

			wg.Done()
		}(server)
	}

	wg.Wait()

	if ngxAlive.update {
		core.NginxBackendServers.Update(ngxAlive.servers)
	}
}

// verifyNginxMonitoringConfig checks if the nginx monitoring feature is enabled.
// If enabled, it gets the backend servers from the LoadableConfig.
// If there are no backend servers or the feature is not enabled, it returns an error.
// It returns a list with Nginx backend servers or an error.
func verifyNginxMonitoringConfig() ([]*config.NginxBackendServer, error) {
	if !config.EnvConfig.HasFeature(global.FeatureNginxMonitoring) {
		return nil, errors2.ErrFeatureNgxDisables
	}

	nginxBackendServers := config.LoadableConfig.GetNginxBackendServers()
	if len(nginxBackendServers) == 0 {
		return nil, errors2.ErrNgxMonitoringEmpty
	}

	return nginxBackendServers, nil
}

// runNgxMonitoring sets a new context for Nginx monitoring and initiates the monitoring.
// The function requires three parameters: a base context ctx, a store of context objects, and a ticker for Nginx monitoring.
// It creates a new context specifically for Nginx with its own cancellation function and stores these in the context store.
// It then attempts to start Nginx monitoring using the startNginxMonitoring function.
// If an error occurs during the start of monitoring, it is handled by the handleNgxMonitoringError function.
//
// ctx is the base context from which the Nginx-specific context is derived.
// store is a store for context objects that can hold the specific context for Nginx monitoring.
// ngxMonitoringTicker is a ticker that triggers the Nginx monitoring at regular intervals.
func runNgxMonitoring(ctx context.Context, store *contextStore, ngxMonitoringTicker *time.Ticker) {
	ngxCtx, ngxCancel := context.WithCancel(ctx)

	store.nginx = &contextTuple{
		ctx:    ngxCtx,
		cancel: ngxCancel,
	}

	if err := startNginxMonitoring(store, ngxMonitoringTicker); err != nil {
		handleNgxMonitoringError(err)
	}
}

// startNginxMonitoring initiates the monitoring of Nginx servers. It takes a contextStore
// and a ticker as arguments. The contextStore is used to manage context-specific values across API boundaries
// and between processes, and the ticker is used to trigger Nginx server assessment at regular intervals.
// The function first validates the Nginx monitoring configuration and updates the NginxBackendServers in the
// core package as necessary. It then enters a loop which repeatedly evaluates the status of the Nginx backend servers
// at intervals defined by the ticker. The loop continues until the context is cancelled.
//
// Arguments:
// - store: A pointer to a contextStore instance. Used to manage context-specific values.
// - ticker: A pointer to a time.Ticker instance. Used to trigger Nginx server assessments at regular intervals.
//
// Returns:
// Returns an error if the Nginx monitoring configuration verification fails or if the context is cancelled.
func startNginxMonitoring(store *contextStore, ticker *time.Ticker) error {
	nginxBackendServers, err := verifyNginxMonitoringConfig()
	if err != nil {
		return err
	}

	core.NginxBackendServers.Update(nginxBackendServers)
	loopNgxBackendServers(nginxBackendServers)

	for {
		select {
		case <-ticker.C:
			loopNgxBackendServers(nginxBackendServers)
		case <-store.nginx.ctx.Done():
			return store.nginx.ctx.Err()
		}
	}
}

// handleNgxMonitoringError is a function that handles errors related
// to the Nginx monitoring feature. If the Nginx monitoring feature is
// not enabled, it logs an informational message. If there are no
// configured backend servers for Nginx monitoring, it logs an error message.
func handleNgxMonitoringError(err error) {
	if !config.EnvConfig.HasFeature(global.FeatureNginxMonitoring) {
		if errors.Is(err, errors2.ErrFeatureNgxDisables) {
			level.Info(logging.DefaultLogger).Log(global.LogKeyMsg, "Nginx monitoring feature is not enabled")
		}
	} else if errors.Is(err, errors2.ErrNgxMonitoringEmpty) {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyError, "Nginx monitoring backend servers are not configured")
	}
}

// restartNgxMonitoring stops the current monitoring ticker, cancels the nginx context from the store,
// then starts a new monitoring ticker and begins monitoring nginx again in a new goroutine.
// This function is useful when you need to restart the nginx monitoring process for any reason, like configuration changes.
//
// Params:
// - ctx: The context in which we run monitoring. Can be used to stop monitoring externally.
// - store: A reference to the contextStore, which holds the cancel function for the nginx context.
// - ngxMonitoring: A double pointer to a time Ticker, which we stop and replace with a new Ticker.
func restartNgxMonitoring(ctx context.Context, store *contextStore, ngxMonitoring **time.Ticker) {
	(*ngxMonitoring).Stop()
	store.nginx.cancel()

	*ngxMonitoring = time.NewTicker(global.NginxMonitoringDelay * time.Second)

	go runNgxMonitoring(ctx, store, *ngxMonitoring)
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
	ctx, cancel := context.WithCancel(context.Background())

	if err := setupEnvironment(); err != nil {
		logStdLib.Fatalln("Unable to setup the environment. Error:", err)
	}

	if err := setupFeatures(); err != nil {
		logStdLib.Fatalln("Unable to setup the features. Error:", err)
	}

	statsTicker := time.NewTicker(global.StatsDelay * time.Second)
	ngxMonitoringTicker := time.NewTicker(global.NginxMonitoringDelay * time.Second)
	store := newContextStore()

	store.action = newContextTuple(ctx)

	actionWorkers := initializeActionWorkers()

	setupWorkers(ctx, store, actionWorkers)
	handleSignals(ctx, cancel, store, statsTicker, &ngxMonitoringTicker, actionWorkers)
	setupRedis()
	core.LoadStatsFromRedis()
	startHTTPServer(ctx)

	// Nginx monitoring feature
	go runNgxMonitoring(ctx, store, ngxMonitoringTicker)

	startStatsLoop(ctx, statsTicker)

	os.Exit(0)
}
