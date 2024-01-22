package main

import (
	"context"
	"encoding/json"
	"fmt"
	logStdLib "log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/decl"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/action"
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/croessner/nauthilus/server/lualib/filter"
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
// The structure contains the following fields: ldapLookup, ldapAuth, lua, sql, and action.
// Each field is a pointer to an instance of contextTuple type. This structure allows for efficient context storage for different processes.
type contextStore struct {
	ldapLookup *contextTuple
	ldapAuth   *contextTuple
	lua        *contextTuple
	sql        *contextTuple
	action     *contextTuple
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
			decl.LogKeyWarning, err,
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
				decl.LogKeyError, fmt.Sprintf("Error loading location '%s': %v", tz, err),
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
// If the application is configured without the Lua features (decl.FeatureLua), it performs no operation and returns nil.
// If the application is configured with the Lua features, it attempts to pre-compile the Lua features.
// If pre-compilation of the Lua features encounters any errors, it returns the error. Otherwise, it returns nil.
func PreCompileFeatures() error {
	if !config.EnvConfig.HasFeature(decl.FeatureLua) {
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

// handleSignals is a function to manage OS signals within the Go application.
// It initiates two goroutines to handle termination and reload signals respectively.
// All signal-handling functions are called asynchronously.
//
// Parameters:
// - `ctx context.Context`: a context that carries deadline, cancelation signals, and other request-scoped values
// - `cancel context.CancelFunc`: a cancel function that can be called to cancel the context
// - `store *contextStore`: a pointer to the context store that may need to be modified or queried upon receiving a signal
// - `statsTimer *time.Ticker`: a pointer to a ticker that performs some action after a certain duration. Might be stopped on receiving a signal.
//
// This function doesn't return any values.
func handleSignals(ctx context.Context, cancel context.CancelFunc, store *contextStore, statsTimer *time.Ticker) {
	go handleTerminateSignal(cancel, statsTimer)
	go handleReloadSignal(ctx, store)
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
	close(action.WorkerEndChan)
}

// handleTerminateSignal is a function which listens for system level termination signals (SIGINT, SIGTERM).
// Upon receiving such signal, it initiates an orderly shutdown of the application by
// cancelling context and executing cleanup tasks such as handling backend connections,
// syncing Prometheus metrics to Redis and stopping the stats timer before ultimately
// exiting the application. It's specifically designed to gracefully shut down "Nauthilus" service.
//
// cancel arg: method to call to cancel the context
//
// statsTimer arg: reference to the statistics timer that keeps track of application statistics
//
// How to use:
//
//	func main() {
//	     // Create context, and statsTimer
//	     ctx, cancel := context.WithCancel(context.Background())
//	     statsTimer := time.NewTicker(5 * time.Second)
//	     // Then call this function to handle termination signals
//	     go handleTerminateSignal(cancel, statsTimer)
//	     // Rest of your application logic
//	}
func handleTerminateSignal(cancel context.CancelFunc, statsTimer *time.Ticker) {
	sigsTerminate := make(chan os.Signal, 1)

	signal.Notify(sigsTerminate, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigsTerminate

	level.Info(logging.DefaultLogger).Log(decl.LogKeyMsg, "Shutting down Nauthilus", "signal", sig)

	cancel()

	// Wait for HTTP server termination
	<-core.HTTPEndChan

	for _, passDB := range config.EnvConfig.PassDBs {
		handleBackend(passDB)
	}

	<-action.WorkerEndChan

	// Sync some Prometheus data to Redis
	core.SaveStatsToRedis()

	level.Debug(logging.DefaultLogger).Log(decl.LogKeyMsg, "Shutdown complete")

	statsTimer.Stop()

	terminateLuaStatePools()
	closeChannels()

	os.Exit(0)
}

// handleReloadSignal is a function that listens for a SIGHUP (hangup signal) from the operating system.
// When the signal is received, the function handles the reload process by calling the handleReload function.
// It takes two arguments: a context defined by the caller (ctx) which dictates the lifetime of the process,
// and a pointer to a contextStore (store) which presumably stores context data used by the handler.
//
// handleReloadSignal operates in an infinite loop, continuously listening for signals until the context is cancelled.
// If the received signal is SIGHUP, the loop calls handleReload with the same context and store, plus the received signal.
//
// The function does not return anything, and it continues to run until the provided context is cancelled, at which point it exits the loop and the function.
func handleReloadSignal(ctx context.Context, store *contextStore) {
	sigsReload := make(chan os.Signal, 1)

	signal.Notify(sigsReload, syscall.SIGHUP)

	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigsReload:
			handleReload(ctx, store, sig)
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
	case decl.BackendLDAP:
		<-backend.LDAPEndChan
		<-backend.LDAPAuthEndChan

		close(backend.LDAPEndChan)
		close(backend.LDAPAuthEndChan)
		close(backend.LDAPRequestChan)
		close(backend.LDAPAuthRequestChan)
	case decl.BackendMySQL, decl.BackendPostgres:
		if backend.Database != nil && backend.Database.Conn != nil {
			backend.Database.Conn.Close()
		}
	case decl.BackendLua:
		<-backend.LuaMainWorkerEndChan

		close(backend.LuaMainWorkerEndChan)
		close(backend.LuaRequestChan)
	case decl.BackendCache:
	default:
		level.Warn(logging.DefaultLogger).Log(decl.LogKeyWarning, "Unknown backend")
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

// stopAndRestartActionWorker is a helper function that first stops a running action worker
// associated with the context tuple provided (act), then restarts it with a fresh context.
// The function achieves this by utilizing the context's cancel function to stop the ongoing work,
// waiting for the action worker to completely shut down, and then starting a new action worker
// with a fresh context derived from the original context (ctx).
func stopAndRestartActionWorker(act *contextTuple, ctx context.Context) {
	stopContext(act)

	<-action.WorkerEndChan

	act.ctx, act.cancel = context.WithCancel(ctx)

	startActionWorker(act)
}

// stopContext cancels the context associated with the given contextTuple.
func stopContext(tuple *contextTuple) {
	tuple.cancel()
}

// startActionWorker starts a new worker to perform an action.
// It creates a new instance of the Worker struct and calls the Work method with the given contextTuple.
func startActionWorker(act *contextTuple) {
	go action.NewWorker().Work(act.ctx)
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

// handleReload takes in a context, a contextStore and an operating signal as input.
// Based on the type of backend used (LDAP, MySQL, Postgres, Lua, or Cache), it reloads the
// corresponding services, and restarts the necessary workers by calling the relevant functions.
// Specific logging messages and error handlers are called at various stages during the process.
// This function is generally invoked when a reload signal is received by Nauthilus, requiring it to
// refresh its configuration and restart the services according to the updated configuration.
// Parameters:
//
//	ctx:     The context on which this function will operate
//	store:   The contextStore containing the current state of the backend services
//	sig:     The signal that triggers the reloading of Nauthilus
func handleReload(ctx context.Context, store *contextStore, sig os.Signal) {
	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyMsg, "Reloading Nauthilus", "signal", sig,
	)

	for _, passDB := range config.EnvConfig.PassDBs {
		switch passDB.Get() {
		case decl.BackendLDAP:
			store.ldapLookup, store.ldapAuth = handleLDAPBackend(store.ldapLookup, store.ldapAuth, ctx)
		case decl.BackendMySQL, decl.BackendPostgres:
			store.sql = handleSQLBackend(store.sql, ctx)
		case decl.BackendLua:
			store.lua = handleLuaBackend(store.lua, ctx)
		case decl.BackendCache:
		default:
			level.Warn(logging.DefaultLogger).Log(decl.LogKeyWarning, "Unknown backend")
		}
	}

	stopAndRestartActionWorker(store.action, ctx)

	if err := config.ReloadConfigFile(); err != nil {
		level.Error(logging.DefaultErrLogger).Log(
			decl.LogKeyError, err,
		)
	}

	if err := setupFeatures(); err != nil {
		level.Error(logging.DefaultErrLogger).Log(
			decl.LogKeyMsg, "Unable to setup the features",
			decl.LogKeyError, err,
		)
	}

	for _, passDB := range config.EnvConfig.PassDBs {
		switch passDB.Get() {
		case decl.BackendLDAP:
			startLDAPWorkers(store.ldapLookup, store.ldapAuth)
		case decl.BackendMySQL, decl.BackendPostgres:
			backend.Database = backend.NewDatabase(store.sql.ctx)
		case decl.BackendLua:
			startLuaWorker(store.lua)
		case decl.BackendCache:
		default:
			level.Warn(logging.DefaultLogger).Log(decl.LogKeyWarning, "Unknown backend")
		}
	}

	level.Debug(logging.DefaultLogger).Log(
		decl.LogKeyMsg, "Reload complete",
	)
}

// setupWorkers initializes workers for different backend types based on the
// environment configuration. Each type of worker (e.g., LDAP, SQL, Lua) is setup
// according to the backend type provided in the PassDBs variable from the environment
// configuration. An action worker is started first, and worker channels are created to
// communicate between different workers. If an unknown backend is encountered, a
// warning is logged.
// Parameters:
// ctx – context for managing the life cycle of the workers
// store – contains various components required for backend processing
func setupWorkers(ctx context.Context, store *contextStore) {
	action.WorkerEndChan = make(chan lualib.Done)

	startActionWorker(store.action)

	for _, passDB := range config.EnvConfig.PassDBs {
		switch passDB.Get() {
		case decl.BackendLDAP:
			setupLDAPWorker(store, ctx)
		case decl.BackendMySQL, decl.BackendPostgres, decl.BackendSQL:
			setupSQLWorker(store, ctx, passDB)
		case decl.BackendLua:
			setupLuaWorker(store, ctx)
		case decl.BackendCache:
		default:
			level.Warn(logging.DefaultLogger).Log(decl.LogKeyWarning, "Unknown backend", "backend")
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
			decl.LogKeyWarning, "Currently only one SQLConf Database is allowed!",
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
	backend.LuaRequestChan = make(chan *backend.LuaRequest, decl.MaxChannelSize)
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
		decl.LogKeyMsg, "Starting Nauthilus HTTP server",
		"version", version,
	)

	core.HTTPEndChan = make(chan core.Done)

	go core.HTTPApp(ctx)
}

// startStatsLoop is a function that continuously loops over a time ticker.
// On each tick, it prints the current statistics using the core.PrintStats() function
// and persist them to Redis using core.SaveStatsToRedis().
//
// statsTimer: A time.Ticker object which controls the frequency of stats operations.
//
// Example:
//
//	ticker := time.NewTicker(time.Second * 10)
//	go startStatsLoop(ticker)
func startStatsLoop(statsTimer *time.Ticker) {
	for {
		select {
		case <-statsTimer.C:
			core.PrintStats()
			core.SaveStatsToRedis()
		}
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
	ctx, cancel := context.WithCancel(context.Background())

	if err := setupEnvironment(); err != nil {
		logStdLib.Fatalln("Unable to setup the environment. Error:", err)
	}

	if err := setupFeatures(); err != nil {
		logStdLib.Fatalln("Unable to setup the features. Error:", err)
	}

	statsTimer := time.NewTicker(decl.StatsDelay * time.Second)
	store := newContextStore()

	store.action = newContextTuple(ctx)

	setupWorkers(ctx, store)
	handleSignals(ctx, cancel, store, statsTimer)
	setupRedis()
	core.LoadStatsFromRedis()
	startHTTPServer(ctx)
	startStatsLoop(statsTimer)
}
