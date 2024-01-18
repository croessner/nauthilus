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

type contextTuple struct {
	ctx    context.Context
	cancel context.CancelFunc
}

type contextStore struct {
	ldapLookup *contextTuple
	ldapAuth   *contextTuple
	lua        *contextTuple
	sql        *contextTuple
	action     *contextTuple
}

func newContextStore() *contextStore {
	store := &contextStore{}

	return store
}

func newContextTuple(ctx context.Context) *contextTuple {
	tuple := &contextTuple{}
	tuple.ctx, tuple.cancel = context.WithCancel(ctx)

	return tuple
}

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

func loadLanguageBundles() {
	core.LangBundle = i18n.NewBundle(language.English)

	core.LangBundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	loadLanguageBundle("en")
	loadLanguageBundle("de")
	loadLanguageBundle("fr")
}

func loadLanguageBundle(lang string) {
	if _, err := core.LangBundle.LoadMessageFile(viper.GetString("language_resources") + "/" + lang + ".json"); err != nil {
		panic(err.Error())
	}
}

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

func setupFeatures() error {
	if err := PreCompileFeatures(); err != nil {
		return err
	}

	if err := PreCompileFilters(); err != nil {
		return err
	}

	return nil
}

func PreCompileFeatures() error {
	if !config.EnvConfig.HasFeature(decl.FeatureLua) {
		return nil
	}

	if err := feature.PreCompileLuaFeatures(); err != nil {
		return err
	}

	return nil
}

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

func handleSignals(ctx context.Context, cancel context.CancelFunc, store *contextStore, statsTimer *time.Ticker) {
	// Signal handling
	go func() {
		sigsTerminate := make(chan os.Signal, 1)

		signal.Notify(sigsTerminate, syscall.SIGINT, syscall.SIGTERM)

		sig := <-sigsTerminate
		level.Info(logging.DefaultLogger).Log(
			decl.LogKeyMsg, "Shutting down Nauthilus", "signal", sig,
		)

		cancel()

		// Wait for HTTP server termination
		<-core.HTTPEndChan

		for _, passDB := range config.EnvConfig.PassDBs {
			switch passDB.Get() {
			case decl.BackendLDAP:
				<-backend.LDAPEndChan
				<-backend.LDAPAuthEndChan
			case decl.BackendMySQL, decl.BackendPostgres:
				if backend.Database != nil && backend.Database.Conn != nil {
					backend.Database.Conn.Close()
				}
			case decl.BackendLua:
				<-backend.LuaMainWorkerEndChan
			case decl.BackendCache:
			default:
				level.Warn(logging.DefaultLogger).Log(decl.LogKeyWarning, "Unknown backend")
			}
		}

		<-action.WorkerEndChan

		// Sync some prometheus data to redis
		core.SaveStatsToRedis()

		level.Debug(logging.DefaultLogger).Log(decl.LogKeyMsg, "Shutdown complete")

		statsTimer.Stop()

		os.Exit(0)
	}()

	// Another goroutine for handling reload signal
	go func() {
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
	}()
}

func handleLDAPBackend(lookup, auth *contextTuple, ctx context.Context) (*contextTuple, *contextTuple) {
	stopContext(lookup)

	<-backend.LDAPEndChan

	stopContext(auth)

	<-backend.LDAPAuthEndChan

	lookup.ctx, lookup.cancel = context.WithCancel(ctx)
	auth.ctx, auth.cancel = context.WithCancel(ctx)

	return lookup, auth
}

func handleSQLBackend(sql *contextTuple, ctx context.Context) *contextTuple {
	if backend.Database != nil && backend.Database.Conn != nil {
		backend.Database.Conn.Close()
	}

	stopContext(sql)

	sql.ctx, sql.cancel = context.WithCancel(ctx)

	return sql
}

func handleLuaBackend(lua *contextTuple, ctx context.Context) *contextTuple {
	stopContext(lua)

	<-backend.LuaMainWorkerEndChan

	lua.ctx, lua.cancel = context.WithCancel(ctx)

	return lua
}

func stopAndRestartActionWorker(act *contextTuple, ctx context.Context) {
	stopContext(act)

	<-action.WorkerEndChan

	act.ctx, act.cancel = context.WithCancel(ctx)

	startActionWorker(act)
}

func stopContext(tuple *contextTuple) {
	tuple.cancel()
}

func startActionWorker(act *contextTuple) {
	go action.NewWorker().Work(act.ctx)
}

func startLDAPWorkers(lookup, auth *contextTuple) {
	go backend.LDAPMainWorker(lookup.ctx)
	go backend.LDAPAuthWorker(auth.ctx)
}

func startLuaWorker(lua *contextTuple) {
	go backend.LuaMainWorker(lua.ctx)
}

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

func setupLuaWorker(store *contextStore, ctx context.Context) {
	backend.LuaRequestChan = make(chan *backend.LuaRequest, decl.MaxChannelSize)
	backend.LuaMainWorkerEndChan = make(chan backend.Done)

	store.lua = newContextTuple(ctx)

	startLuaWorker(store.lua)
}

func setupRedis() {
	redisLogger := &util.RedisLogger{}
	redis.SetLogger(redisLogger)

	backend.RedisHandle = util.NewRedisClient()
	backend.RedisHandleReplica = util.NewRedisReplicaClient()

	if backend.RedisHandleReplica == nil {
		backend.RedisHandleReplica = backend.RedisHandle
	}
}

func startHTTPServer(ctx context.Context) {
	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyMsg, "Starting Nauthilus HTTP server",
		"version", version,
	)

	core.HTTPEndChan = make(chan core.Done)

	go core.HTTPApp(ctx)
}

func startStatsLoop(statsTimer *time.Ticker) {
	for {
		select {
		case <-statsTimer.C:
			core.PrintStats()
			core.SaveStatsToRedis()
		}
	}
}

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
