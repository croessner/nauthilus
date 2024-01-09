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
	"github.com/oschwald/maxminddb-golang"
	"github.com/spf13/viper"
	"golang.org/x/text/language"
)

const version = "@@gittag@@-@@gitcommit@@"

//nolint:gocognit // Ignore
func main() {
	var (
		ldapCtx          context.Context
		ldapAuthCtx      context.Context
		luaActionCtx     context.Context
		sqlCtx           context.Context
		luaBackendCtx    context.Context
		ldapCancel       context.CancelFunc
		ldapAuthCancel   context.CancelFunc
		luaActionCancel  context.CancelFunc
		sqlCancel        context.CancelFunc
		luaBackendCancel context.CancelFunc
		err              error
	)

	config.EnvConfig, err = config.NewConfig()
	if err != nil {
		logStdLib.Fatalf("Unable to load EnvConfig: %s", err)
	}

	core.LangBundle = i18n.NewBundle(language.English)

	core.LangBundle.RegisterUnmarshalFunc("json", json.Unmarshal)
	if _, err := core.LangBundle.LoadMessageFile(viper.GetString("language_resources") + "/en.json"); err != nil {
		panic(err.Error())
	}
	if _, err := core.LangBundle.LoadMessageFile(viper.GetString("language_resources") + "/de.json"); err != nil {
		panic(err.Error())
	}
	if _, err := core.LangBundle.LoadMessageFile(viper.GetString("language_resources") + "/fr.json"); err != nil {
		panic(err.Error())
	}

	logging.SetupLogging(config.EnvConfig.Verbosity.Level(), config.EnvConfig.LogJSON, config.EnvConfig.InstanceName)
	logStdLib.SetOutput(log.NewStdlibAdapter(logging.DefaultErrLogger))

	// Manually set time zone
	if tz := os.Getenv("TZ"); tz != "" {
		if time.Local, err = time.LoadLocation(tz); err != nil {
			level.Error(logging.DefaultErrLogger).Log(
				decl.LogKeyError, fmt.Sprintf("Error loading location '%s': %v", tz, err),
			)
		}
	}

	config.LoadableConfig, err = config.NewConfigFile()
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(
			decl.LogKeyWarning, err,
		)

		os.Exit(1)
	}

	level.Debug(logging.DefaultLogger).Log(
		"EnvConfig", config.EnvConfig,
	)

	if config.EnvConfig.HasFeature(decl.FeatureGeoIP) {
		core.GeoIPReader = &core.GeoIP{}

		core.GeoIPReader.Reader, err = maxminddb.Open(config.EnvConfig.GeoipPath)
		if err != nil {
			level.Error(logging.DefaultErrLogger).Log(
				decl.LogKeyMsg, "Can not open GeoLite2-City Database file",
				decl.LogKeyError, err,
			)

			core.GeoIPReader = nil
		}
	}

	if config.EnvConfig.HasFeature(decl.FeatureLua) {
		err = feature.PreCompileLuaFeatures()
		if err != nil {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyError, err)

			os.Exit(1)
		}
	}

	if config.LoadableConfig.Lua != nil && len(config.LoadableConfig.Lua.Filters) > 0 {
		err = filter.PreCompileLuaFilters()
		if err != nil {
			level.Error(logging.DefaultErrLogger).Log(decl.LogKeyError, err)

			os.Exit(1)
		}
	}

	// Signal handling
	sigsTerminate := make(chan os.Signal, 1)
	sigsReload := make(chan os.Signal, 1)

	signal.Notify(sigsTerminate, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(sigsReload, syscall.SIGHUP)

	// The statsTimer is used to print frequent statistics.
	statsTimer := time.NewTicker(decl.StatsDelay * time.Second)

	// Root context
	ctx, cancel := context.WithCancel(context.Background())

	// Lua action end channel and worker context
	action.WorkerEndChan = make(chan lualib.Done)
	luaActionCtx, luaActionCancel = context.WithCancel(ctx)

	go action.NewWorker().Work(luaActionCtx)

	go func() {
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
			}
		}

		<-action.WorkerEndChan

		// Sync some prometheus data to redis
		core.SaveStatsToRedis()

		level.Debug(logging.DefaultLogger).Log(decl.LogKeyMsg, "Shutdown complete")

		statsTimer.Stop()

		os.Exit(0)
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case sig := <-sigsReload:
				level.Info(logging.DefaultLogger).Log(
					decl.LogKeyMsg, "Reloading Nauthilus", "signal", sig,
				)

				for _, passDB := range config.EnvConfig.PassDBs {
					switch passDB.Get() {
					case decl.BackendLDAP:
						ldapCancel()

						<-backend.LDAPEndChan

						ldapAuthCancel()

						<-backend.LDAPAuthEndChan

						// Create new context after stopping LDAP
						ldapCtx, ldapCancel = context.WithCancel(ctx)
						ldapAuthCtx, ldapAuthCancel = context.WithCancel(ctx)
					case decl.BackendMySQL, decl.BackendPostgres:
						if backend.Database != nil && backend.Database.Conn != nil {
							backend.Database.Conn.Close()
						}

						sqlCancel()

						// Create new context after stopping SQK
						sqlCtx, sqlCancel = context.WithCancel(ctx)
					case decl.BackendLua:
						luaBackendCancel()

						<-backend.LuaMainWorkerEndChan

						luaBackendCtx, luaBackendCancel = context.WithCancel(ctx)
					}
				}

				luaActionCancel()

				<-action.WorkerEndChan

				luaActionCtx, luaActionCancel = context.WithCancel(ctx)

				// Restart action worker.
				go action.NewWorker().Work(luaActionCtx)

				if err := config.ReloadConfigFile(); err != nil {
					level.Error(logging.DefaultErrLogger).Log(
						decl.LogKeyError, err,
					)
				}

				for _, passDB := range config.EnvConfig.PassDBs {
					switch passDB.Get() {
					case decl.BackendLDAP:
						go backend.LDAPMainWorker(ldapCtx)
						go backend.LDAPAuthWorker(ldapAuthCtx)
					case decl.BackendMySQL, decl.BackendPostgres:
						backend.Database = backend.NewDatabase(sqlCtx)
					case decl.BackendLua:
						go backend.LuaMainWorker(ctx)
					}
				}

				if config.EnvConfig.HasFeature(decl.FeatureLua) {
					err = feature.PreCompileLuaFeatures()
					if err != nil {
						level.Error(logging.DefaultErrLogger).Log(decl.LogKeyError, err)
					}
				}

				if config.LoadableConfig.Lua != nil && len(config.LoadableConfig.Lua.Filters) > 0 {
					err = filter.PreCompileLuaFilters()
					if err != nil {
						level.Error(logging.DefaultErrLogger).Log(decl.LogKeyError, err)
					}
				}

				level.Debug(logging.DefaultLogger).Log(
					decl.LogKeyMsg, "Reload complete",
				)
			}
		}
	}()

	for _, passDB := range config.EnvConfig.PassDBs {
		switch passDB.Get() {
		case decl.BackendLDAP:
			backend.LDAPRequestChan = make(chan *backend.LDAPRequest, config.LoadableConfig.LDAP.Config.LookupPoolSize)
			backend.LDAPAuthRequestChan = make(chan *backend.LDAPAuthRequest, config.LoadableConfig.LDAP.Config.LookupPoolSize)
			backend.LDAPEndChan = make(chan backend.Done)
			backend.LDAPAuthEndChan = make(chan backend.Done)

			// LDAP context
			ldapCtx, ldapCancel = context.WithCancel(ctx)
			ldapAuthCtx, ldapAuthCancel = context.WithCancel(ctx)

			// Start LDAP worker process
			go backend.LDAPMainWorker(ldapCtx)
			go backend.LDAPAuthWorker(ldapAuthCtx)
		case decl.BackendMySQL, decl.BackendPostgres, decl.BackendSQL:
			if backend.Database != nil {
				level.Warn(logging.DefaultLogger).Log(
					decl.LogKeyWarning, "Currently only one SQLConf Database is allowed!",
					"skipping", passDB)

				continue
			}

			sqlCtx, sqlCancel = context.WithCancel(ctx)

			backend.Database = backend.NewDatabase(sqlCtx)
		case decl.BackendLua:
			backend.LuaRequestChan = make(chan *backend.LuaRequest, decl.MaxChannelSize)
			backend.LuaMainWorkerEndChan = make(chan backend.Done)

			luaBackendCtx, luaBackendCancel = context.WithCancel(ctx)

			go backend.LuaMainWorker(luaBackendCtx)
		}
	}

	redisLogger := &util.RedisLogger{}
	redis.SetLogger(redisLogger)

	backend.RedisHandle = util.NewRedisClient()
	backend.RedisHandleReplica = util.NewRedisReplicaClient()

	if backend.RedisHandleReplica == nil {
		backend.RedisHandleReplica = backend.RedisHandle
	}

	core.LoadStatsFromRedis()

	level.Info(logging.DefaultLogger).Log(
		decl.LogKeyMsg, "Starting Nauthilus HTTP server",
		"version", version,
	)

	core.HTTPEndChan = make(chan core.Done)

	go core.HTTPApp(ctx)

	for {
		select {
		case <-statsTimer.C:
			core.PrintStats()
			core.SaveStatsToRedis()
		}
	}
}
