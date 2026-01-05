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

package bootfx

import (
	"context"
	"flag"
	"fmt"
	stdlog "log"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/lualib/hook"
	"github.com/croessner/nauthilus/server/stats"

	jsoniter "github.com/json-iterator/go"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
	"golang.org/x/text/language"
)

var json = jsoniter.ConfigFastest

// slogStdWriter adapts the standard library logger to forward to slog via our level wrapper.
type slogStdWriter struct{ logger *slog.Logger }

func (w *slogStdWriter) Write(p []byte) (int, error) {
	_ = level.Info(w.logger).Log("msg", string(p))

	return len(p), nil
}

// ParseFlagsAndPrintVersion parses command-line flags, configures viper/config paths,
// and prints the version information if the `-version` flag is set.
func ParseFlagsAndPrintVersion(version string) {
	versionFlag := flag.Bool("version", false, "print version and exit")
	configFlag := flag.String("config", "", "path to configuration file")
	configFormatFlag := flag.String("config-format", "yaml", "configuration file format (yaml, json, toml, etc.)")

	flag.Parse()

	if *versionFlag {
		fmt.Println("Version: ", version)
		os.Exit(0)
	}

	if *configFlag != "" {
		config.ConfigFilePath = *configFlag
		viper.SetConfigFile(*configFlag)
	}

	viper.SetConfigType(*configFormatFlag)
}

// SetupConfiguration initializes the environment, loads the configuration file,
// optional language bundles, and configures logging.
func SetupConfiguration() error {
	config.NewEnvironmentConfig()

	setTimeZone()

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
		file.GetServer().GetLog().IsAddSourceEnabled(),
		file.GetServer().GetInstanceName(),
	)
	stdlog.SetOutput(&slogStdWriter{logger: log.Logger})

	return nil
}

// SetupLuaScripts pre-compiles Lua scripts for features, filters, init scripts, and hooks.
func SetupLuaScripts() error {
	preCompileSteps := []func() error{PreCompileFeatures, PreCompileFilters, PreCompileInit, PreCompileHooks}

	for _, task := range preCompileSteps {
		if err := task(); err != nil {
			return err
		}
	}

	return nil
}

// PreCompileFeatures pre-compiles Lua features if enabled.
func PreCompileFeatures() error {
	if config.GetFile().HaveLuaFeatures() {
		if err := feature.PreCompileLuaFeatures(); err != nil {
			return err
		}
	}

	return nil
}

// PreCompileFilters pre-compiles Lua filters if enabled.
func PreCompileFilters() error {
	if config.GetFile().HaveLuaFilters() {
		if err := filter.PreCompileLuaFilters(); err != nil {
			return err
		}
	}

	return nil
}

// PreCompileInit pre-compiles configured Lua init scripts.
func PreCompileInit() error {
	if config.GetFile().HaveLuaInit() {
		for _, scriptPath := range config.GetFile().GetLuaInitScriptPaths() {
			if err := hook.PreCompileLuaScript(scriptPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// PreCompileHooks pre-compiles Lua hooks if enabled.
func PreCompileHooks() error {
	if config.GetFile().HaveLuaHooks() {
		if err := hook.PreCompileLuaHooks(); err != nil {
			return err
		}
	}

	return nil
}

// EnableBlockProfile toggles runtime block profiling according to configuration.
func EnableBlockProfile() {
	if config.GetFile().GetServer().GetInsights().IsBlockProfileEnabled() {
		runtime.SetBlockProfileRate(1)
	} else {
		runtime.SetBlockProfileRate(-1)
	}
}

// DebugLoadableConfig logs selected configuration sections at debug level.
func DebugLoadableConfig() {
	debugIfNotNil := func(key string, value any) {
		if value == nil {
			return
		}

		level.Debug(log.Logger).Log(key, fmt.Sprintf("%+v", value))
	}

	file := config.GetFile()

	debugIfNotNil(definitions.FeatureRBL, file.GetRBLs())
	debugIfNotNil(definitions.FeatureTLSEncryption, file.GetClearTextList())
	debugIfNotNil(definitions.FeatureRelayDomains, file.GetRelayDomains())
	debugIfNotNil(definitions.FeatureBackendServersMonitoring, file.GetBackendServerMonitoring())
	debugIfNotNil(definitions.LogKeyBruteForce, file.GetBruteForce())
	debugIfNotNil("oauth2", file.GetOauth2())

	ldap := file.GetLDAP()
	if ldap != nil {
		debugIfNotNil("ldap", ldap.GetConfig())
	}
}

// InitializeInstanceInfo sets the instance info metric labels.
func InitializeInstanceInfo(version string) {
	infoMetric := stats.GetMetrics().GetInstanceInfo().With(prometheus.Labels{
		"instance_name": config.GetFile().GetServer().GetInstanceName(),
		"version":       version,
	})

	infoMetric.Set(1)
}

// InitializeHTTPClients initializes HTTP clients that are only needed when the frontend is enabled.
func InitializeHTTPClients() {
	if config.GetFile().GetServer().Frontend.Enabled {
		core.InitHTTPClient()
	}
}

// RunLuaInitScript executes Lua init scripts (if configured).
func RunLuaInitScript(ctx context.Context) {
	if config.GetFile().HaveLuaInit() {
		for _, scriptPath := range config.GetFile().GetLuaInitScriptPaths() {
			hook.RunLuaInit(ctx, scriptPath)
		}
	}
}

// InitializeBruteForceTolerate starts the brute force tolerate housekeeping.
func InitializeBruteForceTolerate(ctx context.Context) {
	go tolerate.GetTolerate().StartHouseKeeping(ctx)
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

// setTimeZone configures the process time zone based on the TZ environment variable.
func setTimeZone() {
	var err error

	if tz := os.Getenv("TZ"); tz != "" {
		if time.Local, err = time.LoadLocation(tz); err != nil {
			if log.Logger != nil {
				level.Error(log.Logger).Log(
					definitions.LogKeyMsg, fmt.Sprintf("Error loading timezone location '%s'", tz),
					definitions.LogKeyError, err,
				)
			} else {
				stdlog.Printf("Error loading location '%s': %v", tz, err)
			}
		}
	}
}
