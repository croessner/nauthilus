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
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/croessner/nauthilus/server/lualib/filter"
	"github.com/croessner/nauthilus/server/lualib/hook"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util/keygen"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
)

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
	genOIDCKey := flag.Bool("gen-oidc-key", false, "generate a new RSA key for OIDC signing")
	genSAMLCert := flag.String("gen-saml-cert", "", "generate a self-signed certificate for SAML (provide common name)")
	keyBits := flag.Int("key-bits", 4096, "bits for the generated RSA key")
	certYears := flag.Int("cert-years", 10, "validity in years for the generated certificate")

	flag.Parse()

	if *versionFlag {
		fmt.Println("Version: ", version)
		os.Exit(0)
	}

	if *genOIDCKey {
		key, err := keygen.GenerateRSAKey(*keyBits)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate OIDC key: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(key)
		os.Exit(0)
	}

	if *genSAMLCert != "" {
		cert, key, err := keygen.GenerateSelfSignedCert(*genSAMLCert, *keyBits, *certYears)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate SAML certificate: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Certificate:")
		fmt.Println(cert)
		fmt.Println("Key:")
		fmt.Println(key)
		os.Exit(0)
	}

	if *configFlag != "" {
		config.ConfigFilePath = *configFlag
		viper.SetConfigFile(*configFlag)
	}

	config.ConfigFileType = *configFormatFlag
	viper.SetConfigType(*configFormatFlag)
}

// SetupConfiguration initializes the environment, loads the configuration file,
// optional language bundles, and configures logging.
func SetupConfiguration() error {
	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())

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

	log.SetupLogging(
		file.GetServer().GetLog().GetLogLevel(),
		file.GetServer().GetLog().IsLogFormatJSON(),
		file.GetServer().GetLog().IsLogUsesColor(),
		file.GetServer().GetLog().IsAddSourceEnabled(),
		file.GetServer().GetInstanceName(),
	)

	// Sync the addSource configuration with the level package
	level.ApplyGlobalConfig(file.GetServer().GetLog().IsAddSourceEnabled())

	stdlog.SetOutput(&slogStdWriter{logger: log.GetLogger()})

	return nil
}

// SetupLuaScripts pre-compiles Lua scripts for features, filters, init scripts, and hooks.
func SetupLuaScripts(cfg config.File, logger *slog.Logger) error {
	if err := PreCompileFeatures(cfg, logger); err != nil {
		return err
	}

	if err := PreCompileFilters(cfg, logger); err != nil {
		return err
	}

	if err := PreCompileInit(cfg); err != nil {
		return err
	}

	return PreCompileHooks(cfg)
}

// PreCompileFeatures pre-compiles Lua features if enabled.
func PreCompileFeatures(cfg config.File, logger *slog.Logger) error {
	if cfg.HaveLuaFeatures() {
		if err := feature.PreCompileLuaFeatures(cfg, logger); err != nil {
			return err
		}
	}

	return nil
}

// PreCompileFilters pre-compiles Lua filters if enabled.
func PreCompileFilters(cfg config.File, logger *slog.Logger) error {
	if cfg.HaveLuaFilters() {
		if err := filter.PreCompileLuaFilters(cfg); err != nil {
			return err
		}
	}

	return nil
}

// PreCompileInit pre-compiles configured Lua init scripts.
func PreCompileInit(cfg config.File) error {
	if cfg.HaveLuaInit() {
		for _, scriptPath := range cfg.GetLuaInitScriptPaths() {
			if err := hook.PreCompileLuaScript(cfg, scriptPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// PreCompileHooks pre-compiles Lua hooks if enabled.
func PreCompileHooks(cfg config.File) error {
	if cfg.HaveLuaHooks() {
		if err := hook.PreCompileLuaHooks(cfg); err != nil {
			return err
		}
	}

	return nil
}

// EnableBlockProfile toggles runtime block profiling according to configuration.
func EnableBlockProfile(cfg config.File) {
	if cfg.GetServer().GetInsights().IsBlockProfileEnabled() {
		runtime.SetBlockProfileRate(1)
	} else {
		runtime.SetBlockProfileRate(-1)
	}
}

// DebugLoadableConfig logs selected configuration sections at debug level.
func DebugLoadableConfig(cfg config.File, logger *slog.Logger) {
	debugIfNotNil := func(key string, value any) {
		if value == nil {
			return
		}

		level.Debug(logger).Log(key, fmt.Sprintf("%+v", value))
	}

	file := cfg

	debugIfNotNil(definitions.FeatureRBL, file.GetRBLs())
	debugIfNotNil(definitions.FeatureTLSEncryption, file.GetClearTextList())
	debugIfNotNil(definitions.FeatureRelayDomains, file.GetRelayDomains())
	debugIfNotNil(definitions.FeatureBackendServersMonitoring, file.GetBackendServerMonitoring())
	debugIfNotNil(definitions.LogKeyBruteForce, file.GetBruteForce())
	debugIfNotNil("idp", file.GetIdP())

	ldap := file.GetLDAP()
	if ldap != nil {
		debugIfNotNil("ldap", ldap.GetConfig())
	}
}

// InitializeInstanceInfo sets the instance info metric labels.
func InitializeInstanceInfo(cfg config.File, version string) {
	infoMetric := stats.GetMetrics().GetInstanceInfo().With(prometheus.Labels{
		"instance_name": cfg.GetServer().GetInstanceName(),
		"version":       version,
	})

	infoMetric.Set(1)
}

// RunLuaInitScript executes Lua init scripts (if configured).
func RunLuaInitScript(ctx context.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client) {
	if cfg.HaveLuaInit() {
		for _, scriptPath := range cfg.GetLuaInitScriptPaths() {
			_ = hook.RunLuaInit(ctx, cfg, logger, redis, scriptPath)
		}
	}
}

// InitializeBruteForceTolerate starts the brute force tolerate housekeeping.
func InitializeBruteForceTolerate(ctx context.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client) {
	t := tolerate.NewTolerateWithDeps(cfg, logger, redis, cfg.GetBruteForce().GetToleratePercent())
	tolerate.SetTolerate(t)

	go t.StartHouseKeeping(ctx)
}

// setTimeZone configures the process time zone based on the TZ environment variable.
func setTimeZone() {
	if tz := os.Getenv("TZ"); tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			time.Local = loc
		} else {
			stdlog.Printf("Error loading location '%s': %v", tz, err)
		}
	}
}
