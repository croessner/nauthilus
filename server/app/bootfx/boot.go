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

// Package bootfx provides bootfx functionality.
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

	"github.com/croessner/nauthilus/v3/internal/flagutil"
	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/environment"
	"github.com/croessner/nauthilus/v3/server/lualib/hook"
	"github.com/croessner/nauthilus/v3/server/lualib/subject"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util/keygen"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"
)

// slogStdWriter adapts the standard library logger to forward to slog via our level wrapper.
type slogStdWriter struct{ logger *slog.Logger }

func (w *slogStdWriter) Write(p []byte) (int, error) {
	_ = level.Info(w.logger).Log("msg", string(p))

	return len(p), nil
}

// LuaTestFlags holds parsed command-line flags for Lua script testing.
type LuaTestFlags struct {
	ScriptPath   string
	CallbackType string
	MockDataPath string
}

var luaTestFlags LuaTestFlags
var configCheckMode bool
var configDumpDefaultsMode bool
var configDumpNonDefaultsMode bool
var configDumpPrintSensitiveMode bool
var configDumpFormat = config.DumpFormatCanonical

const bootFlagVersion = "version"

// ParseFlagsAndPrintVersion parses command-line flags, configures viper/config paths,
// and prints the version information if the `-version` flag is set.
func ParseFlagsAndPrintVersion(version string) {
	flags := newBootFlags()

	applyBootFlagUsage()

	flag.Parse()

	applyBootRuntimeFlags(version, flags)
	handleBootExitActions(version, flags)
	applyConfigFileFlags(flags)
}

type bootFlags struct {
	version                  *bool
	configPath               *string
	configFormat             *string
	configDumpFormat         *string
	configCheck              *bool
	configDumpDefaults       *bool
	configDumpNonDefaults    *bool
	configDumpPrintSensitive *bool
	genOIDCKey               *bool
	genSAMLCert              *string
	keyBits                  *int
	certYears                *int
	testLuaScript            *string
	testCallback             *string
	testMockData             *string
}

// newBootFlags registers server boot flags and keeps their pointers.
func newBootFlags() bootFlags {
	return bootFlags{
		version:                  flag.Bool(bootFlagVersion, false, "print version and exit"),
		configPath:               flag.String("config", "", "path to configuration file"),
		configFormat:             flag.String("config-format", "yaml", "configuration file format (yaml, json, toml, etc.)"),
		configDumpFormat:         flag.String("dump-format", string(config.DumpFormatCanonical), "configuration dump output format (canonical, yaml, json, toml)"),
		configCheck:              flag.Bool("config-check", false, "validate configuration and exit (0 if valid, 1 otherwise)"),
		configDumpDefaults:       flag.Bool("d", false, "print configuration defaults and exit"),
		configDumpNonDefaults:    flag.Bool("n", false, "print non-default configuration values and exit"),
		configDumpPrintSensitive: flag.Bool("P", false, "print sensitive configuration values in dump output"),
		genOIDCKey:               flag.Bool("gen-oidc-key", false, "generate a new RSA key for OIDC signing"),
		genSAMLCert:              flag.String("gen-saml-cert", "", "generate a self-signed certificate for SAML (provide common name)"),
		keyBits:                  flag.Int("key-bits", 4096, "bits for the generated RSA key"),
		certYears:                flag.Int("cert-years", 10, "validity in years for the generated certificate"),
		testLuaScript:            flag.String("test-lua", "", "path to Lua script to test"),
		testCallback:             flag.String("test-callback", "", "callback type: subject, environment, action, backend, hook, cache_flush"),
		testMockData:             flag.String("test-mock", "", "path to JSON file with mock data"),
	}
}

// applyBootFlagUsage installs grouped usage output for server boot flags.
func applyBootFlagUsage() {
	flagutil.ApplyGroupedDoubleDashUsage(flag.CommandLine, "nauthilus", []flagutil.UsageGroup{
		{Title: "General", Flags: []string{bootFlagVersion, "config", "config-format"}},
		{Title: "Configuration Checks", Flags: []string{"config-check", "d", "n", "dump-format", "P"}},
		{Title: "Key Generation", Flags: []string{"gen-oidc-key", "gen-saml-cert", "key-bits", "cert-years"}},
		{Title: "Lua Testing", Flags: []string{"test-lua", "test-callback", "test-mock"}},
	})
}

// applyBootRuntimeFlags stores parsed flags in package runtime state.
func applyBootRuntimeFlags(version string, flags bootFlags) {
	luaTestFlags.ScriptPath = *flags.testLuaScript
	luaTestFlags.CallbackType = *flags.testCallback
	luaTestFlags.MockDataPath = *flags.testMockData
	configCheckMode = *flags.configCheck
	configDumpDefaultsMode = *flags.configDumpDefaults
	configDumpNonDefaultsMode = *flags.configDumpNonDefaults
	configDumpPrintSensitiveMode = *flags.configDumpPrintSensitive
	config.SetConfigDumpPrintSensitiveValues(*flags.configDumpPrintSensitive)
	config.SetConfigDumpVersion(version)

	parsedDumpFormat, err := config.ParseDumpFormat(*flags.configDumpFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --dump-format value: %v\n", err)
		os.Exit(1)
	}

	configDumpFormat = parsedDumpFormat
}

// handleBootExitActions performs flags that print and terminate the process.
func handleBootExitActions(version string, flags bootFlags) {
	if *flags.version {
		fmt.Println("Version: ", version)
		os.Exit(0)
	}

	if *flags.genOIDCKey {
		printGeneratedOIDCKey(*flags.keyBits)
	}

	if *flags.genSAMLCert != "" {
		printGeneratedSAMLCert(*flags.genSAMLCert, *flags.keyBits, *flags.certYears)
	}
}

// printGeneratedOIDCKey prints an RSA signing key and exits.
func printGeneratedOIDCKey(keyBits int) {
	key, err := keygen.GenerateRSAKey(keyBits)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate OIDC key: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(key)
	os.Exit(0)
}

// printGeneratedSAMLCert prints a SAML certificate/key pair and exits.
func printGeneratedSAMLCert(commonName string, keyBits int, certYears int) {
	cert, key, err := keygen.GenerateSelfSignedCert(commonName, keyBits, certYears)
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

// applyConfigFileFlags updates Viper with parsed config file flags.
func applyConfigFileFlags(flags bootFlags) {
	if *flags.configPath != "" {
		config.ConfigFilePath = *flags.configPath
		viper.SetConfigFile(*flags.configPath)
	}

	config.ConfigFileType = *flags.configFormat
	viper.SetConfigType(*flags.configFormat)
}

// GetLuaTestFlags returns the parsed Lua test flags.
func GetLuaTestFlags() LuaTestFlags {
	return luaTestFlags
}

// IsLuaTestMode returns true if Lua test mode is enabled.
func IsLuaTestMode() bool {
	return luaTestFlags.ScriptPath != ""
}

// IsConfigCheckMode returns true if config check mode is enabled.
func IsConfigCheckMode() bool {
	return configCheckMode
}

// IsConfigDumpDefaultsMode returns true if defaults dump mode is enabled.
func IsConfigDumpDefaultsMode() bool {
	return configDumpDefaultsMode
}

// IsConfigDumpNonDefaultsMode returns true if non-default dump mode is enabled.
func IsConfigDumpNonDefaultsMode() bool {
	return configDumpNonDefaultsMode
}

// IsConfigDumpPrintSensitiveMode returns true if sensitive dump values should be printed.
func IsConfigDumpPrintSensitiveMode() bool {
	return configDumpPrintSensitiveMode
}

// GetConfigDumpFormat returns the selected configuration dump format.
func GetConfigDumpFormat() config.DumpFormat {
	if configDumpFormat == "" {
		return config.DumpFormatCanonical
	}

	return configDumpFormat
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

	if _, err := SetupGoPlugins(file, log.GetLogger()); err != nil {
		return err
	}

	if err := compiler.CompileAndActivate(context.Background(), policyruntime.DefaultStore(), compiler.NewCompiler(), compiler.Input{
		Config:     file,
		Generation: 1,
	}); err != nil {
		return fmt.Errorf("unable to build policy snapshot: %w", err)
	}

	return nil
}

// SetupGoPlugins verifies native plugin artifacts and registers module descriptors.
func SetupGoPlugins(cfg config.File, logger *slog.Logger) (*pluginloader.State, error) {
	var plugins *config.PluginsSection
	if cfg != nil {
		plugins = cfg.GetPlugins()
	}

	verified, err := pluginloader.NewVerifier(pluginloader.WithVerificationLogger(logger)).Verify(plugins)
	if err != nil {
		return nil, fmt.Errorf("verify native plugin artifacts: %w", err)
	}

	state, err := pluginloader.NewLoader(pluginloader.WithLogger(logger)).Load(verified)
	if err != nil {
		return state, fmt.Errorf("load native plugin modules: %w", err)
	}

	if err := pluginloader.ValidateOrderedPluginBackends(cfg, state); err != nil {
		return state, fmt.Errorf("validate native plugin backend references: %w", err)
	}

	pluginloader.SetDefaultState(state)

	return state, nil
}

// SetupLuaScripts pre-compiles Lua scripts for environment sources, subject sources, init scripts, and hooks.
func SetupLuaScripts(cfg config.File, logger *slog.Logger) error {
	if err := PreCompileEnvironmentSources(cfg, logger); err != nil {
		return err
	}

	if err := PreCompileSubjectSources(cfg, logger); err != nil {
		return err
	}

	if err := PreCompileInit(cfg); err != nil {
		return err
	}

	return PreCompileHooks(cfg)
}

// PreCompileEnvironmentSources pre-compiles Lua environment sources if enabled.
func PreCompileEnvironmentSources(cfg config.File, logger *slog.Logger) error {
	if cfg.HaveLuaEnvironmentSources() {
		if err := environment.PreCompileLuaEnvironmentSources(cfg, logger); err != nil {
			return err
		}
	}

	return nil
}

// PreCompileSubjectSources pre-compiles Lua subject sources if enabled.
func PreCompileSubjectSources(cfg config.File, _ *slog.Logger) error {
	if cfg.HaveLuaSubjectSources() {
		if err := subject.PreCompileLuaSubjectSources(cfg); err != nil {
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

// PreCompileHooks refreshes the Lua hook registry from configuration.
func PreCompileHooks(cfg config.File) error {
	if err := hook.PreCompileLuaHooks(cfg); err != nil {
		return err
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

	debugIfNotNil(definitions.ControlRBL, file.GetRBLs())
	debugIfNotNil(definitions.ControlTLSEncryption, file.GetClearTextList())
	debugIfNotNil(definitions.ControlRelayDomains, file.GetRelayDomains())
	debugIfNotNil(definitions.ServiceBackendHealthChecks, file.GetBackendServerMonitoring())
	debugIfNotNil(definitions.LogKeyBruteForce, file.GetBruteForce())
	debugIfNotNil("idp", file.GetIDP())

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
	if err := RunLuaInitScripts(ctx, cfg, logger, redis); err != nil {
		_ = level.Error(logger).Log(definitions.LogKeyMsg, "Unable to run Lua init scripts", definitions.LogKeyError, err)
	}
}

// RunLuaInitScripts executes configured Lua init scripts with one atomic i18n catalog session.
func RunLuaInitScripts(ctx context.Context, cfg config.File, logger *slog.Logger, redis rediscli.Client) error {
	if !cfg.HaveLuaInit() {
		return nil
	}

	i18nRuntime := lualib.DefaultI18NRuntime().NewCatalogSession()
	for _, scriptPath := range cfg.GetLuaInitScriptPaths() {
		if err := hook.RunLuaInitWithI18NRuntime(ctx, cfg, logger, redis, scriptPath, i18nRuntime); err != nil {
			return err
		}
	}

	return i18nRuntime.CommitCatalogSession()
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
