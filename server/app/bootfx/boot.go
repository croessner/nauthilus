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
	"flag"
	"fmt"
	stdlog "log"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/croessner/nauthilus/v4/internal/flagutil"
	"github.com/croessner/nauthilus/v4/server/backend"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/lualib/cacheflush"
	"github.com/croessner/nauthilus/v4/server/lualib/hook"
	"github.com/croessner/nauthilus/v4/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/croessner/nauthilus/v4/server/util/keygen"

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

// PrepareConfiguration initializes process configuration and returns one unpublished candidate.
func PrepareConfiguration() (config.File, error) {
	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())

	config.NewEnvironmentConfig()

	setTimeZone()

	if config.ConfigFilePath != "" {
		if _, err := os.Stat(config.ConfigFilePath); os.IsNotExist(err) {
			return nil, fmt.Errorf("specified configuration file does not exist: %s", config.ConfigFilePath)
		}
	}

	file, err := config.PrepareFile()
	if err != nil {
		return nil, fmt.Errorf("unable to load config file: %w", err)
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

	return file, nil
}

// SetupConfiguration validates and returns the unpublished configuration for command-only modes.
func SetupConfiguration() (config.File, error) {
	return PrepareConfiguration()
}

// SetupGoPlugins verifies native plugin artifacts and registers module descriptors.
func SetupGoPlugins(cfg config.File, logger *slog.Logger) (*pluginloader.State, error) {
	var plugins *config.PluginsSection
	if cfg != nil {
		plugins = cfg.GetPlugins()
	}

	verifierOptions := []pluginloader.VerifierOption{pluginloader.WithVerificationLogger(logger)}
	loaderOptions := []pluginloader.Option{pluginloader.WithLogger(logger)}

	if plugins != nil && len(plugins.Modules) > 0 {
		artifacts, err := config.ArtifactSnapshotFor(cfg)
		if err != nil {
			return nil, fmt.Errorf("load native plugin artifact snapshot: %w", err)
		}

		verifierOptions = append(verifierOptions, pluginloader.WithArtifactReader(artifacts.ReadFile))
		loaderOptions = append(loaderOptions, pluginloader.WithLoaderArtifactReader(artifacts.ReadFile))
	}

	verified, err := pluginloader.NewVerifier(verifierOptions...).Verify(plugins)
	if err != nil {
		return nil, fmt.Errorf("verify native plugin artifacts: %w", err)
	}

	state, err := pluginloader.NewLoader(loaderOptions...).Load(verified)
	if err != nil {
		return state, fmt.Errorf("load native plugin modules: %w", err)
	}

	if err := pluginloader.ValidateOrderedPluginBackends(cfg, state); err != nil {
		return state, fmt.Errorf("validate native plugin backend references: %w", err)
	}

	if err := pluginloader.ValidatePluginDebugSelectors(cfg, state); err != nil {
		return state, fmt.Errorf("validate native plugin debug selectors: %w", err)
	}

	return state, nil
}

// SetupLuaScripts pre-compiles every restart-bound Lua program before workers start.
func SetupLuaScripts(cfg config.File, _ *slog.Logger) error {
	modules, err := luaseal.CaptureConfigured(cfg)
	if err != nil {
		return err
	}

	if err = backend.PrepareLuaBackendScriptsWithModules(cfg, modules); err != nil {
		return err
	}

	if err = cacheflush.PrepareConfiguredScriptWithModules(cfg, modules); err != nil {
		return err
	}

	return PreCompileHooks(cfg, modules)
}

// PreCompileHooks refreshes the Lua hook registry from configuration.
func PreCompileHooks(cfg config.File, modules *luaseal.Modules) error {
	if err := hook.PreCompileLuaHooksWithModules(cfg, modules); err != nil {
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
