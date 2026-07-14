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
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"os"

	"github.com/croessner/nauthilus/v3/server/app/bootfx"
	"github.com/croessner/nauthilus/v3/server/app/envfx"
	"github.com/croessner/nauthilus/v3/server/app/languagefx"
	"github.com/croessner/nauthilus/v3/server/app/localizationfx"
	"github.com/croessner/nauthilus/v3/server/app/logfx"
	"github.com/croessner/nauthilus/v3/server/app/loopsfx"
	"github.com/croessner/nauthilus/v3/server/app/opsfx"
	"github.com/croessner/nauthilus/v3/server/app/policyfx"
	"github.com/croessner/nauthilus/v3/server/app/reloadfx"
	"github.com/croessner/nauthilus/v3/server/app/restartfx"
	"github.com/croessner/nauthilus/v3/server/app/signalsfx"
	remotebackend "github.com/croessner/nauthilus/v3/server/backend/remote"
	"github.com/croessner/nauthilus/v3/server/config"
	_ "github.com/croessner/nauthilus/v3/server/core/auth"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/svcctx"
	"github.com/croessner/nauthilus/v3/server/testing/luatest"

	"github.com/spf13/viper"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

var (
	version   = "dev"
	buildTime = ""
)

type bootstrapped struct{}

// newBootstrapped returns a token that enforces ordering for fx providers
// that depend on configuration being loaded.
func newBootstrapped() *bootstrapped {
	return &bootstrapped{}
}

// rootContextOption provides the root context and cancellation function as interface types.
//
// This avoids the pitfall of fx.Supply(ctx) registering the concrete implementation type
// instead of the context.Context interface.
func rootContextOption(ctx context.Context, cancel context.CancelFunc) fx.Option {
	return fx.Provide(
		func() context.Context {
			return ctx
		},
		func() context.CancelFunc {
			return cancel
		},
	)
}

// main is the entry point of the application.
func main() {
	bootfx.ParseFlagsAndPrintVersion(version)

	if handleEarlyExitModes() {
		return
	}

	if err := bootfx.SetupConfiguration(); err != nil {
		stdlog.Fatalln("unable to load config file:", err)
	}

	ctx, cancel := svcctx.GetCtxWithCancel()
	fApp := newFxApplication(ctx, cancel)

	runFxApplication(ctx, fApp)
}

// handleEarlyExitModes handles command modes that finish before the fx runtime starts.
func handleEarlyExitModes() bool {
	// Check if we're in Lua test mode
	if bootfx.IsLuaTestMode() {
		runLuaTest()

		return true
	}

	if bootfx.IsConfigDumpDefaultsMode() {
		os.Exit(runConfigDumpDefaults(os.Stdout, os.Stderr))
	}

	if bootfx.IsConfigDumpNonDefaultsMode() {
		os.Exit(runConfigDumpNonDefaults(bootfx.SetupConfiguration, os.Stdout, os.Stderr))
	}

	if bootfx.IsConfigCheckMode() {
		os.Exit(runConfigCheck(bootfx.SetupConfiguration, os.Stderr))
	}

	return false
}

// newFxApplication builds the fx application with the production module graph.
func newFxApplication(ctx context.Context, cancel context.CancelFunc) *fx.App {
	return fx.New(
		fx.WithLogger(func(logger *slog.Logger) fxevent.Logger {
			if logger.Enabled(context.Background(), slog.LevelDebug) {
				return logfx.NewFxEventLogger(logger)
			}

			return fxevent.NopLogger
		}),
		rootContextOption(ctx, cancel),
		fx.Provide(newBootstrapped),
		fx.Provide(newConfigDeps),
		fx.Provide(newLogger),
		fx.Provide(newDbgModuleMapping),
		fx.Provide(newRedisDeps),
		fx.Provide(newAccountCache),
		fx.Provide(newBackendChannel),
		envfx.Module(),
		languagefx.Module(),
		localizationfx.Module(),
		loopsfx.Module(),
		opsfx.Module(),
		policyfx.Module(),
		reloadfx.Module(),
		restartfx.Module(),
		fx.Provide(newActionWorkers),
		fx.Provide(newContextStoreForRuntime),
		fx.Provide(newReloadOrchestrator),
		fx.Provide(newRestartOrchestrator),
		fx.Invoke(registerRuntimeLifecycle),
		fx.Invoke(registerRemoteBackendLifecycle),
		signalsfx.Module(),
	)
}

// runFxApplication starts the fx runtime and blocks until the root context ends.
func runFxApplication(ctx context.Context, fApp *fx.App) {
	if err := fApp.Start(context.Background()); err != nil {
		stdlog.Fatalln("Unable to start fx app. Error:", err)
	}

	<-ctx.Done()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), definitions.FxStopTimeout)
	defer stopCancel()

	if err := fApp.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop fx app. Error: %v", err)
	}
}

func registerRemoteBackendLifecycle(lc fx.Lifecycle) {
	lc.Append(fx.Hook{
		OnStop: func(context.Context) error {
			return remotebackend.CloseConnectionManagers()
		},
	})
}

func runConfigCheck(setupConfiguration func() error, stderr io.Writer) int {
	if setupConfiguration == nil {
		_, _ = fmt.Fprintln(stderr, "configuration check failed: setup function is nil")

		return 1
	}

	err := setupConfiguration()
	if err == nil {
		return 0
	}

	_, _ = fmt.Fprintf(stderr, "configuration check failed: %v\n", err)

	return 1
}

func runConfigDumpDefaults(stdout io.Writer, stderr io.Writer) int {
	if bootfx.IsConfigDumpNonDefaultsMode() {
		_, _ = fmt.Fprintln(stderr, "configuration dump failed: use either -d or -n, not both")

		return 1
	}

	dumpFormat := bootfx.GetConfigDumpFormat()

	output, err := config.RenderDefaultConfigDumpWithFormat(dumpFormat)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "configuration dump failed: %v\n", err)

		return 1
	}

	if output != "" {
		_, _ = fmt.Fprintln(stdout, output)
	}

	return 0
}

func runConfigDumpNonDefaults(setupConfiguration func() error, stdout io.Writer, stderr io.Writer) int {
	if bootfx.IsConfigDumpDefaultsMode() {
		_, _ = fmt.Fprintln(stderr, "configuration dump failed: use either -d or -n, not both")

		return 1
	}

	if setupConfiguration == nil {
		_, _ = fmt.Fprintln(stderr, "configuration dump failed: setup function is nil")

		return 1
	}

	if err := setupConfiguration(); err != nil {
		_, _ = fmt.Fprintf(stderr, "configuration dump failed: %v\n", err)

		return 1
	}

	dumpFormat := bootfx.GetConfigDumpFormat()

	output, err := config.RenderNonDefaultConfigDumpWithFormat(viper.AllSettings(), dumpFormat)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "configuration dump failed: %v\n", err)

		return 1
	}

	if output != "" {
		_, _ = fmt.Fprintln(stdout, output)
	}

	return 0
}

// runLuaTest executes the Lua script test and exits.
func runLuaTest() {
	flags := bootfx.GetLuaTestFlags()

	// Validate flags
	if flags.ScriptPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --test-lua flag requires a script path")
		os.Exit(1)
	}

	if flags.CallbackType == "" {
		fmt.Fprintln(os.Stderr, "Error: --test-callback flag is required (subject, environment, action, backend, hook, cache_flush)")
		os.Exit(1)
	}

	// Validate callback type
	validCallbacks := map[string]bool{
		"subject":     true,
		"environment": true,
		"action":      true,
		"backend":     true,
		"hook":        true,
		"cache_flush": true,
	}

	if !validCallbacks[flags.CallbackType] {
		fmt.Fprintf(os.Stderr, "Error: invalid callback type '%s'. Valid types: subject, environment, action, backend, hook, cache_flush\n", flags.CallbackType)
		os.Exit(1)
	}

	// Create test runner
	runner, err := luatest.NewTestRunner(flags.ScriptPath, flags.CallbackType, flags.MockDataPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating test runner: %v\n", err)
		os.Exit(1)
	}

	// Run the test
	result, err := runner.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running test: %v\n", err)
		os.Exit(1)
	}

	// Print results
	runner.PrintResult(result)

	// Exit with appropriate code
	os.Exit(runner.GetExitCode(result))
}
