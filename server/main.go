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

	"github.com/croessner/nauthilus/server/app/bootfx"
	"github.com/croessner/nauthilus/server/app/envfx"
	"github.com/croessner/nauthilus/server/app/languagefx"
	"github.com/croessner/nauthilus/server/app/logfx"
	"github.com/croessner/nauthilus/server/app/loopsfx"
	"github.com/croessner/nauthilus/server/app/opsfx"
	"github.com/croessner/nauthilus/server/app/reloadfx"
	"github.com/croessner/nauthilus/server/app/restartfx"
	"github.com/croessner/nauthilus/server/app/signalsfx"
	_ "github.com/croessner/nauthilus/server/core/auth"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/svcctx"
	"github.com/croessner/nauthilus/server/testing/luatest"

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

	// Check if we're in Lua test mode
	if bootfx.IsLuaTestMode() {
		runLuaTest()

		return
	}

	if bootfx.IsConfigCheckMode() {
		os.Exit(runConfigCheck(bootfx.SetupConfiguration, os.Stderr))
	}

	if err := bootfx.SetupConfiguration(); err != nil {
		stdlog.Fatalln("unable to load config file:", err)
	}

	ctx, cancel := svcctx.GetCtxWithCancel()
	stopTimeout := definitions.FxStopTimeout

	fApp := fx.New(
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
		loopsfx.Module(),
		opsfx.Module(),
		reloadfx.Module(),
		restartfx.Module(),
		fx.Provide(newActionWorkers),
		fx.Provide(newContextStoreForRuntime),
		fx.Provide(newReloadOrchestrator),
		fx.Provide(newRestartOrchestrator),
		fx.Invoke(registerRuntimeLifecycle),
		signalsfx.Module(),
	)

	if err := fApp.Start(context.Background()); err != nil {
		stdlog.Fatalln("Unable to start fx app. Error:", err)
	}

	<-ctx.Done()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), stopTimeout)
	defer stopCancel()

	if err := fApp.Stop(stopCtx); err != nil {
		stdlog.Printf("Unable to stop fx app. Error: %v", err)
	}
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

// runLuaTest executes the Lua script test and exits.
func runLuaTest() {
	flags := bootfx.GetLuaTestFlags()

	// Validate flags
	if flags.ScriptPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --test-lua flag requires a script path")
		os.Exit(1)
	}

	if flags.CallbackType == "" {
		fmt.Fprintln(os.Stderr, "Error: --test-callback flag is required (filter, feature, action, backend, hook, cache_flush)")
		os.Exit(1)
	}

	// Validate callback type
	validCallbacks := map[string]bool{
		"filter":      true,
		"feature":     true,
		"action":      true,
		"backend":     true,
		"hook":        true,
		"cache_flush": true,
	}

	if !validCallbacks[flags.CallbackType] {
		fmt.Fprintf(os.Stderr, "Error: invalid callback type '%s'. Valid types: filter, feature, action, backend, hook, cache_flush\n", flags.CallbackType)
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
