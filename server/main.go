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
	stdlog "log"

	"github.com/croessner/nauthilus/server/app/loopsfx"
	"github.com/croessner/nauthilus/server/app/opsfx"
	"github.com/croessner/nauthilus/server/app/reloadfx"
	"github.com/croessner/nauthilus/server/app/restartfx"
	"github.com/croessner/nauthilus/server/app/signalsfx"
	_ "github.com/croessner/nauthilus/server/core/auth"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/svcctx"

	"go.uber.org/fx"
)

var (
	version   = "dev"
	buildTime = ""
)

type bootstrapped struct{}

// newBootstrapped runs the legacy configuration bootstrap and returns a token
// that enforces ordering for fx providers that depend on configuration being loaded.
func newBootstrapped() (*bootstrapped, error) {
	if err := setupConfiguration(); err != nil {
		return nil, err
	}

	return &bootstrapped{}, nil
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
	parseFlagsAndPrintVersion()

	ctx, cancel := svcctx.GetCtxWithCancel()
	stopTimeout := definitions.FxStopTimeout

	fApp := fx.New(
		fx.NopLogger,
		rootContextOption(ctx, cancel),
		fx.Provide(newBootstrapped),
		fx.Provide(newConfigDeps),
		fx.Provide(newLogger),
		fx.Provide(newRedisClient),
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
