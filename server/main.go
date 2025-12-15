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
	"log/slog"
	"time"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/app/logfx"
	"github.com/croessner/nauthilus/server/app/loopsfx"
	"github.com/croessner/nauthilus/server/app/redifx"
	"github.com/croessner/nauthilus/server/core"
	_ "github.com/croessner/nauthilus/server/core/auth"
	"github.com/croessner/nauthilus/server/monitoring"
	"github.com/croessner/nauthilus/server/svcctx"

	"go.uber.org/fx"
)

var (
	version   = "dev"
	buildTime = ""
)

type bootstrapped struct{}

func newBootstrapped() (*bootstrapped, error) {
	if err := setupConfiguration(); err != nil {
		return nil, err
	}

	return &bootstrapped{}, nil
}

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

// main is the entry point of the application. It initializes the environment, workers, monitoring, and starts the HTTP server.
func main() {
	parseFlagsAndPrintVersion()

	ctx, cancel := svcctx.GetCtxWithCancel()
	stopTimeout := 10 * time.Second

	fApp := fx.New(
		fx.NopLogger,
		rootContextOption(ctx, cancel),
		fx.Provide(newBootstrapped),
		fx.Provide(func(_ *bootstrapped) (struct {
			fx.Out
			Provider configfx.Provider
			Reloader configfx.Reloader
		}, error) {
			r, err := configfx.NewProvider()
			if err != nil {
				return struct {
					fx.Out
					Provider configfx.Provider
					Reloader configfx.Reloader
				}{}, err
			}

			return struct {
				fx.Out
				Provider configfx.Provider
				Reloader configfx.Reloader
			}{
				Provider: r,
				Reloader: r,
			}, nil
		}),
		fx.Provide(func(_ *bootstrapped) *slog.Logger {
			return logfx.NewLogger()
		}),
		fx.Provide(func(_ *bootstrapped) redifx.Client {
			return redifx.NewClient()
		}),
		loopsfx.Module(),
		fx.Invoke(func(
			lc fx.Lifecycle,
			ctx context.Context,
			cancel context.CancelFunc,
			_ *bootstrapped,
			cfgProvider configfx.Provider,
			logger *slog.Logger,
			redisClient redifx.Client,
			statsSvc *loopsfx.StatsService,
			monitoringSvc *loopsfx.BackendMonitoringService,
			connMgrSvc *loopsfx.ConnMgrService,
		) {
			lc.Append(fx.Hook{
				OnStart: func(context.Context) error {
					// Initialize OpenTelemetry tracing early (no-op if disabled)
					monitoring.GetTelemetry().Start(ctx, version)

					initializeInstanceInfo()
					debugLoadableConfig()

					if err := setupLuaScripts(); err != nil {
						stdlog.Fatalln("Unable to setup Lua scripts. Error:", err)
					}

					enableBlockProfile()
					store := newContextStore()
					store.cfgProvider = cfgProvider
					store.logger = logger
					store.redisClient = redisClient

					store.action = newContextTuple(ctx)

					actionWorkers := initializeActionWorkers()

					inititalizeBruteForceTolerate(ctx)
					initializeHTTPClients()
					core.InitPassDBResultPool()
					setupWorkers(ctx, store, actionWorkers)
					handleSignals(ctx, cancel, store, monitoringSvc, actionWorkers)
					setupRedis(ctx)

					runLuaInitScript(ctx)
					core.LoadStatsFromRedis(ctx)
					startHTTPServer(ctx, store)

					if err := connMgrSvc.Start(ctx); err != nil {
						return err
					}

					if err := monitoringSvc.Start(ctx); err != nil {
						return err
					}

					if err := statsSvc.Start(ctx); err != nil {
						return err
					}

					return nil
				},
				OnStop: func(stopCtx context.Context) error {
					if err := statsSvc.Stop(stopCtx); err != nil {
						stdlog.Printf("Unable to stop stats service. Error: %v", err)
					}

					if err := monitoringSvc.Stop(stopCtx); err != nil {
						stdlog.Printf("Unable to stop backend monitoring service. Error: %v", err)
					}

					if err := connMgrSvc.Stop(stopCtx); err != nil {
						stdlog.Printf("Unable to stop connection manager service. Error: %v", err)
					}

					cancel()
					monitoring.GetTelemetry().Shutdown(stopCtx)

					return nil
				},
			})
		}),
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
