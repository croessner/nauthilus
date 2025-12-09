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
	stdlog "log"
	"os"
	"time"

	"github.com/croessner/nauthilus/server/core"
	_ "github.com/croessner/nauthilus/server/core/auth"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/monitoring"
	"github.com/croessner/nauthilus/server/svcctx"
)

var (
	version   = "dev"
	buildTime = ""
)

// main is the entry point of the application. It initializes the environment, workers, monitoring, and starts the HTTP server.
func main() {
	parseFlagsAndPrintVersion()

	ctx, cancel := svcctx.GetCtxWithCancel()

	if err := setupConfiguration(); err != nil {
		stdlog.Fatalln("Unable to setup the environment. Error:", err)
	}

	// Initialize OpenTelemetry tracing early (no-op if disabled)
	monitoring.GetTelemetry().Start(ctx, version)
	defer monitoring.GetTelemetry().Shutdown(ctx)

	initializeInstanceInfo()
	debugLoadableConfig()

	if err := setupLuaScripts(); err != nil {
		stdlog.Fatalln("Unable to setup Lua scripts. Error:", err)
	}

	enableBlockProfile()

	statsTicker := time.NewTicker(definitions.StatsDelay * time.Second)
	monitoringTicker := time.NewTicker(definitions.BackendServerMonitoringDelay * time.Second)
	store := newContextStore()

	store.action = newContextTuple(ctx)

	actionWorkers := initializeActionWorkers()

	inititalizeBruteForceTolerate(ctx)
	initializeHTTPClients()
	core.InitPassDBResultPool()
	setupWorkers(ctx, store, actionWorkers)
	handleSignals(ctx, cancel, store, statsTicker, &monitoringTicker, actionWorkers)
	setupRedis(ctx)

	runLuaInitScript(ctx)
	core.LoadStatsFromRedis(ctx)
	startHTTPServer(ctx, store)
	runConnectionManager(ctx)

	// Backend server monitoring feature
	go runBackendServerMonitoring(ctx, store, monitoringTicker)

	startStatsLoop(ctx, statsTicker)

	os.Exit(0)
}
