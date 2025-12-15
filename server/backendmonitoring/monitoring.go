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

package backendmonitoring

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	errorspkg "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/monitoring"
	"github.com/croessner/nauthilus/server/stats"
)

// serversAlive represents a concurrency-safe collection of backend servers that are currently operational.
type serversAlive struct {
	mu      sync.Mutex
	servers []*config.BackendServer
}

// configForMonitoring retrieves and validates the backend servers configuration for monitoring.
// Returns a list of backend servers or an error if monitoring is disabled or no servers are configured.
func configForMonitoring() ([]*config.BackendServer, error) {
	if !config.GetFile().HasFeature(definitions.FeatureBackendServersMonitoring) {
		return nil, errorspkg.ErrFeatureBackendServersMonitoringDisabled
	}

	backendServers := config.GetFile().GetBackendServers()
	if len(backendServers) == 0 {
		return nil, errorspkg.ErrMonitoringBackendServersEmpty
	}

	return backendServers, nil
}

// handleError processes the given error, logging messages based on its type and feature availability.
func handleError(err error) {
	if !config.GetFile().HasFeature(definitions.FeatureBackendServersMonitoring) {
		if stderrors.Is(err, errorspkg.ErrFeatureBackendServersMonitoringDisabled) {
			level.Info(log.Logger).Log(definitions.LogKeyMsg, "Monitoring feature is not enabled")
		}

		return
	}

	if stderrors.Is(err, errorspkg.ErrMonitoringBackendServersEmpty) {
		level.Error(log.Logger).Log(
			definitions.LogKeyMsg, "Monitoring backend servers are not configured",
			definitions.LogKeyError, err,
		)
	}
}

// logBackendServerError logs an error related to a backend server, including details like host, port, protocol, and the error.
func logBackendServerError(server *config.BackendServer, err error) {
	level.Error(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Backend server failed: %s:%d (%s)",
			server.Host, server.Port, server.Protocol),
		definitions.LogKeyError, err,
		definitions.LogKeyBackendServer, server,
	)
}

// logBackendServerDebug logs a debug message indicating that a backend server is operational, including its details.
func logBackendServerDebug(server *config.BackendServer) {
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Backend server alive: %s:%d (%s)",
			server.Host, server.Port, server.Protocol),
		definitions.LogKeyBackendServer, server,
	)
}

// compareServers compares two slices of BackendServer pointers to determine if they contain the same elements in any order.
func compareServers(servers []*config.BackendServer, servers2 []*config.BackendServer) bool {
	if len(servers) != len(servers2) {
		return false
	}

	foundServer := 0
	for _, server := range servers {
		for _, server2 := range servers2 {
			if server == server2 {
				foundServer++
				continue
			}
		}
	}

	return len(servers) == foundServer
}

// healthCheckLoop performs periodic health checks on backend servers and updates the list of active servers atomically.
func healthCheckLoop(servers []*config.BackendServer, oldServers *serversAlive) *serversAlive {
	var wg sync.WaitGroup

	wg.Add(len(servers))

	serversLiveness := &serversAlive{}

	stats.GetMetrics().GetBackendServerStatus().WithLabelValues("wanted").Set(float64(len(servers)))

	for _, server := range servers {
		go func(server *config.BackendServer) {
			err := monitoring.NewMonitor().CheckBackendConnection(server)

			serversLiveness.mu.Lock()
			defer serversLiveness.mu.Unlock()

			if err != nil {
				logBackendServerError(server, err)
			} else {
				serversLiveness.servers = append(serversLiveness.servers, server)
				logBackendServerDebug(server)
			}

			wg.Done()
		}(server)
	}

	wg.Wait()

	stats.GetMetrics().GetBackendServerStatus().WithLabelValues("alive").Set(float64(len(serversLiveness.servers)))

	if !compareServers(serversLiveness.servers, oldServers.servers) {
		core.BackendServers.Update(serversLiveness.servers)
		oldServers.servers = serversLiveness.servers
	}

	return oldServers
}

// Run executes the backend server monitoring loop until ctx is canceled.
// On configuration errors the loop does not run (best-effort), but the process continues.
func Run(ctx context.Context, ticker *time.Ticker) {
	backendServers, err := configForMonitoring()
	if err != nil {
		handleError(err)

		return
	}

	oldServers := &serversAlive{servers: backendServers}

	core.BackendServers.Update(backendServers)
	oldServers = healthCheckLoop(backendServers, oldServers)

	for {
		select {
		case <-ticker.C:
			oldServers = healthCheckLoop(backendServers, oldServers)
		case <-ctx.Done():
			return
		}
	}
}
