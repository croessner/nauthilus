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
	"log/slog"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	errorspkg "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/monitoring"
	"github.com/croessner/nauthilus/server/stats"
)

type healthGate struct {
	failureThreshold  int
	recoveryThreshold int
	failures          int
	successes         int
	healthy           bool
}

func newHealthGate(failureThreshold int, recoveryThreshold int, initiallyHealthy bool) *healthGate {
	if failureThreshold < 1 {
		failureThreshold = 1
	}

	if recoveryThreshold < 1 {
		recoveryThreshold = 1
	}

	return &healthGate{
		failureThreshold:  failureThreshold,
		recoveryThreshold: recoveryThreshold,
		healthy:           initiallyHealthy,
	}
}

func (g *healthGate) Record(success bool) bool {
	if g == nil {
		return success
	}

	if success {
		g.failures = 0
		if g.healthy {
			g.successes = 0

			return true
		}

		g.successes++
		if g.successes >= g.recoveryThreshold {
			g.healthy = true
			g.successes = 0
		}

		return g.healthy
	}

	g.successes = 0
	if !g.healthy {
		g.failures = 0

		return false
	}

	g.failures++
	if g.failures >= g.failureThreshold {
		g.healthy = false
		g.failures = 0
	}

	return g.healthy
}

func (g *healthGate) Healthy() bool {
	if g == nil {
		return true
	}

	return g.healthy
}

type serverProbeState struct {
	connect *healthGate
	deep    *healthGate
}

func newServerProbeState(monitoringCfg *config.BackendServerMonitoring) *serverProbeState {
	return &serverProbeState{
		connect: newHealthGate(monitoringCfg.GetFailureThreshold(), monitoringCfg.GetRecoveryThreshold(), true),
		deep:    newHealthGate(monitoringCfg.GetFailureThreshold(), monitoringCfg.GetRecoveryThreshold(), true),
	}
}

func (s *serverProbeState) record(phase monitoring.BackendCheckPhase, success bool) bool {
	if phase == monitoring.BackendCheckPhaseConnect {
		return s.connect.Record(success)
	}

	if success {
		s.connect.Record(true)
	}

	return s.deep.Record(success)
}

func (s *serverProbeState) healthy(server *config.BackendServer) bool {
	if s == nil {
		return true
	}

	if server != nil && server.DeepCheck {
		return s.connect.Healthy() && s.deep.Healthy()
	}

	return s.connect.Healthy()
}

type backendProbe struct {
	server *config.BackendServer
	phase  monitoring.BackendCheckPhase
}

type healthCheckRunner struct {
	logger     *slog.Logger
	monitor    monitoring.Monitor
	oldServers *serversAlive
	states     map[*config.BackendServer]*serverProbeState
	servers    []*config.BackendServer
}

// serversAlive stores the backend servers currently considered healthy.
type serversAlive struct {
	servers []*config.BackendServer
}

// configForMonitoring retrieves and validates the backend servers configuration for monitoring.
// Returns a list of backend servers or an error if monitoring is disabled or no servers are configured.
func configForMonitoring(cfg config.File) ([]*config.BackendServer, error) {
	if !cfg.HasFeature(definitions.FeatureBackendServersMonitoring) {
		return nil, errorspkg.ErrFeatureBackendServersMonitoringDisabled
	}

	backendServers := cfg.GetBackendServers()
	if len(backendServers) == 0 {
		return nil, errorspkg.ErrMonitoringBackendServersEmpty
	}

	return backendServers, nil
}

// handleError processes the given error, logging messages based on its type and feature availability.
func handleError(cfg config.File, logger *slog.Logger, err error) {
	if !cfg.HasFeature(definitions.FeatureBackendServersMonitoring) {
		if stderrors.Is(err, errorspkg.ErrFeatureBackendServersMonitoringDisabled) {
			level.Info(logger).Log(definitions.LogKeyMsg, "Monitoring feature is not enabled")
		}

		return
	}

	if stderrors.Is(err, errorspkg.ErrMonitoringBackendServersEmpty) {
		level.Error(logger).Log(
			definitions.LogKeyMsg, "Monitoring backend servers are not configured",
			definitions.LogKeyError, err,
		)
	}
}

// logBackendServerError logs an error related to a backend server, including details like host, port, protocol, and the error.
func logBackendServerError(logger *slog.Logger, server *config.BackendServer, phase monitoring.BackendCheckPhase, err error, stillHealthy bool) {
	level.Error(logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Backend server failed: %s:%d (%s)",
			server.Host, server.Port, server.Protocol),
		definitions.LogKeyError, err,
		"health_check_phase", string(phase),
		"health_check_still_healthy", stillHealthy,
		definitions.LogKeyBackendServer, server,
	)
}

// logBackendServerDebug logs a debug message indicating that a backend server is operational, including its details.
func logBackendServerDebug(logger *slog.Logger, server *config.BackendServer, phase monitoring.BackendCheckPhase, healthy bool) {
	level.Info(logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Backend server alive: %s:%d (%s)",
			server.Host, server.Port, server.Protocol),
		"health_check_phase", string(phase),
		"health_check_healthy", healthy,
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

func newHealthCheckRunner(cfg config.File, logger *slog.Logger, servers []*config.BackendServer, oldServers *serversAlive) *healthCheckRunner {
	monitoringCfg := cfg.GetBackendServerMonitoring()
	runner := &healthCheckRunner{
		logger:     logger,
		monitor:    monitoring.NewMonitor(cfg, logger),
		oldServers: oldServers,
		states:     make(map[*config.BackendServer]*serverProbeState, len(servers)),
		servers:    servers,
	}

	for _, server := range servers {
		runner.states[server] = newServerProbeState(monitoringCfg)
	}

	return runner
}

func (r *healthCheckRunner) runConnect() {
	probes := make([]backendProbe, 0, len(r.servers))
	for _, server := range r.servers {
		probes = append(probes, backendProbe{server: server, phase: monitoring.BackendCheckPhaseConnect})
	}

	r.runProbes(probes)
}

func (r *healthCheckRunner) runDeep() {
	probes := make([]backendProbe, 0, len(r.servers))
	for _, server := range r.servers {
		if !server.DeepCheck {
			continue
		}

		probes = append(probes, backendProbe{server: server, phase: monitoring.BackendCheckPhaseDeep})
	}

	r.runProbes(probes)
}

func (r *healthCheckRunner) runCombined() {
	probes := make([]backendProbe, 0, len(r.servers))
	for _, server := range r.servers {
		phase := monitoring.BackendCheckPhaseConnect
		if server.DeepCheck {
			phase = monitoring.BackendCheckPhaseDeep
		}

		probes = append(probes, backendProbe{server: server, phase: phase})
	}

	r.runProbes(probes)
}

func (r *healthCheckRunner) runProbes(probes []backendProbe) {
	if len(probes) == 0 {
		return
	}

	var wg sync.WaitGroup

	wg.Add(len(probes))

	stats.GetMetrics().GetBackendServerStatus().WithLabelValues("wanted").Set(float64(len(r.servers)))

	for _, probe := range probes {
		go func(probe backendProbe) {
			err := r.monitor.CheckBackendConnectionPhase(probe.server, probe.phase)
			success := err == nil

			state := r.states[probe.server]
			healthy := state.record(probe.phase, success)

			if err != nil {
				logBackendServerError(r.logger, probe.server, probe.phase, err, healthy)
			} else {
				logBackendServerDebug(r.logger, probe.server, probe.phase, healthy)
			}

			wg.Done()
		}(probe)
	}

	wg.Wait()

	r.updateAliveServers()
}

func (r *healthCheckRunner) updateAliveServers() {
	serversLiveness := &serversAlive{}

	for _, server := range r.servers {
		if r.states[server].healthy(server) {
			serversLiveness.servers = append(serversLiveness.servers, server)
		}
	}

	stats.GetMetrics().GetBackendServerStatus().WithLabelValues("alive").Set(float64(len(serversLiveness.servers)))

	if !compareServers(serversLiveness.servers, r.oldServers.servers) {
		core.BackendServers.Update(serversLiveness.servers)
		r.oldServers.servers = serversLiveness.servers
	}
}

func connectAndDeepIntervals(cfg config.File, tickerInterval time.Duration) (time.Duration, time.Duration) {
	monitoringCfg := cfg.GetBackendServerMonitoring()
	connectInterval := monitoringCfg.GetConnectInterval(tickerInterval)
	deepInterval := monitoringCfg.GetDeepInterval(connectInterval)

	return connectInterval, deepInterval
}

// Run executes the backend server monitoring loop until ctx is canceled.
// On configuration errors the loop does not run (best-effort), but the process continues.
func Run(ctx context.Context, cfg config.File, logger *slog.Logger, ticker *time.Ticker) {
	RunWithTickerInterval(ctx, cfg, logger, ticker, 0)
}

// RunWithTickerInterval executes the backend server monitoring loop using tickerInterval as the connect-interval fallback.
func RunWithTickerInterval(ctx context.Context, cfg config.File, logger *slog.Logger, ticker *time.Ticker, tickerInterval time.Duration) {
	backendServers, err := configForMonitoring(cfg)
	if err != nil {
		handleError(cfg, logger, err)

		return
	}

	oldServers := &serversAlive{servers: backendServers}

	core.BackendServers.Update(backendServers)
	runner := newHealthCheckRunner(cfg, logger, backendServers, oldServers)
	connectInterval, deepInterval := connectAndDeepIntervals(cfg, tickerInterval)

	if ticker == nil {
		ticker = time.NewTicker(connectInterval)
		defer ticker.Stop()
	}

	if connectInterval == deepInterval {
		runner.runCombined()
	} else {
		runner.runConnect()
		runner.runDeep()
	}

	var deepTicker *time.Ticker
	if connectInterval != deepInterval {
		deepTicker = time.NewTicker(deepInterval)
		defer deepTicker.Stop()
	}

	for {
		select {
		case <-ticker.C:
			if connectInterval == deepInterval {
				runner.runCombined()
			} else {
				runner.runConnect()
			}
		case <-deepTickerChan(deepTicker):
			runner.runDeep()
		case <-ctx.Done():
			return
		}
	}
}

func deepTickerChan(ticker *time.Ticker) <-chan time.Time {
	if ticker == nil {
		return nil
	}

	return ticker.C
}
