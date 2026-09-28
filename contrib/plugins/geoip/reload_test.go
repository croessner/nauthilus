// Copyright (C) 2026 Christian Roessner
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
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// blockedRefreshLoader serves the initial database once and then blocks the next load of it,
// which is the periodic refresh, until release is closed.
type blockedRefreshLoader struct {
	stale           *lifecycleTestDatabase
	loading         chan struct{}
	release         chan struct{}
	initialPath     string
	replacementPath string
	initialLoads    atomic.Int32
}

// load implements databaseLoader for the refresh race.
func (l *blockedRefreshLoader) load(_ context.Context, config moduleConfig) (geoDatabase, error) {
	switch config.DatabasePath {
	case l.initialPath:
		if l.initialLoads.Add(1) == 1 {
			return newLifecycleTestDatabase(testCountryDE, false), nil
		}

		close(l.loading)
		<-l.release

		return l.stale, nil
	case l.replacementPath:
		return newLifecycleTestDatabase(testReloadedCountry, false), nil
	default:
		return nil, fmt.Errorf("unexpected database path %q", config.DatabasePath)
	}
}

// TestRefreshInFlightDoesNotRevertReconfigure reproduces a periodic refresh that loaded the
// previous database path and published it after Reconfigure had switched to a new path.
func TestRefreshInFlightDoesNotRevertReconfigure(t *testing.T) {
	loader := &blockedRefreshLoader{
		stale: newLifecycleTestDatabase(testCountryDE, false), loading: make(chan struct{}), release: make(chan struct{}),
		initialPath: testDatabasePath(t, "geoip.json"), replacementPath: testDatabasePath(t, "geoip-reload.json"),
	}
	plugin := NewPlugin()
	plugin.databaseLoad = loader.load

	module := testModule(loader.initialPath)
	registry, _ := registerTestPluginInstance(t, plugin, module)

	runner := newRunnerForPlugin(registry, plugin, module, newRecordingMetrics(), &recordingTracer{})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	defer stopRunner(t, runner)

	refreshDone := make(chan struct{})

	go func() {
		defer close(refreshDone)

		plugin.refreshOnce(context.Background())
	}()

	<-loader.loading

	if err := runner.Reconfigure(context.Background(), testConfigFile(testModule(loader.replacementPath))); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}

	close(loader.release)
	<-refreshDone

	if config, _ := plugin.currentConfig(); config.DatabasePath != loader.replacementPath {
		t.Fatalf("database path after refresh = %q, want the reconfigured path", config.DatabasePath)
	}

	assertFact(t, lookupGeoIP(t, plugin, testClientIP).Facts, factCountryISO, testReloadedCountry)

	select {
	case <-loader.stale.closed:
	default:
		t.Fatal("the discarded refresh result was not closed")
	}
}

func TestValidateReconfigureClassifiesCandidates(t *testing.T) {
	module := testModule(testDatabasePath(t, "geoip.json"))
	runner, plugin, _, _ := startedTestRunnerWithPlugin(t, module)

	defer stopRunner(t, runner)

	changedBindings := testModule(testDatabasePath(t, "geoip.json"))
	changedBindings.Config["decision_bindings"].([]any)[0].(map[string]any)["input"] = map[string]any{
		"fact": "resource.other_ip", "category": "resource",
	}

	invalid := testModule(testDatabasePath(t, "geoip.json"))
	invalid.Config["refresh_interval"] = "later"

	tests := []struct {
		config       map[string]any
		name         string
		wantErr      bool
		restartBound bool
	}{
		{name: "valid", config: testModule(testDatabasePath(t, "geoip-reload.json")).Config},
		{name: "invalid", config: invalid.Config, wantErr: true},
		{name: "decision bindings", config: changedBindings.Config, wantErr: true, restartBound: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := plugin.ValidateReconfigure(context.Background(), pluginregistry.NewConfigView(test.config))
			if (err != nil) != test.wantErr || errors.Is(err, pluginapi.ErrRestartRequired) != test.restartBound {
				t.Fatalf("ValidateReconfigure() error = %v, want error %v restart-bound %v", err, test.wantErr, test.restartBound)
			}
		})
	}

	if config, _ := plugin.currentConfig(); config.DatabasePath != module.Config["database_path"] {
		t.Fatal("ValidateReconfigure changed the running configuration")
	}
}

// TestRefreshInFlightDoesNotPublishAfterStop reproduces a periodic refresh that published
// databases after Stop had already retired the plugin state.
func TestRefreshInFlightDoesNotPublishAfterStop(t *testing.T) {
	loader := &blockedRefreshLoader{
		stale: newLifecycleTestDatabase(testCountryDE, false), loading: make(chan struct{}), release: make(chan struct{}),
		initialPath: testDatabasePath(t, "geoip.json"), replacementPath: testDatabasePath(t, "geoip-reload.json"),
	}
	plugin := NewPlugin()
	plugin.databaseLoad = loader.load

	module := testModule(loader.initialPath)
	registry, _ := registerTestPluginInstance(t, plugin, module)

	runner := newRunnerForPlugin(registry, plugin, module, newRecordingMetrics(), &recordingTracer{})
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	refreshDone := make(chan struct{})

	go func() {
		defer close(refreshDone)

		plugin.refreshOnce(context.Background())
	}()

	<-loader.loading
	stopRunner(t, runner)
	close(loader.release)
	<-refreshDone

	if _, ready := plugin.currentConfig(); ready {
		t.Fatal("a refresh published databases after Stop")
	}

	select {
	case <-loader.stale.closed:
	default:
		t.Fatal("the refresh result loaded across Stop was not closed")
	}
}
