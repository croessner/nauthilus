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

package loopsfx

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
)

// mockCfgProvider implements configfx.Provider for testing.
type mockCfgProvider struct {
	snap configfx.Snapshot
}

func (m *mockCfgProvider) Current() configfx.Snapshot {
	return m.snap
}

func TestStatsServiceStartStop(t *testing.T) {
	svc := NewStatsService(
		10*time.Millisecond,
		func(context.Context) {},
		func(context.Context) {},
	)

	ctx := t.Context()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestBackendMonitoringServiceStartStopWhenDisabled(t *testing.T) {
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})
	snap := configfx.Snapshot{File: config.GetFile()}

	svc := NewBackendMonitoringService(10*time.Millisecond, &mockCfgProvider{snap: snap}, slog.Default())

	ctx := t.Context()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if svc.running {
		t.Fatalf("service should not be running when %q is disabled", definitions.FeatureBackendServersMonitoring)
	}

	if svc.ticker != nil {
		t.Fatalf("ticker should be nil when %q is disabled", definitions.FeatureBackendServersMonitoring)
	}

	if err := svc.Stop(context.Background()); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestBackendMonitoringServiceRestartStopsWhenDisabled(t *testing.T) {
	f := &config.Feature{}
	_ = f.Set(definitions.FeatureBackendServersMonitoring)

	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{Features: []*config.Feature{f}}})
	snap := configfx.Snapshot{File: config.GetFile()}

	svc := NewBackendMonitoringService(10*time.Millisecond, &mockCfgProvider{snap: snap}, slog.Default())

	ctx := t.Context()

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !svc.running {
		t.Fatalf("service should be running when %q is enabled", definitions.FeatureBackendServersMonitoring)
	}

	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})
	svc.cfgProvider = &mockCfgProvider{snap: configfx.Snapshot{File: config.GetFile()}}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer stopCancel()

	if err := svc.Restart(stopCtx); err != nil {
		t.Fatalf("Restart failed: %v", err)
	}

	if svc.running {
		t.Fatalf("service should not be running after disabling %q", definitions.FeatureBackendServersMonitoring)
	}

	if svc.ticker != nil {
		t.Fatalf("ticker should be nil after disabling %q", definitions.FeatureBackendServersMonitoring)
	}
}
