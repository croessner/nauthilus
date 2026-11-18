// Copyright (C) 2026 Christian Rößner
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
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/lokisource"
	"github.com/croessner/nauthilus/v4/server/supportops/prometheussource"
	"github.com/croessner/nauthilus/v4/server/supportops/windowsource"
)

// historicalSettings returns a valid historical source configuration.
func historicalSettings(url string) *config.HistoricalDiagnosticsSource {
	return &config.HistoricalDiagnosticsSource{Enabled: true, URL: url, Tenant: "tenant-a", InstanceLabel: "pod",
		Selector: map[string]string{"job": "nauthilus"}, Timeout: 2 * time.Second}
}

// TestHistoricalConnectionMapsTheConfiguredBoundary pins that every fixed value of the configuration reaches the
// connection and that the defaults of the bounds apply.
func TestHistoricalConnectionMapsTheConfiguredBoundary(t *testing.T) {
	settings := historicalSettings("http://prometheus.example.org:9090/base")

	connection, err := historicalConnection(nil, settings)
	if err != nil {
		t.Fatalf("historicalConnection() = %v", err)
	}

	if connection.BaseURL.String() != settings.URL || connection.Tenant != "tenant-a" || connection.InstanceLabel != "pod" ||
		connection.Selector["job"] != "nauthilus" || connection.Timeout != 2*time.Second ||
		connection.MaxTimeWindow != settings.GetMaxTimeWindow() || connection.MaxSeries != settings.GetMaxSeries() ||
		connection.MaxResponseBytes != settings.GetMaxResponseBytes() {
		t.Fatalf("connection = %+v", connection)
	}

	if connection.HTTPClient == nil {
		t.Fatal("the connection needs its own HTTP client")
	}
}

// TestAppendHistoricalSourceBuildsOrOmits pins that a source builds from its configuration, and that a source that
// cannot be built is left out without failing the others.
func TestAppendHistoricalSourceBuildsOrOmits(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	kept := []supportops.Source{nil}

	for name, build := range map[string]func(windowsource.Connection) (supportops.Source, error){
		"loki": func(connection windowsource.Connection) (supportops.Source, error) { return lokisource.New(connection) },
		"prometheus": func(connection windowsource.Connection) (supportops.Source, error) {
			return prometheussource.New(connection)
		},
	} {
		t.Run(name, func(t *testing.T) {
			sources := appendHistoricalSource(kept, logger, name, nil, historicalSettings("http://source.example.org"), build)
			if len(sources) != 2 || sources[1] == nil {
				t.Fatalf("sources = %v, want the new source appended", sources)
			}

			if got := sources[1].Name(); got != name {
				t.Fatalf("source name = %q, want %q", got, name)
			}

			omitted := appendHistoricalSource(kept, logger, name, nil, historicalSettings("http://[::1"), build)
			if len(omitted) != 1 {
				t.Fatalf("an unparsable URL must leave the source out: %v", omitted)
			}

			failed := appendHistoricalSource(kept, logger, name, nil, historicalSettings("http://source.example.org"),
				func(windowsource.Connection) (supportops.Source, error) { return nil, errors.New("boom") })
			if len(failed) != 1 {
				t.Fatalf("a failing builder must leave the source out: %v", failed)
			}
		})
	}
}
