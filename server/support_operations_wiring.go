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
	"log/slog"
	"net/http"
	"net/url"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/lokisource"
	"github.com/croessner/nauthilus/v4/server/supportops/prometheussource"
	"github.com/croessner/nauthilus/v4/server/supportops/runtimesource"
	"github.com/croessner/nauthilus/v4/server/supportops/windowsource"
	"github.com/prometheus/client_golang/prometheus"
)

// operationsConfigProvider is the narrow config surface of the operations diagnostics wiring.
type operationsConfigProvider interface {
	GetOperationsDiagnostics() *config.OperationsDiagnosticsSection
}

// newSupportOperationsService builds the process-owned diagnostics service from the startup configuration. It returns
// nil when the service is disabled; the routes and tools then answer OPERATIONS_NOT_CONFIGURED. A historical source
// (Loki or Prometheus) that cannot be built is logged and left out, so the runtime part keeps working and that source
// reports not_configured.
func newSupportOperationsService(cfg config.File, logger *slog.Logger) *supportops.Service {
	provider, ok := cfg.(operationsConfigProvider)
	if !ok {
		return nil
	}

	section := provider.GetOperationsDiagnostics()
	if !section.Enabled {
		return nil
	}

	var sources []supportops.Source

	if section.Sources.NauthilusRuntime.IsEnabled() {
		sources = append(sources, runtimesource.New(prometheus.DefaultGatherer, runtimesource.CoreCounterFamilies...))
	}

	if section.Sources.Loki.Enabled {
		sources = appendHistoricalSource(sources, logger, "Loki", cfg, &section.Sources.Loki, func(connection windowsource.Connection) (supportops.Source, error) {
			return lokisource.New(connection)
		})
	}

	if section.Sources.Prometheus.Enabled {
		sources = appendHistoricalSource(sources, logger, "Prometheus", cfg, &section.Sources.Prometheus, func(connection windowsource.Connection) (supportops.Source, error) {
			return prometheussource.New(connection)
		})
	}

	service, err := supportops.NewService(supportops.Options{Sources: sources, Instance: cfg.GetServer().GetInstanceName(),
		Deployment: operationsDeployment(cfg), Audit: supportaccess.LogAuditRecorder{Logger: logger}})
	if err != nil {
		_ = level.Error(logger).Log(definitions.LogKeyMsg, "Operations diagnostics disabled", definitions.LogKeyError, err)

		return nil
	}

	return service
}

// appendHistoricalSource builds one historical source from its configuration and appends it; a source that cannot
// be built is logged and left out.
func appendHistoricalSource(sources []supportops.Source, logger *slog.Logger, name string, cfg config.File,
	settings *config.HistoricalDiagnosticsSource, build func(windowsource.Connection) (supportops.Source, error)) []supportops.Source {
	connection, err := historicalConnection(cfg, settings)
	if err == nil {
		var source supportops.Source

		if source, err = build(connection); err == nil {
			return append(sources, source)
		}
	}

	_ = level.Error(logger).Log(definitions.LogKeyMsg, name+" diagnostics source disabled", definitions.LogKeyError, err)

	return sources
}

// historicalConnection maps the configuration of a historical source to its fixed connection boundary. The HTTP
// client uses no proxy and the TLS settings from the sealed config artifacts.
func historicalConnection(cfg config.File, settings *config.HistoricalDiagnosticsSource) (windowsource.Connection, error) {
	base, err := url.Parse(settings.URL)
	if err != nil {
		return windowsource.Connection{}, err
	}

	tlsConfig, err := config.BuildClientTLSConfig(cfg, &settings.TLS)
	if err != nil {
		return windowsource.Connection{}, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = tlsConfig

	return windowsource.Connection{BaseURL: base, HTTPClient: &http.Client{Transport: transport},
		Selector: settings.Selector, Tenant: settings.Tenant, InstanceLabel: settings.InstanceLabel,
		Username: settings.BasicAuth.Username, Password: settings.BasicAuth.Password, BearerToken: settings.BearerToken,
		Timeout: settings.GetTimeout(), MaxTimeWindow: settings.GetMaxTimeWindow(), MaxSeries: settings.GetMaxSeries(),
		MaxResponseBytes: settings.GetMaxResponseBytes()}, nil
}

// operationsDeployment names the deployment of the diagnostics scope: the history deployment when one is set.
func operationsDeployment(cfg config.File) string {
	if provider, ok := cfg.(historyConfigProvider); ok {
		return provider.GetHistory().GetClickHouse().GetDeployment()
	}

	return ""
}
