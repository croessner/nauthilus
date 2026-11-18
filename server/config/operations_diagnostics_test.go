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

package config

import (
	"slices"
	"strings"
	"testing"
)

// historicalSourceFixture returns an enabled, valid historical source below host.
func historicalSourceFixture(host string) HistoricalDiagnosticsSource {
	return HistoricalDiagnosticsSource{Enabled: true, URL: "https://" + host, Selector: map[string]string{"job": "nauthilus"},
		InstanceLabel: "instance"}
}

// diagnosticsSettings builds file settings with the given operations section.
func diagnosticsSettings(section OperationsDiagnosticsSection) *FileSettings {
	return &FileSettings{Observability: &ObservabilitySection{Diagnostics: DiagnosticsSection{Operations: section}}}
}

// TestValidateOperationsDiagnosticsHistoricalSources pins the load-time rules that apply to every historical source:
// each enabled source needs the enabled service and a valid boundary, and the service needs at least one source.
func TestValidateOperationsDiagnosticsHistoricalSources(t *testing.T) {
	disabledRuntime := RuntimeDiagnosticsSource{Enabled: new(false)}
	badURL := historicalSourceFixture("example.org")
	badURL.URL = "https://example.org?x=1"

	for name, tc := range map[string]struct {
		section OperationsDiagnosticsSection
		want    string
	}{
		"prometheus alone": {OperationsDiagnosticsSection{Enabled: true, Sources: OperationsDiagnosticsSources{
			NauthilusRuntime: disabledRuntime, Prometheus: historicalSourceFixture("prometheus.example.org")}}, ""},
		"both historical sources": {OperationsDiagnosticsSection{Enabled: true, Sources: OperationsDiagnosticsSources{
			Loki: historicalSourceFixture("loki.example.org"), Prometheus: historicalSourceFixture("prometheus.example.org")}}, ""},
		"no source at all": {OperationsDiagnosticsSection{Enabled: true, Sources: OperationsDiagnosticsSources{
			NauthilusRuntime: disabledRuntime}}, "at least one source"},
		"prometheus without service": {OperationsDiagnosticsSection{Sources: OperationsDiagnosticsSources{
			Prometheus: historicalSourceFixture("prometheus.example.org")}}, "when the prometheus source is enabled"},
		"loki without service": {OperationsDiagnosticsSection{Sources: OperationsDiagnosticsSources{
			Loki: historicalSourceFixture("loki.example.org")}}, "when the loki source is enabled"},
		"invalid prometheus url": {OperationsDiagnosticsSection{Enabled: true, Sources: OperationsDiagnosticsSources{
			Prometheus: badURL}}, "sources.prometheus.url"},
	} {
		t.Run(name, func(t *testing.T) {
			err := diagnosticsSettings(tc.section).validateOperationsDiagnostics()

			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("validate = %v, want no error", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("validate = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

// TestArtifactOperationsDiagnosticsPathsCoverEveryEnabledSource pins that the TLS trust and identity files of every
// enabled historical source are sealed with the other config artifacts.
func TestArtifactOperationsDiagnosticsPathsCoverEveryEnabledSource(t *testing.T) {
	loki := historicalSourceFixture("loki.example.org")
	loki.TLS = HTTPClientTLS{CAFile: "/etc/loki-ca.pem"}

	prometheus := historicalSourceFixture("prometheus.example.org")
	prometheus.TLS = HTTPClientTLS{CAFile: "/etc/prometheus-ca.pem", Cert: "/etc/prometheus.pem", Key: "/etc/prometheus.key"}

	disabled := historicalSourceFixture("off.example.org")
	disabled.Enabled = false
	disabled.TLS = HTTPClientTLS{CAFile: "/etc/off-ca.pem"}

	paths := artifactOperationsDiagnosticsPaths(diagnosticsSettings(OperationsDiagnosticsSection{Enabled: true,
		Sources: OperationsDiagnosticsSources{Loki: loki, Prometheus: prometheus}}))

	for _, want := range []string{"/etc/loki-ca.pem", "/etc/prometheus-ca.pem", "/etc/prometheus.pem", "/etc/prometheus.key"} {
		if !slices.Contains(paths, want) {
			t.Errorf("paths = %q, want %q", paths, want)
		}
	}

	paths = artifactOperationsDiagnosticsPaths(diagnosticsSettings(OperationsDiagnosticsSection{Enabled: true,
		Sources: OperationsDiagnosticsSources{Loki: disabled}}))
	if slices.Contains(paths, "/etc/off-ca.pem") {
		t.Errorf("a disabled source must not contribute paths: %q", paths)
	}
}
