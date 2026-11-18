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

package runtimesource

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// testRuntimeQuery asks for every component at a fixed time.
func testRuntimeQuery() supportops.Query {
	now := time.Date(2026, time.November, 18, 8, 0, 0, 0, time.UTC)

	return supportops.Query{Window: supportops.Window{From: now.Add(-15 * time.Minute), Until: now}, Now: now,
		Components: supportops.Components, Instance: "mx-1"}
}

// findingsOf returns the findings of one component.
func findingsOf(result supportops.SourceResult, component string) []supportops.Finding {
	var findings []supportops.Finding

	for _, finding := range result.Findings {
		if finding.Component == component {
			findings = append(findings, finding)
		}
	}

	return findings
}

// newRegistry registers the gauges and counters the rule table reads, with the server's label sets.
func newRegistry(t *testing.T) (*prometheus.Registry, map[string]*prometheus.GaugeVec, map[string]*prometheus.CounterVec) {
	t.Helper()

	registry := prometheus.NewRegistry()
	gauges := map[string]*prometheus.GaugeVec{
		familyLDAPTargetHealth: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: familyLDAPTargetHealth}, []string{labelPool, labelTarget}),
		familyLDAPBreakerState: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: familyLDAPBreakerState}, []string{labelPool, labelTarget}),
		familyBackendServers:   prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: familyBackendServers}, []string{labelServerStatus}),
	}
	counters := map[string]*prometheus.CounterVec{
		familyLDAPErrors:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: familyLDAPErrors}, []string{labelPool, "op", "code"}),
		familyRedisTimeouts: prometheus.NewCounterVec(prometheus.CounterOpts{Name: familyRedisTimeouts}, []string{labelPoolName}),
		familyAuthEvents:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: familyAuthEvents}, []string{labelOutcome, labelLane}),
		"nauthilus_plugin_clickhouse_clickhouse_flush_batches_total": prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "nauthilus_plugin_clickhouse_clickhouse_flush_batches_total"}, []string{labelResult}),
	}

	for _, collector := range gauges {
		registry.MustRegister(collector)
	}

	for _, collector := range counters {
		registry.MustRegister(collector)
	}

	return registry, gauges, counters
}

// TestRuntimeFindings pins the rule table: current gauges give failing/degraded/ok, lifetime counters give
// observed/not_observed with counting_since, and components without data are unknown.
func TestRuntimeFindings(t *testing.T) {
	registry, gauges, counters := newRegistry(t)

	gauges[familyLDAPTargetHealth].WithLabelValues("auth", "ldap://dc1").Set(0)
	gauges[familyLDAPBreakerState].WithLabelValues("auth", "ldap://dc1").Set(breakerStateOpen)
	gauges[familyLDAPTargetHealth].WithLabelValues("auth", "ldap://dc2").Set(1)
	gauges[familyLDAPBreakerState].WithLabelValues("auth", "ldap://dc2").Set(breakerStateHalfOpen)
	gauges[familyBackendServers].WithLabelValues(serverStatusWanted).Set(3)
	gauges[familyBackendServers].WithLabelValues(serverStatusAlive).Set(2)
	counters[familyLDAPErrors].WithLabelValues("auth", "search", "51").Add(4)
	counters[familyAuthEvents].WithLabelValues("delivered", "fast").Add(10)
	counters["nauthilus_plugin_clickhouse_clickhouse_flush_batches_total"].WithLabelValues("success").Add(9)
	counters["nauthilus_plugin_clickhouse_clickhouse_flush_batches_total"].WithLabelValues("http_error").Add(2)

	result := New(registry, CoreCounterFamilies...).Collect(context.Background(), testRuntimeQuery())
	if result.Report.Status != supportops.SourceStatusOK || !slices.Equal(result.Report.Coverage.Instances, []string{"mx-1"}) {
		t.Fatalf("report = %+v", result.Report)
	}

	assertLDAPFindings(t, findingsOf(result, supportops.ComponentLDAP))

	if backend := singleFinding(t, result, supportops.ComponentBackendMonitoring, supportops.StatusDegraded); backend.Symptoms[0].Count != 1 {
		t.Fatalf("backend = %+v", backend)
	}

	for component, status := range map[string]supportops.Status{
		supportops.ComponentRedis: supportops.StatusNotObserved, supportops.ComponentAuthEventDelivery: supportops.StatusNotObserved,
		supportops.ComponentPolicy: supportops.StatusNotObserved, supportops.ComponentAuthBackend: supportops.StatusUnknown,
	} {
		singleFinding(t, result, component, status)
	}

	if clickHouse := singleFinding(t, result, supportops.ComponentClickHouseExport, supportops.StatusObserved); clickHouse.Symptoms[0].Count != 2 {
		t.Fatalf("clickhouse = %+v", clickHouse)
	}
}

// assertLDAPFindings checks the per-target current state and the per-pool lifetime counter.
func assertLDAPFindings(t *testing.T, ldap []supportops.Finding) {
	t.Helper()

	if len(ldap) != 3 || ldap[0].Status != supportops.StatusFailing || len(ldap[0].Symptoms) != 2 ||
		ldap[1].Status != supportops.StatusDegraded || ldap[2].Status != supportops.StatusObserved ||
		ldap[2].Freshness.Basis != supportops.BasisProcessLifetimeCounter || ldap[2].Symptoms[0].Count != 4 {
		t.Fatalf("ldap = %+v", ldap)
	}
}

// singleFinding requires exactly one finding of a component with the given status.
func singleFinding(t *testing.T, result supportops.SourceResult, component string, status supportops.Status) supportops.Finding {
	t.Helper()

	findings := findingsOf(result, component)
	if len(findings) != 1 || findings[0].Status != status {
		t.Fatalf("%s = %+v, want one %s finding", component, findings, status)
	}

	return findings[0]
}

// TestRuntimeAbsentDataIsUnknown pins that unregistered families never answer ok or not_observed.
func TestRuntimeAbsentDataIsUnknown(t *testing.T) {
	result := New(prometheus.NewRegistry()).Collect(context.Background(), testRuntimeQuery())

	if len(result.Findings) != len(supportops.Components) {
		t.Fatalf("findings = %d, want one unknown per component", len(result.Findings))
	}

	for _, finding := range result.Findings {
		if finding.Status != supportops.StatusUnknown || finding.Scope.Instance != "mx-1" || finding.Observed.At == nil {
			t.Fatalf("finding = %+v", finding)
		}
	}
}

// failingGatherer simulates a registry that cannot be read.
type failingGatherer struct{ partial []*dto.MetricFamily }

// Gather returns the partial families and an error.
func (g failingGatherer) Gather() ([]*dto.MetricFamily, error) {
	return g.partial, errors.New("collector failed")
}

// TestRuntimeGatherFailures pins unavailable and partial reports and the respect of a cancelled context.
func TestRuntimeGatherFailures(t *testing.T) {
	if result := New(failingGatherer{}).Collect(context.Background(), testRuntimeQuery()); result.Report.Status != supportops.SourceStatusUnavailable {
		t.Fatalf("report = %+v", result.Report)
	}

	registry, gauges, _ := newRegistry(t)
	gauges[familyBackendServers].WithLabelValues(serverStatusWanted).Set(1)

	families, _ := registry.Gather()

	if result := New(failingGatherer{partial: families}).Collect(context.Background(), testRuntimeQuery()); result.Report.Status != supportops.SourceStatusPartial {
		t.Fatalf("report = %+v", result.Report)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if result := New(registry).Collect(cancelled, testRuntimeQuery()); result.Report.Status != supportops.SourceStatusTimeout {
		t.Fatalf("report = %+v", result.Report)
	}
}

// TestClickHouseFamilyPatternsMatchPluginNames pins the scoped plugin metric names of every stream.
func TestClickHouseFamilyPatternsMatchPluginNames(t *testing.T) {
	for _, name := range []string{
		"nauthilus_plugin_clickhouse_flush_batches_total",
		"nauthilus_plugin_clickhouse_clickhouse_flush_batches_total",
		"nauthilus_plugin_history_clickhouse_event_flush_batches_total",
		"nauthilus_plugin_x_clickhouse_auth_events_flush_batches_total",
	} {
		if !clickHouseFlushFamilies.MatchString(name) {
			t.Errorf("%s must match the flush pattern", name)
		}
	}

	if clickHouseFlushFamilies.MatchString("clickhouse_flush_batches_total") || clickHouseQueueFamilies.MatchString("nauthilus_plugin_x_queued_rows_total") {
		t.Fatal("unscoped or foreign names must not match")
	}
}
