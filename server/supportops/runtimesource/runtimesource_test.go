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
	"maps"
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
		familyPluginCalls: prometheus.NewCounterVec(prometheus.CounterOpts{Name: familyPluginCalls},
			[]string{labelModule, labelComponent, labelExtensionPoint, "method", labelResult}),
		familyLuaVMReplaced: prometheus.NewCounterVec(prometheus.CounterOpts{Name: familyLuaVMReplaced}, []string{labelKey}),
		familyAuthAppErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Name: familyAuthAppErrors}, []string{labelTransport}),
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
		supportops.ComponentPolicy: supportops.StatusNotObserved, supportops.ComponentAuthBackend: supportops.StatusNotObserved,
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

// ldapCounterCase is one expected lifetime-counter finding of the LDAP error classification.
type ldapCounterCase struct {
	labels  map[string]string
	symptom string
	count   int64
}

// TestRuntimeLDAPErrorsAreClassified pins that a rejected user password (bind, result code 49) is reported as its
// own informational symptom per pool, operation, and code, while every other directory error stays LDAP_ERRORS.
func TestRuntimeLDAPErrorsAreClassified(t *testing.T) {
	registry, _, counters := newRegistry(t)

	counters[familyLDAPErrors].WithLabelValues("auth", "bind", "49").Add(3)
	counters[familyLDAPErrors].WithLabelValues("auth", "bind", "network").Add(1)
	counters[familyLDAPErrors].WithLabelValues("lookup", "search", "32").Add(2)

	result := New(registry, CoreCounterFamilies...).Collect(context.Background(), testRuntimeQuery())
	want := []ldapCounterCase{
		{map[string]string{labelPool: "auth", labelOp: "bind", labelCode: "49"}, supportops.SymptomLDAPBindRejected, 3},
		{map[string]string{labelPool: "auth", labelOp: "bind", labelCode: "network"}, supportops.SymptomLDAPErrors, 1},
		{map[string]string{labelPool: "lookup", labelOp: "search", labelCode: "32"}, supportops.SymptomLDAPErrors, 2},
	}

	findings := findingsOf(result, supportops.ComponentLDAP)
	if len(findings) != len(want) {
		t.Fatalf("ldap findings = %+v, want %d", findings, len(want))
	}

	for index, expected := range want {
		finding := findings[index]
		if finding.Status != supportops.StatusObserved || !maps.Equal(finding.Labels, expected.labels) ||
			len(finding.Symptoms) != 1 || finding.Symptoms[0].Code != expected.symptom || finding.Symptoms[0].Count != expected.count {
			t.Errorf("finding %d = %+v, want %+v", index, finding, expected)
		}
	}
}

// TestRuntimeAuthBackendEvidence pins the runtime evidence of the auth_backend component: failed native plugin
// backend calls, replaced Lua backend VMs, and unexpected authentication application errors. Other plugin extension
// points, non-failure results, and Lua VM pools of other roles never count.
func TestRuntimeAuthBackendEvidence(t *testing.T) {
	registry, _, counters := newRegistry(t)
	calls := counters[familyPluginCalls]

	calls.WithLabelValues("rns", "directory", "backend", "VerifyPassword", "ok").Add(100)
	calls.WithLabelValues("rns", "directory", "backend", "VerifyPassword", "error").Add(2)
	calls.WithLabelValues("rns", "directory", "backend", "ListAccounts", "timeout").Add(1)
	calls.WithLabelValues("rns", "directory", "backend", "VerifyPassword", "canceled").Add(7)
	calls.WithLabelValues("rns", "directory", "backend", "VerifyPassword", "admission_limited").Add(5)
	calls.WithLabelValues("rep", "scorer", "filter", "Evaluate", "error").Add(9)
	counters[familyLuaVMReplaced].WithLabelValues("backend:legacy").Add(2)
	counters[familyLuaVMReplaced].WithLabelValues("feature:geo").Add(8)
	counters[familyAuthAppErrors].WithLabelValues("http").Add(4)

	result := New(registry, CoreCounterFamilies...).Collect(context.Background(), testRuntimeQuery())
	want := []ldapCounterCase{
		{map[string]string{labelKind: kindApplication, labelName: "http"}, supportops.SymptomAuthApplicationErrors, 4},
		{map[string]string{labelKind: kindLua, labelName: "backend:legacy"}, supportops.SymptomLuaBackendVMReplaced, 2},
		{map[string]string{labelKind: kindPlugin, labelName: "rns/directory"}, supportops.SymptomPluginBackendCallFailures, 3},
	}

	findings := findingsOf(result, supportops.ComponentAuthBackend)
	if len(findings) != len(want) {
		t.Fatalf("auth_backend findings = %+v, want %d", findings, len(want))
	}

	for index, expected := range want {
		finding := findings[index]
		if finding.Status != supportops.StatusObserved || !maps.Equal(finding.Labels, expected.labels) ||
			finding.Freshness.Basis != supportops.BasisProcessLifetimeCounter || len(finding.Symptoms) != 1 ||
			finding.Symptoms[0].Code != expected.symptom || finding.Symptoms[0].Count != expected.count {
			t.Errorf("finding %d = %+v, want %+v", index, finding, expected)
		}
	}
}

// TestRuntimeAuthBackendNothingCounted pins that registered but silent backend counters answer one not_observed
// finding, never one per family and never ok.
func TestRuntimeAuthBackendNothingCounted(t *testing.T) {
	registry, _, _ := newRegistry(t)

	result := New(registry, CoreCounterFamilies...).Collect(context.Background(), testRuntimeQuery())
	singleFinding(t, result, supportops.ComponentAuthBackend, supportops.StatusNotObserved)
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
