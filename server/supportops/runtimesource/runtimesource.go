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

// Package runtimesource is the nauthilus_runtime source of the operational diagnostics: a side-effect-free read of
// this instance's Prometheus registry. Gauges give the current state; counters accumulate since process start and
// never claim anything about the requested window. It never dials a backend and never writes.
package runtimesource

import (
	"context"
	"math"
	"regexp"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// processStartFamily is the Go process collector's start time gauge.
const processStartFamily = "process_start_time_seconds"

// CoreCounterFamilies are counter vectors the server registers at startup. A gathered registry omits a vector that
// has not counted yet, so for these families an absent series means "nothing counted since process start".
var CoreCounterFamilies = []string{familyLDAPErrors, familyRedisTimeouts, familyAuthEvents, familyPolicyTechnical}

// Source reads the local Prometheus registry.
type Source struct {
	gatherer   prometheus.Gatherer
	registered map[string]struct{}
}

// New returns the runtime source over gatherer (normally prometheus.DefaultGatherer). registeredCounters names the
// counter families known to be registered in that registry (normally CoreCounterFamilies); every other absent
// family is reported as unknown.
func New(gatherer prometheus.Gatherer, registeredCounters ...string) *Source {
	registered := make(map[string]struct{}, len(registeredCounters))
	for _, name := range registeredCounters {
		registered[name] = struct{}{}
	}

	return &Source{gatherer: gatherer, registered: registered}
}

// Name returns the source name.
func (s *Source) Name() string {
	return supportops.SourceRuntime
}

// Kind returns the source kind.
func (s *Source) Kind() supportops.SourceKind {
	return supportops.SourceKindLocalCurrent
}

// Collect gathers the registry once and evaluates the fixed rule table for every requested component.
func (s *Source) Collect(ctx context.Context, query supportops.Query) supportops.SourceResult {
	report := supportops.SourceReport{Status: supportops.SourceStatusOK,
		Coverage: supportops.Coverage{View: supportops.CoverageLocalInstance, Instances: []string{query.Instance},
			From: supportops.TimePointer(query.Now), Until: supportops.TimePointer(query.Now)}}

	if ctx.Err() != nil {
		report.Status, report.Code = supportops.SourceStatusTimeout, "RUNTIME_TIMEOUT"

		return supportops.SourceResult{Report: report}
	}

	families, err := s.gatherer.Gather()
	if err != nil && len(families) == 0 {
		report.Status, report.Code = supportops.SourceStatusUnavailable, "RUNTIME_GATHER_FAILED"

		return supportops.SourceResult{Report: report}
	}

	if err != nil {
		report.Status, report.Code = supportops.SourceStatusPartial, "RUNTIME_GATHER_PARTIAL"
	}

	snapshot := newSnapshot(families, query, s.registered)

	var findings []supportops.Finding

	for _, component := range query.Components {
		evaluate, known := componentRules[component]
		if !known {
			continue
		}

		findings = append(findings, snapshot.componentFindings(component, evaluate)...)
	}

	return supportops.SourceResult{Report: report, Findings: findings}
}

// componentRules maps each component to its evaluator; components without runtime metrics answer unknown.
var componentRules = map[string]func(*snapshot) []supportops.Finding{
	supportops.ComponentLDAP:              (*snapshot).ldapFindings,
	supportops.ComponentAuthBackend:       nil,
	supportops.ComponentBackendMonitoring: (*snapshot).backendMonitoringFindings,
	supportops.ComponentRedis:             (*snapshot).redisFindings,
	supportops.ComponentClickHouseExport:  (*snapshot).clickHouseFindings,
	supportops.ComponentAuthEventDelivery: (*snapshot).authEventFindings,
	supportops.ComponentPolicy:            (*snapshot).policyFindings,
}

// snapshot is one gathered registry plus the observation context.
type snapshot struct {
	families   map[string]*dto.MetricFamily
	registered map[string]struct{}
	since      *time.Time
	query      supportops.Query
}

// newSnapshot indexes the gathered families by name and reads the process start time.
func newSnapshot(families []*dto.MetricFamily, query supportops.Query, registered map[string]struct{}) *snapshot {
	indexed := make(map[string]*dto.MetricFamily, len(families))

	for _, family := range families {
		indexed[family.GetName()] = family
	}

	result := &snapshot{families: indexed, registered: registered, query: query}

	if family, ok := indexed[processStartFamily]; ok && len(family.GetMetric()) == 1 {
		if seconds := family.GetMetric()[0].GetGauge().GetValue(); seconds > 0 && !math.IsInf(seconds, 0) {
			result.since = supportops.TimePointer(time.Unix(int64(seconds), 0))
		}
	}

	return result
}

// componentFindings runs one evaluator and answers unknown when it found no data.
func (s *snapshot) componentFindings(component string, evaluate func(*snapshot) []supportops.Finding) []supportops.Finding {
	var findings []supportops.Finding

	if evaluate != nil {
		findings = evaluate(s)
	}

	if len(findings) > 0 {
		return findings
	}

	return []supportops.Finding{supportops.UnknownFinding(supportops.SourceRuntime, component, s.scope(),
		s.freshness(supportops.BasisCurrentState), s.observed())}
}

// scope is the local instance scope of every runtime finding.
func (s *snapshot) scope() supportops.FindingScope {
	return supportops.FindingScope{Kind: supportops.ScopeInstance, Instance: s.query.Instance}
}

// observed is the point in time of every runtime finding.
func (s *snapshot) observed() supportops.Observation {
	return supportops.Observation{At: supportops.TimePointer(s.query.Now)}
}

// freshness states the read time and the meaning of the value.
func (s *snapshot) freshness(basis supportops.FreshnessBasis) supportops.Freshness {
	freshness := supportops.Freshness{ObservedAt: s.query.Now.UTC(), Basis: basis}
	if basis == supportops.BasisProcessLifetimeCounter {
		freshness.CountingSince = s.since
	}

	return freshness
}

// finding builds one runtime finding.
func (s *snapshot) finding(component string, basis supportops.FreshnessBasis, status supportops.Status, labels map[string]string, symptoms ...supportops.Symptom) supportops.Finding {
	if symptoms == nil {
		symptoms = []supportops.Symptom{}
	}

	return supportops.Finding{Component: component, Source: supportops.SourceRuntime, Scope: s.scope(), Status: status,
		Observed: s.observed(), Freshness: s.freshness(basis), Labels: labels, Symptoms: symptoms}
}

// series is one metric series with its labels and value.
type series struct {
	labels map[string]string
	value  float64
}

// familySeries returns the series of one family: nil when the family is unknown to the registry, empty when a
// registered counter has not counted yet.
func (s *snapshot) familySeries(name string) []series {
	family, ok := s.families[name]
	if ok {
		return seriesOf(family)
	}

	if _, registered := s.registered[name]; registered {
		return []series{}
	}

	return nil
}

// matchingSeries returns the series of every family whose name matches pattern, labeled with the family name.
func (s *snapshot) matchingSeries(pattern *regexp.Regexp, familyLabel string) []series {
	var result []series

	for name, family := range s.families {
		if !pattern.MatchString(name) {
			continue
		}

		for _, entry := range seriesOf(family) {
			entry.labels[familyLabel] = name
			result = append(result, entry)
		}
	}

	return result
}

// seriesOf converts the gauge or counter metrics of a family.
func seriesOf(family *dto.MetricFamily) []series {
	result := make([]series, 0, len(family.GetMetric()))

	for _, metric := range family.GetMetric() {
		labels := make(map[string]string, len(metric.GetLabel()))
		for _, pair := range metric.GetLabel() {
			labels[pair.GetName()] = pair.GetValue()
		}

		value := metric.GetGauge().GetValue()
		if family.GetType() == dto.MetricType_COUNTER {
			value = metric.GetCounter().GetValue()
		}

		if math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}

		result = append(result, series{labels: labels, value: value})
	}

	return result
}

// count converts a non-negative metric value to a symptom count.
func count(value float64) int64 {
	if value <= 0 {
		return 0
	}

	if value >= math.MaxInt64 {
		return math.MaxInt64
	}

	return int64(value)
}
