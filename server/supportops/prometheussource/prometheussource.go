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

// Package prometheussource is the optional historical metric source of the operational diagnostics. It runs only the
// compiled nauthilus_diagnostics profile: PromQL instant queries that sum the increase of fixed counter series per
// instance over the requested window, below a selector fixed in the configuration. Unlike the instance-local runtime
// source it covers every scraped instance and ties counts to the window. No caller value reaches a query, no series
// leaves Prometheus, redirects are never followed, and every answer is bounded in bytes and series. The query
// mechanics are shared with the other historical sources through package windowsource.
package prometheussource

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/metricnames"
	"github.com/croessner/nauthilus/v4/server/supportops/windowsource"
)

const (
	queryPath = "/api/v1/query"

	// codePrefix starts every failure code of the source, such as PROMETHEUS_TIMEOUT.
	codePrefix = "PROMETHEUS"

	// subqueryStepSeconds is the resolution of the subquery that keeps metric families apart; it is finer than any
	// sensible scrape interval, so no scrape is skipped.
	subqueryStepSeconds = 15

	// familyLabel keeps the metric family on the series of a name-pattern selector.
	familyLabel = "family"

	// minCoverageSamples is the smallest sample count that proves an instance was scraped inside the window: a
	// counter increase needs two samples.
	minCoverageSamples = 2
)

// Config is the fixed connection and query boundary of one Prometheus source.
type Config = windowsource.Connection

// Source is the Prometheus diagnostics source: the shared window engine with the compiled metric profile.
type Source struct {
	*windowsource.Engine
}

// New validates the boundary and builds the source. The HTTP client never follows redirects.
func New(cfg Config) (*Source, error) {
	fixed := fixedMatchers(cfg.Selector)

	engine, err := windowsource.New(cfg, windowsource.Profile{Name: supportops.SourcePrometheus, CodePrefix: codePrefix,
		QueryPath: queryPath, TimeParam: prometheusTime, Basis: supportops.BasisMetricWindow, View: supportops.CoverageMetricLabels,
		MinCoverage: minCoverageSamples, Coverage: coverageQuery(cfg.InstanceLabel, fixed),
		Entries: profileQueries(cfg.InstanceLabel, fixed)})
	if err != nil {
		return nil, err
	}

	return &Source{Engine: engine}, nil
}

// prometheusTime renders the evaluation time as RFC 3339, which the query API accepts.
func prometheusTime(at time.Time) string {
	return at.UTC().Format(time.RFC3339Nano)
}

// fixedMatchers renders the fixed selector as quoted matchers in label order.
func fixedMatchers(selector map[string]string) []string {
	names := make([]string, 0, len(selector))
	for name := range selector {
		names = append(names, name)
	}

	slices.Sort(names)

	matchers := make([]string, 0, len(names))
	for _, name := range names {
		matchers = append(matchers, equal(name, selector[name]))
	}

	return matchers
}

// coverageQuery returns the query that counts the scrape samples of the core gauge every instance sets at startup per
// instance. The gauge is a core metric, so a scrape pipeline that drops core metrics yields no coverage and every
// component reads unknown instead of a false not_observed.
func coverageQuery(instanceLabel string, fixed []string) func(int64) string {
	selector := seriesSelector{name: metricnames.VersionInfo}

	return func(rangeSeconds int64) string {
		return fmt.Sprintf("sum by (%s) (count_over_time(%s[%ds]))", instanceLabel, selector.render(fixed), rangeSeconds)
	}
}

// profileQueries converts the compiled profile into engine entries.
func profileQueries(instanceLabel string, fixed []string) []windowsource.Entry {
	entries := make([]windowsource.Entry, 0, len(diagnosticsProfile))

	for _, entry := range diagnosticsProfile {
		entries = append(entries, windowsource.Entry{Component: entry.component, Symptom: entry.symptom,
			Query: entry.query(instanceLabel, fixed)})
	}

	return entries
}

// seriesSelector is one PromQL series selector without the fixed matchers of the configuration. A selector that
// matches metric names by pattern sets anyName.
type seriesSelector struct {
	name     string
	matchers []string
	anyName  bool
}

// increase renders the increase of the selector's series over rangeSeconds. increase() drops the metric name, so
// series of different families that share every other label would collide ("vector cannot contain metrics with the
// same labelset"); a selector that matches names by pattern therefore keeps the family as a label and runs on a
// subquery, which the label rewrite needs.
func (s seriesSelector) increase(fixed []string, rangeSeconds int64) string {
	if s.anyName {
		return fmt.Sprintf(`increase(label_replace(%s, %s, "$1", %s, "(.+)")[%ds:%ds])`, s.render(fixed),
			strconv.Quote(familyLabel), strconv.Quote(nameLabel), rangeSeconds, subqueryStepSeconds)
	}

	return fmt.Sprintf("increase(%s[%ds])", s.render(fixed), rangeSeconds)
}

// render returns the selector with the fixed matchers appended.
func (s seriesSelector) render(fixed []string) string {
	return s.name + "{" + strings.Join(append(slices.Clone(s.matchers), fixed...), ",") + "}"
}

// equal renders an equality matcher.
func equal(label string, value string) string {
	return label + "=" + strconv.Quote(value)
}
