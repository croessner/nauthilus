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

package lokisource

import (
	"context"
	"errors"
	"math"
	"slices"
	"sync"

	"github.com/croessner/nauthilus/v4/server/supportops"
)

// collection gathers the state of one Collect call: the covered window, completeness, and truncation.
type collection struct {
	source   *Source
	query    supportops.Query
	window   supportops.Window
	mu       sync.Mutex
	status   supportops.SourceStatus
	code     string
	truncate bool
}

// newCollection starts a complete collection for the covered window.
func newCollection(source *Source, query supportops.Query, window supportops.Window) *collection {
	return &collection{source: source, query: query, window: window, status: supportops.SourceStatusOK}
}

// statusRank orders completeness from complete to failed; degrade keeps the worst.
var statusRank = map[supportops.SourceStatus]int{
	supportops.SourceStatusOK: 0, supportops.SourceStatusPartial: 1, supportops.SourceStatusTimeout: 2,
	supportops.SourceStatusUnavailable: 3,
}

// degrade records a worse completeness status and its code.
func (c *collection) degrade(status supportops.SourceStatus, code string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if statusRank[status] > statusRank[c.status] {
		c.status, c.code = status, code
	}
}

// run executes the query of one profile entry (the empty entry is the coverage query). A failure degrades the
// collection: the coverage query makes it unavailable, a profile query only partial.
func (c *collection) run(ctx context.Context, entry profileEntry) ([]vectorSample, bool) {
	rangeSeconds := max(int64(math.Ceil(c.window.Until.Sub(c.window.From).Seconds())), 1)

	samples, truncated, err := c.source.client.instant(ctx, c.source.countQuery(entry.literal, rangeSeconds), c.window.Until)
	if truncated {
		c.mu.Lock()
		c.truncate = true
		c.mu.Unlock()
		c.degrade(supportops.SourceStatusPartial, "LOKI_RESULT_TRUNCATED")
	}

	if err == nil {
		return samples, true
	}

	switch {
	case ctx.Err() != nil:
		c.degrade(supportops.SourceStatusTimeout, "LOKI_TIMEOUT")
	case entry.literal == "":
		c.degrade(supportops.SourceStatusUnavailable, failureCode(err))
	default:
		c.degrade(supportops.SourceStatusPartial, failureCode(err))
	}

	return nil, false
}

// failureCode maps a query failure to a stable code without publishing the cause.
func failureCode(err error) string {
	switch {
	case errors.Is(err, errTruncated):
		return "LOKI_RESULT_TRUNCATED"
	case errors.Is(err, errRejected):
		return "LOKI_QUERY_REJECTED"
	default:
		return "LOKI_UNREACHABLE"
	}
}

// result assembles the source result with the coverage statement.
func (c *collection) result(findings []supportops.Finding) supportops.SourceResult {
	instances := []string{}

	for _, finding := range findings {
		if finding.Scope.Kind == supportops.ScopeInstance && !slices.Contains(instances, finding.Scope.Instance) {
			instances = append(instances, finding.Scope.Instance)
		}
	}

	slices.Sort(instances)

	return supportops.SourceResult{Findings: findings, Report: supportops.SourceReport{Status: c.status, Code: c.code,
		Truncated: c.truncate, Coverage: supportops.Coverage{View: supportops.CoverageLogLabels, Instances: instances,
			From: supportops.TimePointer(c.window.From), Until: supportops.TimePointer(c.window.Until)}}}
}

// findings turns the coverage and profile counts into one finding per component and covered instance. Without
// coverage, every requested component is unknown for the deployment. A failed profile query makes its component
// unknown for instances without another counted symptom, never not_observed.
func (c *collection) findings(entries []profileEntry, coverage []vectorSample, counts [][]vectorSample, failed []bool) []supportops.Finding {
	covered := c.instances(coverage)
	components := entryComponents(entries)

	if len(covered) == 0 {
		findings := make([]supportops.Finding, 0, len(components))
		for _, component := range components {
			findings = append(findings, supportops.UnknownFinding(supportops.SourceLoki, component,
				supportops.FindingScope{Kind: supportops.ScopeDeployment}, c.freshness(), c.observed()))
		}

		return findings
	}

	findings := make([]supportops.Finding, 0, len(components)*len(covered))

	for _, component := range components {
		for _, instance := range covered {
			findings = append(findings, c.componentFinding(component, instance, entries, counts, failed))
		}
	}

	return findings
}

// componentFinding states the counted symptoms of one component on one covered instance.
func (c *collection) componentFinding(component string, instance string, entries []profileEntry, counts [][]vectorSample, failed []bool) supportops.Finding {
	finding := supportops.Finding{Component: component, Source: supportops.SourceLoki, Status: supportops.StatusNotObserved,
		Scope: supportops.FindingScope{Kind: supportops.ScopeInstance, Instance: instance}, Freshness: c.freshness(),
		Observed: c.observed(), Symptoms: []supportops.Symptom{}}
	incomplete := false

	for index, entry := range entries {
		if entry.component != component {
			continue
		}

		if failed[index] {
			incomplete = true

			continue
		}

		if total := c.count(counts[index], instance); total > 0 {
			finding.Status = supportops.StatusObserved
			finding.Symptoms = append(finding.Symptoms, supportops.Symptom{Code: entry.symptom, Count: total})
		}
	}

	if incomplete && finding.Status == supportops.StatusNotObserved {
		finding.Status = supportops.StatusUnknown
	}

	return finding
}

// instances returns the covered instance names: those with at least one log line in the window.
func (c *collection) instances(coverage []vectorSample) []string {
	var instances []string

	for _, sample := range coverage {
		name := instanceName(sample.labels[c.source.instanceLabel])
		if sample.value > 0 && !slices.Contains(instances, name) {
			instances = append(instances, name)
		}
	}

	slices.Sort(instances)

	return instances
}

// count sums the samples of one instance.
func (c *collection) count(samples []vectorSample, instance string) int64 {
	var total float64

	for _, sample := range samples {
		if instanceName(sample.labels[c.source.instanceLabel]) == instance {
			total += sample.value
		}
	}

	if total >= math.MaxInt64 {
		return math.MaxInt64
	}

	return int64(total)
}

// freshness states that log counts refer to the covered window.
func (c *collection) freshness() supportops.Freshness {
	age := int64(c.query.Now.Sub(c.window.Until).Seconds())

	return supportops.Freshness{ObservedAt: c.query.Now.UTC(), Basis: supportops.BasisLogWindow, AgeSeconds: max(age, 0)}
}

// observed is the covered window of every log finding.
func (c *collection) observed() supportops.Observation {
	return supportops.Observation{From: supportops.TimePointer(c.window.From), Until: supportops.TimePointer(c.window.Until)}
}

// entryComponents returns the distinct components of entries in profile order.
func entryComponents(entries []profileEntry) []string {
	var components []string

	for _, entry := range entries {
		if !slices.Contains(components, entry.component) {
			components = append(components, entry.component)
		}
	}

	return components
}
