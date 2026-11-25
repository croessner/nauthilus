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

package windowsource

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
	"github.com/croessner/nauthilus/v4/server/supportops"
)

const (
	// maxParallelQueries bounds the concurrent requests one diagnostics call sends to a source.
	maxParallelQueries = 4

	// maxWindowParts bounds the parts of one window. A window longer than MaxTimeWindow is answered by consecutive
	// parts of at most MaxTimeWindow each; a window that needs more parts keeps its newest ones and is stated as
	// clipped, so one call never covers more than maxWindowParts queries per counted series.
	maxWindowParts = 24

	// TenantHeader carries the tenant of Loki, Mimir, and Cortex.
	TenantHeader = "X-Scope-OrgID"
)

// Connection is the fixed connection and query boundary of one historical source. Every field is set by the
// operator; none comes from a request.
type Connection struct {
	// Selector holds the fixed series or stream matchers every query carries.
	Selector map[string]string

	// HTTPClient is copied; its redirects are never followed.
	HTTPClient *http.Client

	BaseURL     *url.URL
	BearerToken secret.Value
	Password    secret.Value
	Username    string

	// Tenant is sent as X-Scope-OrgID.
	Tenant        string
	InstanceLabel string

	Timeout          time.Duration
	MaxTimeWindow    time.Duration
	MaxSeries        int
	MaxResponseBytes int64
}

// Entry binds one symptom of one component to the instant query that counts it inside a window.
type Entry struct {
	// Query returns the instant query that counts the symptom per instance over rangeMillis milliseconds.
	Query     func(rangeMillis int64) string
	Component string
	Symptom   string
}

// Spec describes one historical source on top of a Client: its identity, how coverage is proven, and its profile.
type Spec struct {
	// Coverage returns the instant query that counts the evidence available per instance over rangeMillis
	// milliseconds.
	Coverage func(rangeMillis int64) string

	// Entries is the compiled profile in response order.
	Entries []Entry

	// Name is the source name of the reports and findings.
	Name string

	// CodePrefix starts every failure code of the source, such as LOKI in LOKI_TIMEOUT.
	CodePrefix string

	// Basis is the freshness basis of the findings.
	Basis supportops.FreshnessBasis

	// View is the coverage view of the report.
	View string

	// InstanceLabel is the series label that names the instance.
	InstanceLabel string

	// MinCoverage is the smallest coverage value that proves an instance was observed in the window.
	MinCoverage float64

	Timeout       time.Duration
	MaxTimeWindow time.Duration

	// ClosedRangeEnd states that the range selectors of the endpoint count (t-range, t], as Loki does; a count of a
	// window then runs one nanosecond before its exclusive end, so it covers exactly [from, until).
	ClosedRangeEnd bool
}

// Engine is a historical diagnostics source that runs a compiled profile through a fixed client.
type Engine struct {
	client *Client
	spec   Spec
}

// Profile is what distinguishes one historical source from another on the same kind of connection.
type Profile struct {
	// TimeParam renders the evaluation time as the endpoint expects it.
	TimeParam func(time.Time) string

	// Coverage and Entries are the queries rendered for the connection of the source.
	Coverage func(rangeMillis int64) string
	Entries  []Entry

	Name       string
	CodePrefix string
	QueryPath  string

	// RangePath is the log query path of an endpoint that answers log reads; empty disables them.
	RangePath string

	// SeriesPath is the stream listing path of a log endpoint; empty disables it.
	SeriesPath string

	// Basis and View state what the findings and the coverage of the source mean.
	Basis       supportops.FreshnessBasis
	View        string
	MinCoverage float64

	// ClosedRangeEnd is copied into the spec; see Spec.ClosedRangeEnd.
	ClosedRangeEnd bool
}

// New validates the connection and builds the source engine for profile. The HTTP client never follows redirects.
func New(conn Connection, profile Profile) (*Engine, error) {
	if conn.BaseURL == nil || conn.InstanceLabel == "" || len(conn.Selector) == 0 {
		return nil, errors.New(profile.Name + " diagnostics source is incompletely configured")
	}

	headers := map[string]string{}
	if conn.Tenant != "" {
		headers[TenantHeader] = conn.Tenant
	}

	client, err := NewClient(ClientConfig{HTTP: conn.HTTPClient, Endpoint: conn.BaseURL, QueryPath: profile.QueryPath,
		RangePath: profile.RangePath, SeriesPath: profile.SeriesPath, Headers: headers, TimeParam: profile.TimeParam, BearerToken: conn.BearerToken, Password: conn.Password,
		Username: conn.Username, MaxResponseBytes: conn.MaxResponseBytes, MaxSeries: conn.MaxSeries})
	if err != nil {
		return nil, err
	}

	return NewEngine(client, Spec{Name: profile.Name, CodePrefix: profile.CodePrefix, Basis: profile.Basis, View: profile.View,
		InstanceLabel: conn.InstanceLabel, MinCoverage: profile.MinCoverage, Timeout: conn.Timeout, MaxTimeWindow: conn.MaxTimeWindow,
		Coverage: profile.Coverage, Entries: profile.Entries, ClosedRangeEnd: profile.ClosedRangeEnd})
}

// NewEngine validates the spec and builds the source.
func NewEngine(client *Client, spec Spec) (*Engine, error) {
	if client == nil || spec.Coverage == nil || spec.Name == "" || spec.CodePrefix == "" || spec.Basis == "" ||
		spec.View == "" || spec.InstanceLabel == "" || spec.MinCoverage <= 0 || spec.Timeout <= 0 || spec.MaxTimeWindow <= 0 {
		return nil, errors.New(spec.Name + " diagnostics source is incompletely configured")
	}

	return &Engine{client: client, spec: spec}, nil
}

// Name returns the source name.
func (e *Engine) Name() string {
	return e.spec.Name
}

// Kind returns the source kind.
func (e *Engine) Kind() supportops.SourceKind {
	return supportops.SourceKindHistorical
}

// code renders one failure code of the source.
func (e *Engine) code(suffix string) string {
	return e.spec.CodePrefix + "_" + suffix
}

// Collect runs the coverage query and the profile queries of the requested components inside the window. A window
// longer than MaxTimeWindow is counted part by part and the counts are added, so no query covers more than
// MaxTimeWindow; the time budget grows with the parts.
func (e *Engine) Collect(ctx context.Context, query supportops.Query) supportops.SourceResult {
	parts, window, clipped := e.windowParts(query.Window)

	ctx, cancel := context.WithTimeout(ctx, e.budget(parts))
	defer cancel()

	collection := newCollection(e, query, window)

	if clipped {
		collection.degrade(supportops.SourceStatusPartial, e.code("WINDOW_CLIPPED"))
	}

	entries := e.requestedEntries(query)
	if len(entries) == 0 {
		return collection.result(nil)
	}

	slots := make(chan struct{}, maxParallelQueries)

	coverage, ok := collection.sumParts(ctx, slots, e.spec.Coverage, parts, true)
	if !ok {
		return collection.result(nil)
	}

	counts := make([][]Sample, len(entries))
	failed := make([]bool, len(entries))

	var wait sync.WaitGroup

	for index, entry := range entries {
		wait.Go(func() {
			samples, succeeded := collection.sumParts(ctx, slots, entry.Query, parts, false)
			counts[index], failed[index] = samples, !succeeded
		})
	}

	wait.Wait()

	return collection.result(collection.findings(entries, coverage, counts, failed))
}

// requestedEntries returns the profile entries of the requested components in profile order.
func (e *Engine) requestedEntries(query supportops.Query) []Entry {
	var entries []Entry

	for _, entry := range e.spec.Entries {
		if query.Wants(entry.Component) {
			entries = append(entries, entry)
		}
	}

	return entries
}

// partLength returns MaxTimeWindow in whole milliseconds, the precision of a range selector.
func (e *Engine) partLength() time.Duration {
	return max(e.spec.MaxTimeWindow.Truncate(time.Millisecond), time.Millisecond)
}

// windowParts splits the requested window into consecutive parts of at most MaxTimeWindow that end at the window
// end, oldest first; the oldest part may be shorter. A window that needs more than maxWindowParts parts keeps its
// newest parts: the covered window is returned with the clipped flag.
func (e *Engine) windowParts(requested supportops.Window) ([]supportops.Window, supportops.Window, bool) {
	length := e.partLength()
	window, clipped := requested, false

	if limit := time.Duration(maxWindowParts) * length; requested.Until.Sub(requested.From) > limit {
		window, clipped = supportops.Window{From: requested.Until.Add(-limit), Until: requested.Until}, true
	}

	return SplitWindow(window, length), window, clipped
}

// SplitWindow splits window into consecutive parts of at most length that end at the window end, oldest first.
func SplitWindow(window supportops.Window, length time.Duration) []supportops.Window {
	var parts []supportops.Window

	for until := window.Until; until.After(window.From); until = until.Add(-length) {
		from := until.Add(-length)
		if from.Before(window.From) {
			from = window.From
		}

		parts = append(parts, supportops.Window{From: from.UTC(), Until: until.UTC()})
	}

	slices.Reverse(parts)

	return parts
}

// budget returns the time budget of a collection over parts: the source timeout for each part.
func (e *Engine) budget(parts []supportops.Window) time.Duration {
	return e.spec.Timeout * time.Duration(max(len(parts), 1))
}

// InstanceName returns an instance label value complete, with invisible format characters made visible.
func InstanceName(value string) string {
	return supportaccess.VerbatimText(value)
}

// collection gathers the state of one Collect call: the covered window, completeness, and truncation.
type collection struct {
	engine   *Engine
	query    supportops.Query
	window   supportops.Window
	mu       sync.Mutex
	status   supportops.SourceStatus
	code     string
	truncate bool
}

// newCollection starts a complete collection for the covered window.
func newCollection(engine *Engine, query supportops.Query, window supportops.Window) *collection {
	return &collection{engine: engine, query: query, window: window, status: supportops.SourceStatusOK}
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

// run executes one instant query that counts exactly the span: the range is the span length in milliseconds, and
// an endpoint with closed range ends is evaluated one nanosecond before the exclusive span end. A failure degrades
// the collection: the coverage query makes it unavailable, a profile query only partial.
func (c *collection) run(ctx context.Context, build func(rangeMillis int64) string, span supportops.Window, coverage bool) ([]Sample, bool) {
	at := span.Until
	if c.engine.spec.ClosedRangeEnd {
		at = at.Add(-time.Nanosecond)
	}

	samples, truncated, err := c.engine.client.Instant(ctx, build(rangeMillis(span)), at)
	if truncated {
		c.markTruncated()
	}

	if err != nil {
		c.fail(ctx, err, coverage)

		return nil, false
	}

	return samples, true
}

// rangeMillis returns the length of a span in whole milliseconds, at least one; support windows are planned in
// whole milliseconds, so the range covers the span exactly.
func rangeMillis(span supportops.Window) int64 {
	return max(int64(math.Ceil(float64(span.Until.Sub(span.From))/float64(time.Millisecond))), 1)
}

// sumParts runs build over every part, at most len(slots) queries at a time, and adds the samples of equal labels.
// It reports false when any part failed, so a partial count is never presented as complete.
func (c *collection) sumParts(ctx context.Context, slots chan struct{}, build func(rangeMillis int64) string,
	parts []supportops.Window, coverage bool) ([]Sample, bool) {
	answers := make([][]Sample, len(parts))
	succeeded := make([]bool, len(parts))

	var wait sync.WaitGroup

	for index, part := range parts {
		wait.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()

			answers[index], succeeded[index] = c.run(ctx, build, part, coverage)
		})
	}

	wait.Wait()

	return addSamples(answers), !slices.Contains(succeeded, false)
}

// addSamples adds the values of samples with equal labels across answers, in the order labels first appear.
func addSamples(answers [][]Sample) []Sample {
	var added []Sample

	index := map[string]int{}

	for _, samples := range answers {
		for _, sample := range samples {
			key := labelsKey(sample.Labels)
			if position, seen := index[key]; seen {
				added[position].Value += sample.Value

				continue
			}

			index[key] = len(added)
			added = append(added, sample)
		}
	}

	return added
}

// failureCode maps a query failure to a stable code without publishing the cause.
func (c *collection) failureCode(err error) string {
	switch {
	case errors.Is(err, ErrTruncated):
		return c.engine.code("RESULT_TRUNCATED")
	case errors.Is(err, ErrRejected):
		return c.engine.code("QUERY_REJECTED")
	default:
		return c.engine.code("UNREACHABLE")
	}
}

// result assembles the source result with the coverage statement of the instances the findings name.
func (c *collection) result(findings []supportops.Finding) supportops.SourceResult {
	instances := []string{}

	for _, finding := range findings {
		if finding.Scope.Kind == supportops.ScopeInstance && !slices.Contains(instances, finding.Scope.Instance) {
			instances = append(instances, finding.Scope.Instance)
		}
	}

	slices.Sort(instances)

	return supportops.SourceResult{Findings: findings, Report: c.report(instances, c.window)}
}

// report states the completeness of the collection, the covered instances, and the covered time span.
func (c *collection) report(instances []string, covered supportops.Window) supportops.SourceReport {
	c.mu.Lock()
	defer c.mu.Unlock()

	if instances == nil {
		instances = []string{}
	}

	return supportops.SourceReport{Status: c.status, Code: c.code, Truncated: c.truncate, Coverage: supportops.Coverage{
		View: c.engine.spec.View, Instances: instances, From: supportops.TimePointer(covered.From),
		Until: supportops.TimePointer(covered.Until)}}
}

// markTruncated records a truncated answer.
func (c *collection) markTruncated() {
	c.mu.Lock()
	c.truncate = true
	c.mu.Unlock()
	c.degrade(supportops.SourceStatusPartial, c.engine.code("RESULT_TRUNCATED"))
}

// fail degrades the collection for a failed query: a coverage failure makes it unavailable, any other only partial.
func (c *collection) fail(ctx context.Context, err error, coverage bool) {
	switch {
	case ctx.Err() != nil:
		c.degrade(supportops.SourceStatusTimeout, c.engine.code("TIMEOUT"))
	case coverage:
		c.degrade(supportops.SourceStatusUnavailable, c.failureCode(err))
	default:
		c.degrade(supportops.SourceStatusPartial, c.failureCode(err))
	}
}

// findings turns the coverage and profile counts into one finding per component and covered instance. Without
// coverage, every requested component is unknown for the deployment. A failed profile query makes its component
// unknown for instances without another counted symptom, never not_observed.
func (c *collection) findings(entries []Entry, coverage []Sample, counts [][]Sample, failed []bool) []supportops.Finding {
	covered := c.instances(coverage)
	components := entryComponents(entries)

	if len(covered) == 0 {
		findings := make([]supportops.Finding, 0, len(components))
		for _, component := range components {
			findings = append(findings, supportops.UnknownFinding(c.engine.spec.Name, component,
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
func (c *collection) componentFinding(component string, instance string, entries []Entry, counts [][]Sample, failed []bool) supportops.Finding {
	finding := supportops.Finding{Component: component, Source: c.engine.spec.Name, Status: supportops.StatusNotObserved,
		Scope: supportops.FindingScope{Kind: supportops.ScopeInstance, Instance: instance}, Freshness: c.freshness(),
		Observed: c.observed(), Symptoms: []supportops.Symptom{}}
	incomplete := false

	for index, entry := range entries {
		if entry.Component != component {
			continue
		}

		if failed[index] {
			incomplete = true

			continue
		}

		if total := c.count(counts[index], instance); total > 0 {
			finding.Status = supportops.StatusObserved
			finding.Symptoms = append(finding.Symptoms, supportops.Symptom{Code: entry.Symptom, Count: total})
		}
	}

	if incomplete && finding.Status == supportops.StatusNotObserved {
		finding.Status = supportops.StatusUnknown
	}

	return finding
}

// instances returns the covered instance names: those whose coverage value proves observation in the window.
func (c *collection) instances(coverage []Sample) []string {
	var instances []string

	for _, sample := range coverage {
		name := InstanceName(sample.Labels[c.engine.spec.InstanceLabel])
		if sample.Value >= c.engine.spec.MinCoverage && !slices.Contains(instances, name) {
			instances = append(instances, name)
		}
	}

	slices.Sort(instances)

	return instances
}

// count sums the samples of one instance and rounds to a whole count, as a rate-based estimate is fractional.
func (c *collection) count(samples []Sample, instance string) int64 {
	var total float64

	for _, sample := range samples {
		if InstanceName(sample.Labels[c.engine.spec.InstanceLabel]) == instance {
			total += sample.Value
		}
	}

	total = math.Round(total)
	if total >= math.MaxInt64 {
		return math.MaxInt64
	}

	return int64(total)
}

// freshness states that the counts refer to the covered window.
func (c *collection) freshness() supportops.Freshness {
	age := int64(c.query.Now.Sub(c.window.Until).Seconds())

	return supportops.Freshness{ObservedAt: c.query.Now.UTC(), Basis: c.engine.spec.Basis, AgeSeconds: max(age, 0)}
}

// observed is the covered window of every finding.
func (c *collection) observed() supportops.Observation {
	return supportops.Observation{From: supportops.TimePointer(c.window.From), Until: supportops.TimePointer(c.window.Until)}
}

// entryComponents returns the distinct components of entries in profile order.
func entryComponents(entries []Entry) []string {
	var components []string

	for _, entry := range entries {
		if !slices.Contains(components, entry.Component) {
			components = append(components, entry.Component)
		}
	}

	return components
}
