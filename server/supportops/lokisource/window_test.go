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
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
)

// Query parts the store fake reads from a metric query.
var (
	storeRange    = regexp.MustCompile(`\[(\d+)(ms|s)\]\)`)
	storeGroupBy  = regexp.MustCompile(`^sum by \(([^)]*)\)`)
	storeLevels   = regexp.MustCompile(`nauthilus_level=~"([^"]*)"`)
	storeContains = regexp.MustCompile(`\|= ("(?:[^"\\]|\\.)*")`)
)

// storeGroup is one result series of a metric answer: its labels and its value per evaluation time.
type storeGroup struct {
	labels map[string]string
	values map[int64]int
}

// metric answers an instant or range count_over_time query over the stored lines with the semantics measured on
// the production Loki: an evaluation at t over range r counts the lines in (t-r, t], and a range query is aligned to
// its step like a query frontend with align_queries_with_step (start rounded down, end rounded up to a multiple of
// the step) and evaluated every step.
func (b *storeLoki) metric(request *http.Request) string {
	parameters := request.URL.Query()
	query := parameters.Get("query")
	groups := map[string]*storeGroup{}

	if !strings.HasSuffix(request.URL.Path, "/query_range") {
		at, _ := strconv.ParseInt(parameters.Get("time"), 10, 64)
		b.count(groups, query, at)

		return storeAnswer("vector", groups)
	}

	start, _ := strconv.ParseInt(parameters.Get("start"), 10, 64)
	end, _ := strconv.ParseInt(parameters.Get("end"), 10, 64)
	stepSeconds, _ := strconv.ParseInt(parameters.Get("step"), 10, 64)
	step := stepSeconds * int64(time.Second)
	last := end - end%step

	if last < end {
		last += step
	}

	for at := start - start%step; at <= last; at += step {
		b.count(groups, query, at)
	}

	return storeAnswer("matrix", groups)
}

// count adds the counts of one evaluation at time at to groups.
func (b *storeLoki) count(groups map[string]*storeGroup, query string, at int64) {
	rangeNanos := storeRangeNanos(query)
	names := []string{}

	if match := storeGroupBy.FindStringSubmatch(query); match != nil {
		names = strings.Split(strings.ReplaceAll(match[1], " ", ""), ",")
	}

	for _, entry := range b.entries {
		fields, counted := storeCounted(entry, query, matchersOf(query))
		if !counted || entry.ts <= at-rangeNanos || entry.ts > at {
			continue
		}

		labels := map[string]string{}

		for _, name := range names {
			switch name {
			case overviewLevelLabel:
				labels[name] = fields[levelField]
			case overviewMessageLabel:
				labels[name] = fields[messageField]
			default:
				labels[name] = entry.labels[name]
			}
		}

		key := storeKey(labels)
		if groups[key] == nil {
			groups[key] = &storeGroup{labels: labels, values: map[int64]int{}}
		}

		groups[key].values[at]++
	}
}

// matchersOf returns the selector matchers of a metric query, whose selector follows count_over_time(.
func matchersOf(query string) map[string]string {
	return storeSelector(query[strings.Index(query, "count_over_time(")+len("count_over_time("):])
}

// storeCounted reports whether a metric query counts entry: its selector, its log format, its level matcher, and
// its literal line filter. It also returns the parsed fields of a JSON line.
func storeCounted(entry storeEntry, query string, matchers map[string]string) (map[string]string, bool) {
	fields := storeFields(entry.line)
	isJSON := strings.HasPrefix(entry.line, "{")

	switch {
	case !storeMatch(matchers, entry.labels):
		return nil, false
	case strings.Contains(query, "| json") && !isJSON, strings.Contains(query, "| logfmt") && isJSON:
		return nil, false
	}

	if match := storeLevels.FindStringSubmatch(query); match != nil && !slices.Contains(strings.Split(match[1], "|"), fields[levelField]) {
		return nil, false
	}

	if match := storeContains.FindStringSubmatch(query); match != nil {
		literal, _ := strconv.Unquote(match[1])
		if !strings.Contains(entry.line, literal) {
			return nil, false
		}
	}

	return fields, true
}

// storeLogfmtPair matches one key=value pair of a slog text line.
var storeLogfmtPair = regexp.MustCompile(`(\w+)=("(?:[^"\\]|\\.)*"|\S+)`)

// storeFields parses a slog JSON or text line into its string fields.
func storeFields(line string) map[string]string {
	fields := map[string]string{}

	if strings.HasPrefix(line, "{") {
		_ = json.Unmarshal([]byte(line), &fields)

		return fields
	}

	for _, pair := range storeLogfmtPair.FindAllStringSubmatch(line, -1) {
		value, err := strconv.Unquote(pair[2])
		if err != nil {
			value = pair[2]
		}

		fields[pair[1]] = value
	}

	return fields
}

// storeRangeNanos returns the range of the count_over_time of a query.
func storeRangeNanos(query string) int64 {
	match := storeRange.FindStringSubmatch(query)
	value, _ := strconv.ParseInt(match[1], 10, 64)

	if match[2] == "ms" {
		return value * int64(time.Millisecond)
	}

	return value * int64(time.Second)
}

// storeAnswer renders the groups as a vector or matrix answer; Loki returns no point for an empty count.
func storeAnswer(kind string, groups map[string]*storeGroup) string {
	result := make([]map[string]any, 0, len(groups))

	for _, group := range groups {
		times := make([]int64, 0, len(group.values))
		for at := range group.values {
			times = append(times, at)
		}

		slices.Sort(times)

		points := make([][]any, 0, len(times))
		for _, at := range times {
			points = append(points, []any{json.Number(fmt.Sprintf("%d.%09d", at/int64(time.Second), at%int64(time.Second))),
				strconv.Itoa(group.values[at])})
		}

		if kind == "vector" {
			result = append(result, map[string]any{"metric": group.labels, "value": points[0]})

			continue
		}

		result = append(result, map[string]any{"metric": group.labels, "values": points})
	}

	rendered, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": kind, "result": result}})

	return string(rendered)
}

// windowSequence numbers the stored test lines, so no two of them are equal.
var windowSequence atomic.Int64

// windowLine stores one distinct JSON line of pod at a time.
func windowLine(pod string, level string, message string, at time.Time) storeEntry {
	line, _ := json.Marshal(map[string]string{levelField: level, messageField: message, "at": at.Format(time.RFC3339Nano),
		"seq": strconv.FormatInt(windowSequence.Add(1), 10)})

	return storeEntry{labels: storeLabels(pod), ts: at.UnixNano(), line: string(line)}
}

// edgeLines stores lines one nanosecond before, on, and one nanosecond after the window edges and every multiple of
// step around the window, so a count that loses an edge line or counts a line outside the window differs.
func edgeLines(window supportops.Window, step time.Duration) []storeEntry {
	points := []time.Time{window.From, window.Until}

	for at := window.From.Truncate(step); !at.After(window.Until.Add(step)); at = at.Add(step) {
		points = append(points, at, at.Add(step/3))
	}

	var entries []storeEntry

	for index, point := range points {
		for offset, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			pod, level := fmt.Sprintf("mx-%d", 1+(index+offset)%2), []string{"WARN", "ERROR"}[(index+offset)%2]
			entries = append(entries, windowLine(pod, level, fmt.Sprintf("message %d", index%3), point.Add(delta)))
		}
	}

	return entries
}

// insideCount returns how many entries lie inside the half-open window.
func insideCount(entries []storeEntry, window supportops.Window) int {
	count := 0

	for _, entry := range entries {
		if entry.ts >= window.From.UnixNano() && entry.ts < window.Until.UnixNano() {
			count++
		}
	}

	return count
}

// warnAndError are the default overview levels.
var warnAndError = []string{supportops.LogLevelError, supportops.LogLevelWarn}

// overviewOf runs the overview over window and returns it with its total count.
func overviewOf(t *testing.T, source *Source, window supportops.Window) (supportops.LogOverviewSourceResult, int) {
	t.Helper()

	result := source.LogOverview(context.Background(), supportops.LogOverviewQuery{Window: window, Now: window.Until.Add(time.Minute),
		Levels: warnAndError})
	total := 0

	for _, series := range result.Series {
		for _, count := range series.Counts {
			total += int(count)
		}
	}

	return result, total
}

// eventsOf pages the events over window and returns how many lines arrived.
func eventsOf(t *testing.T, source *Source, window supportops.Window) int {
	t.Helper()

	seen, gaps := pageStore(t, source, supportops.LogEventsQuery{Window: window, Now: window.Until.Add(time.Minute),
		Levels: warnAndError, Limit: 7})
	if len(gaps) > 0 {
		t.Fatalf("events gaps = %+v", gaps)
	}

	count := 0

	for line, times := range seen {
		if times != 1 {
			t.Fatalf("line %s arrived %d times", line, times)
		}

		count++
	}

	return count
}

// assertTiledGrid checks that the buckets cover exactly the window, without gaps or overlap.
func assertTiledGrid(t *testing.T, buckets []supportops.Window, window supportops.Window) {
	t.Helper()

	if len(buckets) == 0 || len(buckets) > overviewBuckets || !buckets[0].From.Equal(window.From) ||
		!buckets[len(buckets)-1].Until.Equal(window.Until) {
		t.Fatalf("buckets %v do not tile %v", buckets, window)
	}

	for index := 1; index < len(buckets); index++ {
		if !buckets[index].From.Equal(buckets[index-1].Until) {
			t.Fatalf("bucket %d starts at %v, the one before ends at %v", index, buckets[index].From, buckets[index-1].Until)
		}
	}
}

// TestLogOverviewAgreesWithEventsOnAnyWindow reproduces the live defect of 25.11.2026: the overview of 15:38 to 16:38
// answered no message group and LOKI_BUCKETS_MISALIGNED, while the events of the same window returned seven lines.
// Loki's query frontend aligns range evaluations to multiples of the step, so the points never met the bucket ends
// of a grid that ends at an arbitrary window end. On every window the overview must count exactly the lines in
// [from, until), the same lines the events return, without losing an edge line or counting one outside.
func TestLogOverviewAgreesWithEventsOnAnyWindow(t *testing.T) {
	base := time.Date(2026, time.November, 25, 0, 0, 0, 0, time.UTC)

	for name, window := range map[string]supportops.Window{
		"unaligned live window": {From: base.Add(15*time.Hour + 38*time.Minute), Until: base.Add(16*time.Hour + 38*time.Minute)},
		"aligned live window":   {From: base.Add(15*time.Hour + 35*time.Minute), Until: base.Add(16*time.Hour + 35*time.Minute)},
		"milliseconds":          {From: base.Add(15*time.Hour + 38*time.Minute + 17250*time.Millisecond), Until: base.Add(16*time.Hour + time.Minute + 3125*time.Millisecond)},
		"ninety seconds":        {From: base.Add(16*time.Hour + 7*time.Second), Until: base.Add(16*time.Hour + 97*time.Second)},
	} {
		t.Run(name, func(t *testing.T) {
			store := &storeLoki{entries: edgeLines(window, 5*time.Minute)}
			source := newTestSource(t, store.fake(), nil)

			overview, total := overviewOf(t, source, window)
			if overview.Report.Status != supportops.SourceStatusOK || overview.Report.Code != "" {
				t.Fatalf("overview report = %+v", overview.Report)
			}

			assertTiledGrid(t, overview.Buckets, window)

			want := insideCount(store.entries, window)
			if total != want {
				t.Fatalf("overview counted %d lines, %d lie inside the window", total, want)
			}

			if events := eventsOf(t, source, window); events != want {
				t.Fatalf("events returned %d lines, %d lie inside the window", events, want)
			}

			assertBucketCounts(t, overview, store.entries)
		})
	}
}

// assertBucketCounts checks that every bucket of every series holds exactly the lines inside that bucket.
func assertBucketCounts(t *testing.T, overview supportops.LogOverviewSourceResult, entries []storeEntry) {
	t.Helper()

	for _, series := range overview.Series {
		for index, bucket := range overview.Buckets {
			want := 0

			for _, entry := range entries {
				fields := storeFields(entry.line)

				if entry.labels["pod"] == series.Instance && fields[messageField] == series.Message &&
					entry.ts >= bucket.From.UnixNano() && entry.ts < bucket.Until.UnixNano() &&
					strings.EqualFold(fields[levelField], series.Level) {
					want++
				}
			}

			if int(series.Counts[index]) != want {
				t.Fatalf("%s %s %s bucket %v: %d, want %d", series.Instance, series.Level, series.Message, bucket,
					series.Counts[index], want)
			}
		}
	}
}

// longWindow is a twelve-hour window that ends off the hour.
var longWindow = supportops.Window{From: time.Date(2026, time.November, 25, 4, 38, 0, 0, time.UTC),
	Until: time.Date(2026, time.November, 25, 16, 38, 0, 0, time.UTC)}

// hourly splits a window into consecutive hours that end at its end.
func hourly(window supportops.Window) []supportops.Window {
	var hours []supportops.Window

	for until := window.Until; until.After(window.From); until = until.Add(-time.Hour) {
		from := until.Add(-time.Hour)
		if from.Before(window.From) {
			from = window.From
		}

		hours = append(hours, supportops.Window{From: from, Until: until})
	}

	return hours
}

// assertBoundedRequests checks that no request to the fake covered more than bound: neither the range of a metric
// query nor the span of a log read.
func assertBoundedRequests(t *testing.T, fake *fakeLoki, bound time.Duration) {
	t.Helper()

	fake.mu.Lock()
	defer fake.mu.Unlock()

	for _, request := range fake.requests {
		parameters := request.URL.Query()
		query := parameters.Get("query")

		if strings.Contains(query, "count_over_time(") && time.Duration(storeRangeNanos(query)) > bound {
			t.Fatalf("metric query over %v: %s", time.Duration(storeRangeNanos(query)), query)
		}

		start, _ := strconv.ParseInt(parameters.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(parameters.Get("end"), 10, 64)

		if start > 0 && time.Duration(end-start) > bound {
			t.Fatalf("%s over %v", request.URL.Path, time.Duration(end-start))
		}
	}
}

// TestTwelveHourLogQueriesMatchTheirHours reproduces the clipping: with max_time_window 1h a twelve-hour overview or
// events read covered only its newest hour (LOKI_WINDOW_CLIPPED), while twelve hourly calls worked. The long window
// must be answered completely by parts of at most one hour each, and agree with the merged hourly answers.
func TestTwelveHourLogQueriesMatchTheirHours(t *testing.T) {
	var entries []storeEntry

	for _, hour := range hourly(longWindow) {
		entries = append(entries, edgeLines(hour, 25*time.Minute)...)
	}

	store := &storeLoki{entries: entries}
	fake := store.fake()
	source := newTestSource(t, fake, nil)

	overview, total := overviewOf(t, source, longWindow)
	if overview.Report.Status != supportops.SourceStatusOK || overview.Report.Code != "" {
		t.Fatalf("overview report = %+v", overview.Report)
	}

	assertTiledGrid(t, overview.Buckets, longWindow)

	hourlyTotal, hourlyEvents := 0, 0

	for _, hour := range hourly(longWindow) {
		_, count := overviewOf(t, source, hour)
		hourlyTotal += count
		hourlyEvents += eventsOf(t, source, hour)
	}

	want := insideCount(entries, longWindow)
	if total != want || hourlyTotal != want || hourlyEvents != want {
		t.Fatalf("12h overview %d, hourly overviews %d, hourly events %d, inside %d", total, hourlyTotal, hourlyEvents, want)
	}

	if events := eventsOf(t, source, longWindow); events != want {
		t.Fatalf("12h events %d, inside %d", events, want)
	}

	assertBoundedRequests(t, fake, time.Hour)
}

// TestTwelveHourDiagnosticsMatchTheirHours pins the diagnostics counts of a long window: the profile symptom of a
// twelve-hour window equals the sum of its hours, and no Loki query covers more than max_time_window.
func TestTwelveHourDiagnosticsMatchTheirHours(t *testing.T) {
	var entries []storeEntry

	for index, hour := range hourly(longWindow) {
		for _, at := range []time.Time{hour.From, hour.From.Add(17 * time.Minute), hour.Until.Add(-time.Nanosecond)} {
			entries = append(entries, windowLine(fmt.Sprintf("mx-%d", 1+index%2), "ERROR", "Redis batching pipeline returned error", at))
		}
	}

	fake := (&storeLoki{entries: entries}).fake()
	source := newTestSource(t, fake, nil)
	query := supportops.Query{Window: longWindow, Now: longWindow.Until.Add(time.Minute), Components: []string{supportops.ComponentRedis}}

	long := source.Collect(context.Background(), query)
	if long.Report.Status != supportops.SourceStatusOK || long.Report.Code != "" || !long.Report.Coverage.From.Equal(longWindow.From) {
		t.Fatalf("12h report = %+v", long.Report)
	}

	hours := map[string]int64{}

	for _, hour := range hourly(longWindow) {
		query.Window = hour
		for _, finding := range source.Collect(context.Background(), query).Findings {
			hours[finding.Scope.Instance] += symptomCount(finding, supportops.SymptomRedisPipelineError)
		}
	}

	for _, instance := range []string{"mx-1", "mx-2"} {
		got := symptomCount(findingFor(t, long, supportops.ComponentRedis, instance), supportops.SymptomRedisPipelineError)
		if got != 18 || got != hours[instance] {
			t.Fatalf("%s: 12h count %d, hourly sum %d, want 18", instance, got, hours[instance])
		}
	}

	assertBoundedRequests(t, fake, time.Hour)
}

// symptomCount returns the count of one symptom of a finding.
func symptomCount(finding supportops.Finding, code string) int64 {
	for _, symptom := range finding.Symptoms {
		if symptom.Code == code {
			return symptom.Count
		}
	}

	return 0
}

// TestWindowBeyondThePartBoundStaysClipped pins the resource bound: a window that needs more parts than allowed is
// still clipped to its newest parts, and the clipping is stated.
func TestWindowBeyondThePartBoundStaysClipped(t *testing.T) {
	source := newTestSource(t, (&storeLoki{}).fake(), func(cfg *Config) { cfg.MaxTimeWindow = 10 * time.Minute })
	query := supportops.Query{Window: longWindow, Now: longWindow.Until, Components: []string{supportops.ComponentRedis}}

	result := source.Collect(context.Background(), query)
	if result.Report.Status != supportops.SourceStatusPartial || result.Report.Code != "LOKI_WINDOW_CLIPPED" ||
		!result.Report.Coverage.From.Equal(longWindow.Until.Add(-4*time.Hour)) {
		t.Fatalf("clip = %+v", result.Report)
	}
}

// TestEventPartsKeepFailuresVisible pins how a part read meets a failed query: with one log format rejected the pages
// still deliver every line of the other format across all parts and state partial; with every query rejected no
// part is passed over and the page ends without a cursor, so the request can be repeated.
func TestEventPartsKeepFailuresVisible(t *testing.T) {
	window := supportops.Window{From: longWindow.Until.Add(-3 * time.Hour), Until: longWindow.Until}
	store := &storeLoki{reject: "| logfmt"}

	for _, hour := range hourly(window) {
		store.entries = append(store.entries, windowLine("mx-1", "WARN", "json", hour.From.Add(time.Minute)),
			logfmtLine("mx-1", "WARN", "text", hour.From.Add(2*time.Minute)))
	}

	source := newTestSource(t, store.fake(), nil)
	query := supportops.LogEventsQuery{Window: window, Now: window.Until, Levels: warnAndError, Limit: 7}
	delivered := 0

	for page := 0; page < 20; page++ {
		result := source.LogEvents(context.Background(), query)
		if result.Report.Status != supportops.SourceStatusPartial || result.Report.Code != "LOKI_QUERY_REJECTED" {
			t.Fatalf("page %d report = %+v", page, result.Report)
		}

		delivered += len(result.Lines)

		if result.Next == nil {
			break
		}

		query.Position = *result.Next
	}

	if delivered != 3 {
		t.Fatalf("delivered %d JSON lines over the parts, want 3", delivered)
	}

	store.reject = "| __error__"

	result := source.LogEvents(context.Background(), supportops.LogEventsQuery{Window: window, Now: window.Until, Levels: warnAndError, Limit: 7})
	if result.Report.Status != supportops.SourceStatusUnavailable || result.Next != nil || len(result.Lines) != 0 {
		t.Fatalf("unreadable part = %+v", result)
	}
}
