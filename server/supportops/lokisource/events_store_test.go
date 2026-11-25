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
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
)

// storeEntry is one stored line of the store fake.
type storeEntry struct {
	labels map[string]string
	ts     int64
	line   string
}

// storeLoki is a Loki fake over stored lines with backward reads newest first across streams within [start, end)
// and limit, the series listing of streams with data in the span, and probe reads; dedupProbe merges probe lines of
// one stream and time like a deduplicating Loki.
type storeLoki struct {
	entries    []storeEntry
	dedupProbe bool

	// reject, when set, rejects every query that contains it.
	reject string
}

// storeStream is one stream of a fake read answer.
type storeStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"`
}

// storeMatcher reads the label matchers of a selector.
var storeMatcher = regexp.MustCompile(`(\w+)="((?:[^"\\]|\\.)*)"`)

// storeSelector returns the matchers of the selector at the start of a query.
func storeSelector(query string) map[string]string {
	end := strings.Index(query, "}")
	matchers := map[string]string{}

	for _, match := range storeMatcher.FindAllStringSubmatch(query[:end+1], -1) {
		value, _ := strconv.Unquote(`"` + match[2] + `"`)
		matchers[match[1]] = value
	}

	return matchers
}

// storeMatch reports whether labels satisfy every matcher.
func storeMatch(matchers map[string]string, labels map[string]string) bool {
	for name, value := range matchers {
		if labels[name] != value {
			return false
		}
	}

	return true
}

// storeKey renders labels as a map key.
func storeKey(labels map[string]string) string {
	rendered, _ := json.Marshal(labels)

	return string(rendered)
}

// fake returns the HTTP fake.
func (b *storeLoki) fake() *fakeLoki {
	return &fakeLoki{respond: func(request *http.Request) string {
		parameters := request.URL.Query()

		if b.reject != "" && strings.Contains(parameters.Get("query"), b.reject) {
			return `{"status":"error"}`
		}

		start, _ := strconv.ParseInt(parameters.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(parameters.Get("end"), 10, 64)

		if strings.HasSuffix(request.URL.Path, "/series") {
			return b.series(storeSelector(parameters.Get("match[]")), start, end)
		}

		if strings.Contains(parameters.Get("query"), "count_over_time(") {
			return b.metric(request)
		}

		limit, _ := strconv.Atoi(parameters.Get("limit"))

		return b.read(parameters.Get("query"), start, end, limit)
	}}
}

// series answers the stream listing: every stream with a stored line in the span.
func (b *storeLoki) series(matchers map[string]string, start int64, end int64) string {
	seen := map[string]map[string]string{}

	for _, entry := range b.entries {
		if entry.ts >= start && entry.ts < end && storeMatch(matchers, entry.labels) {
			seen[storeKey(entry.labels)] = entry.labels
		}
	}

	data := make([]map[string]string, 0, len(seen))
	for _, labels := range seen {
		data = append(data, labels)
	}

	rendered, _ := json.Marshal(map[string]any{"status": "success", "data": data})

	return string(rendered)
}

// candidates returns the stored lines of one read newest first: in the span, of the selected streams, of the
// query's log format.
func (b *storeLoki) candidates(query string, start int64, end int64) []storeEntry {
	matchers, wantJSON := storeSelector(query), strings.Contains(query, "| json")

	var candidates []storeEntry

	for _, entry := range b.entries {
		if entry.ts >= start && entry.ts < end && storeMatch(matchers, entry.labels) && strings.HasPrefix(entry.line, "{") == wantJSON {
			candidates = append(candidates, entry)
		}
	}

	sort.SliceStable(candidates, func(left, right int) bool { return candidates[left].ts > candidates[right].ts })

	return candidates
}

// read answers one backward read of at most limit lines; a probe read replaces every line and may merge equal ones.
func (b *storeLoki) read(query string, start int64, end int64, limit int) string {
	probe := strings.Contains(query, probeLine)
	merged := map[string]bool{}
	streams := map[string]*storeStream{}
	order := []string{}
	count := 0

	for _, entry := range b.candidates(query, start, end) {
		if count >= limit {
			break
		}

		line, key := entry.line, storeKey(entry.labels)
		if probe {
			line = "-"
		}

		if position := key + fmt.Sprint(entry.ts); probe && b.dedupProbe {
			if merged[position] {
				continue
			}

			merged[position] = true
		}

		if streams[key] == nil {
			streams[key] = &storeStream{Stream: storeStreamLabels(entry.labels)}
			order = append(order, key)
		}

		streams[key].Values = append(streams[key].Values, []string{strconv.FormatInt(entry.ts, 10), line})
		count++
	}

	result := make([]*storeStream, 0, len(order))
	for _, key := range order {
		result = append(result, streams[key])
	}

	rendered, _ := json.Marshal(map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": result}})

	return string(rendered)
}

// storeStreamLabels returns stream labels with the parser labels a query adds.
func storeStreamLabels(labels map[string]string) map[string]string {
	streamLabels := map[string]string{"nauthilus_level": "WARN", "nauthilus_msg": "x"}

	for name, value := range labels {
		streamLabels[name] = value
	}

	return streamLabels
}

// storeLabels returns the labels of one pod stream.
func storeLabels(pod string) map[string]string {
	return map[string]string{"app": "nauthilus", "namespace": "mail", "pod": pod}
}

// pageStore follows the source position over the store fake and returns how often each line came and the gaps.
func pageStore(t *testing.T, source *Source, query supportops.LogEventsQuery) (map[string]int, []supportops.LogGap) {
	t.Helper()

	seen := map[string]int{}

	var gaps []supportops.LogGap

	for page := 0; page < 3000; page++ {
		result := source.LogEvents(context.Background(), query)
		for _, line := range result.Lines {
			seen[line.Line]++
		}

		gaps = append(gaps, result.Gaps...)

		if result.Next == nil {
			return seen, gaps
		}

		query.Position = *result.Next
	}

	t.Fatal("pages never ended")

	return nil, nil
}

// assertEachOnce checks that every stored line came exactly once.
func assertEachOnce(t *testing.T, seen map[string]int, entries []storeEntry) {
	t.Helper()

	for _, entry := range entries {
		if seen[entry.line] != 1 {
			t.Fatalf("line %.40q came %d times (%d distinct of %d)", entry.line, seen[entry.line], len(seen), len(entries))
		}
	}
}

// TestLogEventsSurviveACursorBeyondTheRun reproduces the final review: a crafted or outdated cursor whose skip exceeds
// a stream's run panicked on a slice bound. It must answer without a panic.
func TestLogEventsSurviveACursorBeyondTheRun(t *testing.T) {
	at := testQuery().Now.Add(-time.Minute).UnixNano()
	store := &storeLoki{}

	for _, pod := range []string{"mx-1", "mx-2"} {
		for index := range 3 {
			store.entries = append(store.entries, storeEntry{storeLabels(pod), at, fmt.Sprintf(`{"level":"WARN","msg":"%s-%d"}`, pod, index)})
		}
	}

	query := eventsQuery(2)
	query.Position = supportops.LogPosition{Before: time.Unix(0, at).UTC(), StreamIndex: 1, StreamDigest: streamDigest(storeLabels("mx-2")), Skip: 4000}

	if result := newTestSource(t, store.fake(), nil).LogEvents(context.Background(), query); result.Report.Status == "" {
		t.Fatalf("result = %+v", result)
	}
}

// TestLogEventsPageMixedFormatRuns reproduces the final review: a run spread over both log formats with more lines
// than one read ended with a cursor the service refused. Every line must come exactly once.
func TestLogEventsPageMixedFormatRuns(t *testing.T) {
	at := testQuery().Now.Add(-time.Minute).UnixNano()
	store := &storeLoki{}

	for index := range 3000 {
		store.entries = append(store.entries, storeEntry{storeLabels("mx-1"), at, fmt.Sprintf(`{"level":"WARN","msg":"j%05d"}`, index)},
			storeEntry{storeLabels("mx-1"), at, fmt.Sprintf(`level=WARN msg=l%05d`, index)})
	}

	store.entries = append(store.entries, storeEntry{storeLabels("mx-1"), at - 1e9, `{"level":"WARN","msg":"older"}`})
	seen, _ := pageStore(t, newTestSource(t, store.fake(), func(cfg *Config) { cfg.MaxResponseBytes = 64 << 20 }), eventsQuery(500))

	assertEachOnce(t, seen, store.entries)
}

// runWithLargeOldLines stores a run of 35 lines over pods streams and 40 older lines, 31 of them larger than half the
// byte bound, so ordinary paging shrinks, probes, and hands over to stream-by-stream reads mid-run.
func runWithLargeOldLines(at int64, pods int) *storeLoki {
	store := &storeLoki{}

	for index := range 35 {
		store.entries = append(store.entries, storeEntry{storeLabels(fmt.Sprintf("mx-%02d", index%pods)), at,
			fmt.Sprintf(`{"level":"WARN","msg":"run-%02d"}`, index)})
	}

	for index := range 40 {
		pad := ""
		if index >= 9 {
			pad = strings.Repeat("x", 3000)
		}

		store.entries = append(store.entries, storeEntry{storeLabels("mx-00"), at - int64(index+1)*1e9,
			fmt.Sprintf(`{"level":"WARN","msg":"old-%02d%s"}`, index, pad)})
	}

	return store
}

// TestLogEventsKeepDoneLinesAcrossStreamPages reproduces the final review: the lines a normal page had returned were
// forgotten at the boundary of a stream page, so lines came twice.
func TestLogEventsKeepDoneLinesAcrossStreamPages(t *testing.T) {
	store := runWithLargeOldLines(testQuery().Now.Add(-time.Minute).UnixNano(), 35)
	seen, _ := pageStore(t, newTestSource(t, store.fake(), func(cfg *Config) { cfg.MaxResponseBytes = 20000 }), eventsQuery(10))

	assertEachOnce(t, seen, store.entries)
}

// TestLogEventsProbeSurvivesMergedProbeLines reproduces the final review: a Loki that merges equal probe lines of one
// stream and time made the probe skip the rest of a run without a gap.
func TestLogEventsProbeSurvivesMergedProbeLines(t *testing.T) {
	for _, merged := range []bool{false, true} {
		store := runWithLargeOldLines(testQuery().Now.Add(-time.Minute).UnixNano(), 2)
		store.dedupProbe = merged
		seen, _ := pageStore(t, newTestSource(t, store.fake(), func(cfg *Config) { cfg.MaxResponseBytes = 20000 }), eventsQuery(10))

		assertEachOnce(t, seen, store.entries)
	}
}

// TestLogEventsPageRunsOverManyStreams reproduces the final review: more streams at a run than the series bound ended
// without a line and without a cursor. Every line must come exactly once.
func TestLogEventsPageRunsOverManyStreams(t *testing.T) {
	at := testQuery().Now.Add(-time.Minute).UnixNano()
	store := &storeLoki{}

	for pod := range 60 {
		for index := range 100 {
			store.entries = append(store.entries, storeEntry{storeLabels(fmt.Sprintf("mx-%02d", pod)), at,
				fmt.Sprintf(`{"level":"WARN","msg":"run-%02d-%03d"}`, pod, index)})
		}
	}

	store.entries = append(store.entries, storeEntry{storeLabels("mx-00"), at - 1e9, `{"level":"WARN","msg":"older"}`})
	seen, gaps := pageStore(t, newTestSource(t, store.fake(), func(cfg *Config) {
		cfg.MaxResponseBytes, cfg.MaxSeries = 64<<20, 50
	}), eventsQuery(100))

	assertEachOnce(t, seen, store.entries)

	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v", gaps)
	}
}
