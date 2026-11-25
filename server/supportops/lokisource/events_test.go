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
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
	"github.com/croessner/nauthilus/v4/server/supportops/windowsource"
)

// streams renders a success streams answer: one stream per pod with its lines newest first.
func streams(pod string, at time.Time, lines ...string) string {
	values := make([]string, 0, len(lines))

	for index, line := range lines {
		values = append(values, fmt.Sprintf(`[%q,%q]`, strconv.FormatInt(at.Add(-time.Duration(index)*time.Second).UnixNano(), 10), line))
	}

	return `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"pod":` + strconv.Quote(pod) +
		`,"nauthilus_level":"WARN","nauthilus_msg":"x"},"values":[` + strings.Join(values, ",") + `]}]}}`
}

// eventsQuery asks for warnings of the last 30 minutes.
func eventsQuery(limit int) supportops.LogEventsQuery {
	base := testQuery()

	return supportops.LogEventsQuery{Window: base.Window, Now: base.Now, Levels: []string{supportops.LogLevelWarn}, Limit: limit}
}

// TestLogEventsQueryQuotesCallerFilters pins the exact log queries: a hostile instance and message reach LogQL only
// as quoted strings, so they can neither close the selector nor add a pipeline stage.
func TestLogEventsQueryQuotesCallerFilters(t *testing.T) {
	fake := &fakeLoki{answers: map[string]string{"| json": streams("mx-1", testQuery().Now), "| logfmt": streams("mx-1", testQuery().Now)}}
	query := eventsQuery(10)
	query.Instance = `mx-1"} |= "x`
	message := "a\" | line_format \"{{.password}}"
	query.Message = &message

	newTestSource(t, fake, nil).LogEvents(context.Background(), query)

	selector := testSelector + ` | pod="mx-1\"} |= \"x"`
	stage := ` | nauthilus_msg="a\" | line_format \"{{.password}}"`
	want := []string{
		selector + ` |~ "\"level\":\"(WARN)\"" | json nauthilus_level="level", nauthilus_msg="msg" | __error__="" | nauthilus_level=~"WARN"` + stage,
		selector + ` !~ "^\\s*\\{" |~ "(^|\\s)level=(WARN)(\\s|$)" | logfmt nauthilus_level="level", nauthilus_msg="msg" | __error__="" | nauthilus_level=~"WARN"` + stage,
	}

	for _, request := range fake.requests {
		parameters := request.URL.Query()
		if !slices.Contains(want, parameters.Get("query")) || parameters.Get("direction") != "backward" || parameters.Get("limit") != "11" ||
			!strings.HasSuffix(request.URL.Path, "/query_range") {
			t.Fatalf("request %s ?%v", request.URL.Path, parameters)
		}
	}

	if len(fake.requests) != 2 {
		t.Fatalf("requests = %d", len(fake.requests))
	}
}

// TestLogEventsMergeFormats pins that the lines of both formats merge newest first without the parser labels and that
// More is set when a line follows.
func TestLogEventsMergeFormats(t *testing.T) {
	now := testQuery().Now
	fake := &fakeLoki{answers: map[string]string{
		"| json":   streams("mx-1", now.Add(-time.Second), `{"level":"WARN","msg":"a"}`, `{"level":"WARN","msg":"c"}`),
		"| logfmt": streams("mx-2", now, `level=WARN msg=b`),
	}}

	result := newTestSource(t, fake, nil).LogEvents(context.Background(), eventsQuery(2))
	if result.Report.Status != supportops.SourceStatusOK || !result.More || result.LimitApplied != 2 || len(result.Lines) != 2 ||
		result.Lines[0].Line != "level=WARN msg=b" || result.Lines[1].Instance != "mx-1" {
		t.Fatalf("merged = %+v", result)
	}

	if _, parsed := result.Lines[0].Labels[overviewMessageLabel]; parsed || result.Lines[0].Labels["pod"] != "mx-2" {
		t.Fatalf("labels = %v", result.Lines[0].Labels)
	}
}

// TestLogEventsShrinkPagesAboveTheByteBound pins that an answer above the byte bound shrinks the page instead of
// losing lines, and that a page that never fits is reported.
func TestLogEventsShrinkPagesAboveTheByteBound(t *testing.T) {
	now := testQuery().Now
	sized := &fakeLoki{respond: func(request *http.Request) string {
		limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
		lines := make([]string, 0, limit)

		for range limit {
			lines = append(lines, `{"level":"WARN","msg":"`+strings.Repeat("x", 180)+`"}`)
		}

		return streams("mx-1", now, lines...)
	}}

	shrunk := newTestSource(t, sized, func(cfg *Config) { cfg.MaxResponseBytes = 2000 }).LogEvents(context.Background(), eventsQuery(8))
	if shrunk.Report.Status != supportops.SourceStatusOK || shrunk.LimitApplied != 3 || len(shrunk.Lines) != 3 || !shrunk.More {
		t.Fatalf("shrunk = %+v", shrunk)
	}

	tiny := newTestSource(t, sized, func(cfg *Config) { cfg.MaxResponseBytes = 16 }).LogEvents(context.Background(), eventsQuery(8))
	if tiny.Report.Status != supportops.SourceStatusPartial || !tiny.Report.Truncated || len(tiny.Lines) != 0 {
		t.Fatalf("a page that never fits must be reported, not emptied silently: %+v", tiny)
	}
}

// tieLoki stores JSON lines in its own ingest order, all at one time, and answers a backward query with the first
// limit stored lines before end, like Loki cuts a run of equal timestamps in its own order.
func tieLoki(at time.Time, stored []string, older []string) *fakeLoki {
	return &fakeLoki{respond: func(request *http.Request) string {
		if strings.Contains(request.URL.Query().Get("query"), "| logfmt") {
			return `{"status":"success","data":{"resultType":"streams","result":[]}}`
		}

		limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
		end, _ := strconv.ParseInt(request.URL.Query().Get("end"), 10, 64)
		values := []string{}

		for _, line := range stored {
			if at.UnixNano() < end && len(values) < limit {
				values = append(values, fmt.Sprintf(`[%q,%q]`, strconv.FormatInt(at.UnixNano(), 10), line))
			}
		}

		for index, line := range older {
			stamp := at.Add(-time.Duration(index+1) * time.Second).UnixNano()
			if stamp < end && len(values) < limit {
				values = append(values, fmt.Sprintf(`[%q,%q]`, strconv.FormatInt(stamp, 10), line))
			}
		}

		return `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"pod":"mx-1"},"values":[` +
			strings.Join(values, ",") + `]}]}}`
	}}
}

// TestLogEventsPagesThroughEqualTimestamps reproduces the review finding: Loki cuts a run of equal timestamps in its
// own order, so a page that ended inside the run repeated one line and lost another. Every line must come exactly
// once, in the stable order, across pages of two.
func TestLogEventsPagesThroughEqualTimestamps(t *testing.T) {
	at := testQuery().Now.Add(-time.Minute)
	source := newTestSource(t, tieLoki(at, []string{"e", "d", "c", "b", "a"}, []string{"y", "z"}), nil)
	query := eventsQuery(2)

	var seen []string

	for page := 0; page < 10; page++ {
		result := source.LogEvents(context.Background(), query)
		if result.Report.Status != supportops.SourceStatusOK {
			t.Fatalf("page %d report = %+v", page, result.Report)
		}

		for _, line := range result.Lines {
			seen = append(seen, line.Line)
		}

		if result.Next == nil {
			break
		}

		query.Position = *result.Next
	}

	if want := []string{"a", "b", "c", "d", "e", "y", "z"}; !slices.Equal(seen, want) {
		t.Fatalf("pages = %v, want %v", seen, want)
	}
}

// TestLogEventsInstanceNeverReplacesTheSelector pins that an instance filter only narrows the fixed selector, even
// when the instance label is one of its matchers.
func TestLogEventsInstanceNeverReplacesTheSelector(t *testing.T) {
	fake := &fakeLoki{}
	query := eventsQuery(2)
	query.Instance = "other-app"

	newTestSource(t, fake, func(cfg *Config) { cfg.InstanceLabel = "app" }).LogEvents(context.Background(), query)

	for _, request := range fake.requests {
		if text := request.URL.Query().Get("query"); !strings.HasPrefix(text, testSelector+` | app="other-app"`) {
			t.Fatalf("query = %s", text)
		}
	}
}

// TestLogEventsShrinkToTheSmallestPage pins that the byte bound shrinks a read down to one line whatever the page
// size, instead of giving up on the way.
func TestLogEventsShrinkToTheSmallestPage(t *testing.T) {
	now := testQuery().Now
	line := `{"level":"WARN","msg":"` + strings.Repeat("x", 180) + `"}`
	sized := &fakeLoki{respond: func(request *http.Request) string {
		limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
		lines := make([]string, 0, limit)

		for range limit {
			lines = append(lines, line)
		}

		return streams("mx-1", now, lines...)
	}}
	bound := int64(len(streams("mx-1", now, line, line)))

	for _, limit := range []int{1, 2, 8, 100} {
		result := newTestSource(t, sized, func(cfg *Config) { cfg.MaxResponseBytes = bound }).LogEvents(context.Background(), eventsQuery(limit))
		if result.Report.Status != supportops.SourceStatusOK || len(result.Lines) != 1 || result.Next == nil {
			t.Errorf("limit %d: status %s code %s lines %d next %v", limit, result.Report.Status, result.Report.Code,
				len(result.Lines), result.Next)
		}
	}
}

// TestLogEventsReadStaysWithinTheEntryBound pins that no read asks Loki for more than MaxLogEventRead lines, even for a
// continued page deep inside a long run of equal timestamps.
func TestLogEventsReadStaysWithinTheEntryBound(t *testing.T) {
	fake := &fakeLoki{}
	query := eventsQuery(supportops.MaxLogEventPageLimit)
	query.Position = supportops.LogPosition{Before: testQuery().Now.Add(-time.Minute), Skip: supportops.MaxLogEventRead - 2}

	newTestSource(t, fake, nil).LogEvents(context.Background(), query)

	for _, request := range fake.requests {
		if limit, _ := strconv.Atoi(request.URL.Query().Get("limit")); limit > supportops.MaxLogEventRead {
			t.Fatalf("read limit = %d", limit)
		}
	}
}

// runLoki serves a run of equal timestamps spread over several streams: the stream listing, normal reads (all streams
// mixed in store order, cut at limit), and reads of one stream named by its pod matcher. older lines follow the run.
func runLoki(at time.Time, runs map[string][]string, older []string) *fakeLoki {
	pods := slices.Sorted(maps.Keys(runs))

	return &fakeLoki{respond: func(request *http.Request) string {
		parameters := request.URL.Query()
		if strings.HasSuffix(request.URL.Path, "/series") {
			labels := make([]string, 0, len(pods))
			for _, pod := range pods {
				labels = append(labels, fmt.Sprintf(`{"app":"nauthilus","namespace":"mail","pod":%q}`, pod))
			}

			return `{"status":"success","data":[` + strings.Join(labels, ",") + `]}`
		}

		if strings.Contains(parameters.Get("query"), "| logfmt") {
			return `{"status":"success","data":{"resultType":"streams","result":[]}}`
		}

		limit, _ := strconv.Atoi(parameters.Get("limit"))
		start, _ := strconv.ParseInt(parameters.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(parameters.Get("end"), 10, 64)

		return runAnswer(at, runs, older, pods, parameters.Get("query"), limit, [2]int64{start, end})
	}}
}

// runAnswer renders the streams of one read like Loki's backward read: the newest lines first across all selected
// streams, so the whole run comes before any older line, at most limit lines in total.
func runAnswer(at time.Time, runs map[string][]string, older []string, pods []string, query string, limit int, span [2]int64) string {
	values := map[string][]string{}
	total := 0
	add := func(pod string, stamp int64, line string) {
		if stamp >= span[0] && stamp < span[1] && total < limit {
			values[pod] = append(values[pod], fmt.Sprintf(`[%q,%q]`, strconv.FormatInt(stamp, 10), line))
			total++
		}
	}

	selected := slices.DeleteFunc(slices.Clone(pods), func(pod string) bool {
		return strings.Contains(query, `pod="`) && !strings.Contains(query, fmt.Sprintf(`pod=%q`, pod))
	})

	for _, pod := range selected {
		for _, line := range runs[pod] {
			add(pod, at.UnixNano(), line)
		}
	}

	if len(selected) > 0 && selected[0] == pods[0] {
		for index, line := range older {
			add(pods[0], at.Add(-time.Duration(index+1)*time.Second).UnixNano(), line)
		}
	}

	streamsOut := make([]string, 0, len(selected))

	for _, pod := range selected {
		streamsOut = append(streamsOut, fmt.Sprintf(`{"stream":{"app":"nauthilus","namespace":"mail","pod":%q},"values":[%s]}`,
			pod, strings.Join(values[pod], ",")))
	}

	return `{"status":"success","data":{"resultType":"streams","result":[` + strings.Join(streamsOut, ",") + `]}}`
}

// runLines returns count distinct lines named after the pod.
func runLines(pod string, count int) []string {
	lines := make([]string, count)

	for index := range lines {
		lines[index] = fmt.Sprintf("%s-event-%05d", pod, index)
	}

	return lines
}

// TestLogEventsPageThroughARunLargerThanOneRead reproduces the final review: a run of more equal timestamps than the
// Loki entry bound ended without a line and without a cursor. Spread over streams that each fit one read, every line
// of the run and the older line must be reachable exactly once.
func TestLogEventsPageThroughARunLargerThanOneRead(t *testing.T) {
	at := testQuery().Now.Add(-time.Minute)
	runs := map[string][]string{"mx-1": runLines("mx-1", 3000), "mx-2": runLines("mx-2", 2600), "mx-3": runLines("mx-3", 10)}
	source := newTestSource(t, runLoki(at, runs, []string{"older-event"}), func(cfg *Config) { cfg.MaxResponseBytes = 8 << 20 })

	seen, gaps := pageAllEvents(t, source, eventsQuery(supportops.MaxLogEventPageLimit))
	counts := map[string]int{}

	for _, line := range seen {
		counts[strings.SplitN(line, "-event", 2)[0]]++
	}

	if len(seen) != 5611 || seen[0] != "mx-1-event-00000" || seen[len(seen)-1] != "older-event" || hasDuplicate(seen) || len(gaps) != 0 {
		t.Fatalf("lines = %d %v, first %q, last %q, duplicates %v, gaps %v", len(seen), counts, seen[0], seen[len(seen)-1], hasDuplicate(seen), gaps)
	}
}

// TestLogEventsStateAStreamRunNoReadReturns pins that one stream with more lines at one timestamp than one read is a
// stated gap with its labels, and that paging continues with the other streams and the older lines.
func TestLogEventsStateAStreamRunNoReadReturns(t *testing.T) {
	at := testQuery().Now.Add(-time.Minute)
	runs := map[string][]string{"mx-1": runLines("mx-1", supportops.MaxLogEventRead+3), "mx-2": runLines("mx-2", 4)}
	source := newTestSource(t, runLoki(at, runs, []string{"older-event"}), func(cfg *Config) { cfg.MaxResponseBytes = 8 << 20 })

	seen, gaps := pageAllEvents(t, source, eventsQuery(100))
	if len(gaps) != 1 || gaps[0].Labels["pod"] != "mx-1" || gaps[0].Reason != gapStreamRunExceedsRead || !gaps[0].At.Equal(at) {
		t.Fatalf("gaps = %+v", gaps)
	}

	if !slices.Equal(seen, append(runLines("mx-2", 4), "older-event")) {
		t.Fatalf("lines = %v", seen)
	}
}

// TestLogEventsOrderEqualLinesOfDifferentStreams reproduces the final review: equal time, instance, and line in two
// streams had no unique order, so a page boundary between them repeated one stream.
func TestLogEventsOrderEqualLinesOfDifferentStreams(t *testing.T) {
	at := testQuery().Now.Add(-time.Minute)
	stream := func(id string) windowsource.Stream {
		return windowsource.Stream{Labels: map[string]string{"pod": "mx-1", "stream_id": id},
			Entries: []windowsource.LogEntry{{At: at, Line: "same stored line"}}}
	}

	source := newTestSource(t, &fakeLoki{}, nil)
	query := eventsQuery(1)

	first, _, _ := source.pageLines(windowsource.StreamsResult{Streams: [][]windowsource.Stream{{stream("a"), stream("b")}}}, query, eventRead{fetch: 10})
	query.Position = *first.Next

	second, _, _ := source.pageLines(windowsource.StreamsResult{Streams: [][]windowsource.Stream{{stream("b"), stream("a")}}}, query, eventRead{fetch: 10})
	if first.Lines[0].Labels["stream_id"] == second.Lines[0].Labels["stream_id"] {
		t.Fatalf("one stream returned twice: %v then %v", first.Lines[0].Labels, second.Lines[0].Labels)
	}
}

// pageAllEvents follows the source position until the last page and returns every line in order and every gap.
func pageAllEvents(t *testing.T, source *Source, query supportops.LogEventsQuery) ([]string, []supportops.LogGap) {
	t.Helper()

	var (
		seen []string
		gaps []supportops.LogGap
	)

	for page := 0; page < 500; page++ {
		result := source.LogEvents(context.Background(), query)
		if result.Report.Status == supportops.SourceStatusUnavailable || result.Report.Status == supportops.SourceStatusTimeout {
			t.Fatalf("page %d report = %+v", page, result.Report)
		}

		for _, line := range result.Lines {
			seen = append(seen, line.Line)
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

// hasDuplicate reports whether a line appears twice.
func hasDuplicate(lines []string) bool {
	seen := make(map[string]struct{}, len(lines))

	for _, line := range lines {
		if _, ok := seen[line]; ok {
			return true
		}

		seen[line] = struct{}{}
	}

	return false
}

// TestLogEventsSwitchFromNormalPagesIntoTheRun pins the hand-over: a run that normal pages start into and that later
// outgrows one read continues stream by stream after the lines already returned, without a repeat or a gap.
func TestLogEventsSwitchFromNormalPagesIntoTheRun(t *testing.T) {
	at := testQuery().Now.Add(-time.Minute)
	runs := map[string][]string{"mx-1": runLines("mx-1", 2500), "mx-2": runLines("mx-2", 2300)}
	source := newTestSource(t, runLoki(at, runs, []string{"older-event"}), func(cfg *Config) { cfg.MaxResponseBytes = 8 << 20 })

	seen, gaps := pageAllEvents(t, source, eventsQuery(supportops.MaxLogEventPageLimit))
	if want := append(append(runLines("mx-1", 2500), runLines("mx-2", 2300)...), "older-event"); !slices.Equal(seen, want) || len(gaps) != 0 {
		t.Fatalf("lines = %d, gaps = %v", len(seen), gaps)
	}
}

// timedLine is one stored line of a single-stream fake.
type timedLine struct {
	at   time.Time
	line string
}

// singleStreamLoki serves one stream: its listing, backward reads newest first within [start, end) and limit, and
// probe reads whose line_format stage replaces every line.
func singleStreamLoki(entries []timedLine) *fakeLoki {
	return &fakeLoki{respond: func(request *http.Request) string {
		parameters := request.URL.Query()
		if strings.HasSuffix(request.URL.Path, "/series") {
			return `{"status":"success","data":[{"app":"nauthilus","namespace":"mail","pod":"mx-1"}]}`
		}

		if strings.Contains(parameters.Get("query"), "| logfmt") {
			return `{"status":"success","data":{"resultType":"streams","result":[]}}`
		}

		limit, _ := strconv.Atoi(parameters.Get("limit"))
		start, _ := strconv.ParseInt(parameters.Get("start"), 10, 64)
		end, _ := strconv.ParseInt(parameters.Get("end"), 10, 64)
		values := []string{}

		for _, entry := range entries {
			if stamp := entry.at.UnixNano(); stamp >= start && stamp < end && len(values) < limit {
				line := entry.line
				if strings.Contains(parameters.Get("query"), probeLine) {
					line = "-"
				}

				values = append(values, fmt.Sprintf(`[%q,%q]`, strconv.FormatInt(stamp, 10), line))
			}
		}

		return `{"status":"success","data":{"resultType":"streams","result":[{"stream":{"app":"nauthilus","namespace":"mail","pod":"mx-1"},"values":[` +
			strings.Join(values, ",") + `]}]}}`
	}}
}

// TestLogEventsContinuePastALineAboveTheByteBound reproduces the final review: a single stored line larger than the
// source byte bound ended the paging without a cursor. It must be a stated gap, and the older lines must follow.
func TestLogEventsContinuePastALineAboveTheByteBound(t *testing.T) {
	now := testQuery().Now
	entries := []timedLine{
		{now.Add(-time.Minute), `{"level":"WARN","msg":"newer"}`},
		{now.Add(-2 * time.Minute), `{"level":"WARN","msg":"` + strings.Repeat("x", 4096) + `"}`},
		{now.Add(-3 * time.Minute), `{"level":"WARN","msg":"older"}`},
	}
	source := newTestSource(t, singleStreamLoki(entries), func(cfg *Config) { cfg.MaxResponseBytes = 1024 })

	seen, gaps := pageAllEvents(t, source, eventsQuery(10))
	if !slices.Equal(seen, []string{entries[0].line, entries[2].line}) || len(gaps) != 1 ||
		gaps[0].Reason != gapLinesExceedByteBound || !gaps[0].At.Equal(entries[1].at) {
		t.Fatalf("lines = %v, gaps = %+v", seen, gaps)
	}
}

// TestLogEventsStateAnUnlistedRun pins the maintainer reproducer: when the stream listing fails for a run larger than
// one read, the run is one stated gap and paging continues with the older line instead of ending without a cursor.
func TestLogEventsStateAnUnlistedRun(t *testing.T) {
	at := testQuery().Now.Add(-time.Minute)
	source := newTestSource(t, tieLoki(at, runLines("mx-1", supportops.MaxLogEventRead), []string{"older-event"}),
		func(cfg *Config) { cfg.MaxResponseBytes = 8 << 20 })

	seen, gaps := pageAllEvents(t, source, eventsQuery(100))
	if len(gaps) != 1 || gaps[0].Reason != gapStreamsUnlisted || !slices.Equal(seen, []string{"older-event"}) {
		t.Fatalf("lines = %v, gaps = %+v", seen, gaps)
	}
}
