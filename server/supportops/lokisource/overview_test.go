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
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
)

// overviewSeries is one series of a fake range answer: its labels and its values per evaluation time.
type overviewSeries struct {
	values map[time.Time]string
	pod    string
	level  string
	msg    string
}

// matrix renders a success matrix answer of the series with the overview label names.
func matrix(series ...overviewSeries) string {
	rendered := make([]string, 0, len(series))

	for _, entry := range series {
		times := make([]time.Time, 0, len(entry.values))
		for at := range entry.values {
			times = append(times, at)
		}

		slices.SortFunc(times, func(left, right time.Time) int { return left.Compare(right) })

		points := make([]string, 0, len(times))
		for _, at := range times {
			points = append(points, fmt.Sprintf(`[%d,%q]`, at.Unix(), entry.values[at]))
		}

		rendered = append(rendered, fmt.Sprintf(`{"metric":{"pod":%q,%q:%q,%q:%q},"values":[%s]}`, entry.pod,
			overviewLevelLabel, entry.level, overviewMessageLabel, entry.msg, strings.Join(points, ",")))
	}

	return `{"status":"success","data":{"resultType":"matrix","result":[` + strings.Join(rendered, ",") + `]}}`
}

// overviewFake answers the coverage query and one range answer per log format parser.
func overviewFake(json string, logfmt string) *fakeLoki {
	return &fakeLoki{answers: map[string]string{"": vector("mx-1", "500", "mx-2", "300", "mx-3", "200"),
		"| json": json, "| logfmt": logfmt}}
}

// overviewQuery asks for warnings and errors of the last 30 minutes.
func overviewQuery(levels ...string) supportops.LogOverviewQuery {
	base := testQuery()

	return supportops.LogOverviewQuery{Window: base.Window, Now: base.Now, Levels: levels}
}

// TestLogOverviewReportsUnprofiledWarningsAndErrors reproduces the coverage gap: the compiled profile counts eight
// fixed messages, so RBL failures and WebAuthn warnings stayed invisible. The overview must return every warning and
// error message group per instance with its bucketed counts, whatever the log format, and keep the profile symptom of
// a profiled message.
func TestLogOverviewReportsUnprofiledWarningsAndErrors(t *testing.T) {
	until := testQuery().Window.Until
	fake := overviewFake(
		matrix(overviewSeries{pod: "mx-1", level: "WARN", msg: "WebAuthn sign count anomaly",
			values: map[time.Time]string{until: "2", until.Add(-20 * time.Minute): "1"}}),
		matrix(overviewSeries{pod: "mx-2", level: "ERROR", msg: "RBL check failed",
			values: map[time.Time]string{until.Add(-15 * time.Minute): "3"}},
			overviewSeries{pod: "mx-2", level: "ERROR", msg: "LDAP connection error",
				values: map[time.Time]string{until: "4"}}),
	)

	result := newTestSource(t, fake, nil).LogOverview(context.Background(), overviewQuery())

	assertFullOverviewGrid(t, result, until)

	if webauthn := seriesFor(t, result, "WebAuthn sign count anomaly"); webauthn.Instance != "mx-1" ||
		webauthn.Level != supportops.LogLevelWarn || !slices.Equal(webauthn.Counts[len(webauthn.Counts)-3:], []int64{0, 0, 2}) ||
		total(webauthn.Counts) != 3 || webauthn.Symptom != "" {
		t.Fatalf("webauthn = %+v", webauthn)
	}

	if rbl := seriesFor(t, result, "RBL check failed"); rbl.Instance != "mx-2" || rbl.Level != supportops.LogLevelError ||
		total(rbl.Counts) != 3 {
		t.Fatalf("rbl = %+v", rbl)
	}

	if ldap := seriesFor(t, result, "LDAP connection error"); ldap.Symptom != supportops.SymptomLDAPConnectionError ||
		ldap.Component != supportops.ComponentLDAP {
		t.Fatalf("a profiled message must keep its symptom: %+v", ldap)
	}
}

// assertFullOverviewGrid checks a complete report over all three instances and the 30-minute grid ending at until.
func assertFullOverviewGrid(t *testing.T, result supportops.LogOverviewSourceResult, until time.Time) {
	t.Helper()

	if result.Report.Status != supportops.SourceStatusOK || result.Report.Truncated ||
		!slices.Equal(result.Report.Coverage.Instances, []string{"mx-1", "mx-2", "mx-3"}) {
		t.Fatalf("report = %+v", result.Report)
	}

	if len(result.Buckets) != overviewBuckets || !result.Buckets[len(result.Buckets)-1].Until.Equal(until) ||
		!result.Buckets[0].From.Equal(until.Add(-30*time.Minute)) {
		t.Fatalf("buckets = %+v", result.Buckets)
	}
}

// TestLogOverviewQueryBoundary pins the exact range queries: fixed selector, a level prefilter from the fixed
// vocabulary, both log format parsers with dedicated label names, and the bucket step.
func TestLogOverviewQueryBoundary(t *testing.T) {
	fake := overviewFake(matrix(), matrix())
	newTestSource(t, fake, nil).LogOverview(context.Background(), overviewQuery(supportops.LogLevelError))

	want := map[string]bool{
		`sum by (pod) (count_over_time(` + testSelector + ` [1800s]))`: false,
		`sum by (pod, nauthilus_level, nauthilus_msg) (count_over_time(` + testSelector +
			` |~ "\"level\":\"(ERROR)\"" | json nauthilus_level="level", nauthilus_msg="msg" | __error__="" | nauthilus_level=~"ERROR" [150s]))`: false,
		`sum by (pod, nauthilus_level, nauthilus_msg) (count_over_time(` + testSelector +
			` !~ "^\\s*\\{" |~ "(^|\\s)level=(ERROR)(\\s|$)" | logfmt nauthilus_level="level", nauthilus_msg="msg" | __error__="" | nauthilus_level=~"ERROR" [150s]))`: false,
	}

	for _, request := range fake.requests {
		query := request.URL.Query()
		if _, ok := want[query.Get("query")]; !ok {
			t.Fatalf("unexpected query %q", query.Get("query"))
		}

		want[query.Get("query")] = true

		if strings.HasSuffix(request.URL.Path, "/query_range") && (query.Get("step") != "150" ||
			query.Get("end") != fmt.Sprint(testQuery().Window.Until.UnixNano())) {
			t.Fatalf("range parameters = %v", query)
		}
	}

	for query, seen := range want {
		if !seen {
			t.Errorf("query never sent: %s", query)
		}
	}
}

// TestLogOverviewFailuresAndBounds pins partial results for a failed parser query, truncation of the series bound
// with the most frequent groups kept, and unavailability without coverage.
func TestLogOverviewFailuresAndBounds(t *testing.T) {
	until := testQuery().Window.Until
	busy := overviewFake(matrix(
		overviewSeries{pod: "mx-1", level: "WARN", msg: "rare", values: map[time.Time]string{until: "1"}},
		overviewSeries{pod: "mx-1", level: "WARN", msg: "frequent", values: map[time.Time]string{until: "9"}},
	), `{"status":"error"}`)

	result := newTestSource(t, busy, func(cfg *Config) { cfg.MaxSeries = 3 }).LogOverview(context.Background(), overviewQuery())
	if result.Report.Status != supportops.SourceStatusPartial || result.Report.Code != "LOKI_QUERY_REJECTED" {
		t.Fatalf("a failed parser query must make the overview partial: %+v", result.Report)
	}

	truncated := newTestSource(t, overviewFake(matrix(
		overviewSeries{pod: "mx-1", level: "WARN", msg: "rare", values: map[time.Time]string{until: "1"}},
		overviewSeries{pod: "mx-1", level: "WARN", msg: "frequent", values: map[time.Time]string{until: "9"}},
	), matrix()), func(cfg *Config) { cfg.MaxSeries = 1 })

	result = truncated.LogOverview(context.Background(), overviewQuery())
	if !result.Report.Truncated || len(result.Series) != 1 || result.Series[0].Message != "frequent" {
		t.Fatalf("truncation must keep the most frequent group: %+v", result)
	}

	outage := newTestSource(t, &fakeLoki{status: http.StatusBadGateway}, nil).LogOverview(context.Background(), overviewQuery())
	if outage.Report.Status != supportops.SourceStatusUnavailable || len(outage.Series) != 0 {
		t.Fatalf("outage = %+v", outage)
	}
}

// seriesFor returns the overview series of one message.
func seriesFor(t *testing.T, result supportops.LogOverviewSourceResult, message string) supportops.LogSeries {
	t.Helper()

	for _, series := range result.Series {
		if series.Message == message {
			return series
		}
	}

	t.Fatalf("no series for %q in %+v", message, result.Series)

	return supportops.LogSeries{}
}

// total sums bucket counts.
func total(counts []int64) int64 {
	var sum int64

	for _, count := range counts {
		sum += count
	}

	return sum
}

// TestLogOverviewUnavailableAndMisaligned pins that an overview whose every range query failed is unavailable, never a
// quiet window, and that a point off the bucket grid (an aligning query frontend) is dropped with a partial status.
func TestLogOverviewUnavailableAndMisaligned(t *testing.T) {
	rejected := overviewFake(`{"status":"error"}`, `{"status":"error"}`)

	result := newTestSource(t, rejected, nil).LogOverview(context.Background(), overviewQuery())
	if result.Report.Status != supportops.SourceStatusUnavailable || result.Report.Code != "LOKI_QUERY_REJECTED" {
		t.Fatalf("all range queries failed = %+v", result.Report)
	}

	until := testQuery().Window.Until
	shifted := overviewFake(matrix(overviewSeries{pod: "mx-1", level: "WARN", msg: "shifted",
		values: map[time.Time]string{until: "1", until.Add(-75 * time.Second): "4"}}), matrix())

	result = newTestSource(t, shifted, nil).LogOverview(context.Background(), overviewQuery())
	if result.Report.Status != supportops.SourceStatusPartial || result.Report.Code != "LOKI_BUCKETS_MISALIGNED" ||
		total(seriesFor(t, result, "shifted").Counts) != 1 {
		t.Fatalf("misaligned = %+v %+v", result.Report, result.Series)
	}
}
