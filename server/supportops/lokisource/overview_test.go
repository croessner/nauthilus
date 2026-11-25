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

// overviewSample is one series of a fake instant answer with the overview label names.
type overviewSample struct {
	pod   string
	level string
	msg   string
	value string
}

// overviewVector renders a success vector answer of the samples.
func overviewVector(samples ...overviewSample) string {
	rendered := make([]string, 0, len(samples))

	for _, sample := range samples {
		rendered = append(rendered, fmt.Sprintf(`{"metric":{"pod":%q,%q:%q,%q:%q},"value":[1763452800.0,%q]}`, sample.pod,
			overviewLevelLabel, sample.level, overviewMessageLabel, sample.msg, sample.value))
	}

	return `{"status":"success","data":{"resultType":"vector","result":[` + strings.Join(rendered, ",") + `]}}`
}

// overviewFake answers the coverage query and one fixed answer per log format parser, the same for every bucket.
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
	store := &storeLoki{entries: []storeEntry{
		windowLine("mx-1", "WARN", "WebAuthn sign count anomaly", until.Add(-time.Nanosecond)),
		windowLine("mx-1", "WARN", "WebAuthn sign count anomaly", until.Add(-time.Second)),
		windowLine("mx-1", "WARN", "WebAuthn sign count anomaly", until.Add(-20*time.Minute)),
		windowLine("mx-1", "WARN", "WebAuthn sign count anomaly", until),
		logfmtLine("mx-2", "ERROR", "RBL check failed", until.Add(-15*time.Minute)),
		logfmtLine("mx-2", "ERROR", "RBL check failed", until.Add(-15*time.Minute+time.Second)),
		logfmtLine("mx-2", "ERROR", "RBL check failed", until.Add(-15*time.Minute+2*time.Second)),
		windowLine("mx-2", "ERROR", "LDAP connection error", until.Add(-time.Minute)),
		windowLine("mx-3", "INFO", "started", until.Add(-29*time.Minute)),
	}}

	result := newTestSource(t, store.fake(), nil).LogOverview(context.Background(), overviewQuery(warnAndError...))

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

// logfmtLine stores one distinct slog text line of pod at a time.
func logfmtLine(pod string, level string, message string, at time.Time) storeEntry {
	return storeEntry{labels: storeLabels(pod), ts: at.UnixNano(),
		line: fmt.Sprintf("time=%s level=%s msg=%q seq=%d", at.Format(time.RFC3339Nano), level, message, windowSequence.Add(1))}
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

// TestLogOverviewQueryBoundary pins the exact instant queries: fixed selector, a level prefilter from the fixed
// vocabulary, both log format parsers with dedicated label names, the bucket range in milliseconds, and an
// evaluation one nanosecond before every bucket end, so each count covers exactly its bucket.
func TestLogOverviewQueryBoundary(t *testing.T) {
	fake := overviewFake(overviewVector(), overviewVector())
	result := newTestSource(t, fake, nil).LogOverview(context.Background(), overviewQuery(supportops.LogLevelError))

	want := map[string]int{
		`sum by (pod) (count_over_time(` + testSelector + ` [1800000ms]))`: 1,
		`sum by (pod, nauthilus_level, nauthilus_msg) (count_over_time(` + testSelector +
			` |~ "\"level\":\"(ERROR)\"" | json nauthilus_level="level", nauthilus_msg="msg" | __error__="" | nauthilus_level=~"ERROR" [150000ms]))`: overviewBuckets,
		`sum by (pod, nauthilus_level, nauthilus_msg) (count_over_time(` + testSelector +
			` !~ "^\\s*\\{" |~ "(^|\\s)level=(ERROR)(\\s|$)" | logfmt nauthilus_level="level", nauthilus_msg="msg" | __error__="" | nauthilus_level=~"ERROR" [150000ms]))`: overviewBuckets,
	}
	ends := map[string]bool{}

	for _, bucket := range result.Buckets {
		ends[fmt.Sprint(bucket.Until.UnixNano()-1)] = true
	}

	for _, request := range fake.requests {
		query := request.URL.Query()
		if _, ok := want[query.Get("query")]; !ok || !strings.HasSuffix(request.URL.Path, "/query") || !ends[query.Get("time")] {
			t.Fatalf("unexpected request %s %v", request.URL.Path, query)
		}

		want[query.Get("query")]--
	}

	for query, missing := range want {
		if missing != 0 {
			t.Errorf("query sent %d times too few: %s", missing, query)
		}
	}
}

// TestLogOverviewFailuresAndBounds pins partial results for a failed parser query, truncation of the series bound,
// and unavailability without coverage.
func TestLogOverviewFailuresAndBounds(t *testing.T) {
	busy := overviewFake(overviewVector(overviewSample{pod: "mx-1", level: "WARN", msg: "rare", value: "1"}), `{"status":"error"}`)

	result := newTestSource(t, busy, func(cfg *Config) { cfg.MaxSeries = 3 }).LogOverview(context.Background(), overviewQuery())
	if result.Report.Status != supportops.SourceStatusPartial || result.Report.Code != "LOKI_QUERY_REJECTED" ||
		total(seriesFor(t, result, "rare").Counts) != overviewBuckets {
		t.Fatalf("a failed parser query must make the overview partial: %+v", result)
	}

	truncated := newTestSource(t, overviewFake(overviewVector(
		overviewSample{pod: "mx-1", level: "WARN", msg: "frequent", value: "9"},
		overviewSample{pod: "mx-1", level: "WARN", msg: "rare", value: "1"},
	), overviewVector()), func(cfg *Config) { cfg.MaxSeries = 1 })

	result = truncated.LogOverview(context.Background(), overviewQuery())
	if !result.Report.Truncated || result.Report.Status != supportops.SourceStatusPartial || len(result.Series) != 1 {
		t.Fatalf("a cut answer must be stated: %+v", result)
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

// TestLogOverviewUnavailable pins that an overview whose every count query failed is unavailable, never a quiet
// window.
func TestLogOverviewUnavailable(t *testing.T) {
	rejected := overviewFake(`{"status":"error"}`, `{"status":"error"}`)

	result := newTestSource(t, rejected, nil).LogOverview(context.Background(), overviewQuery())
	if result.Report.Status != supportops.SourceStatusUnavailable || result.Report.Code != "LOKI_QUERY_REJECTED" {
		t.Fatalf("all count queries failed = %+v", result.Report)
	}
}
