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

package prometheussource

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportops"
)

// hitFake answers the coverage query with one scrape sample every 30 seconds per instance and the Redis pool timeout
// query with the hits of each instance inside (t-range, t]; every other query has no samples. Ranges above bound
// are recorded.
func hitFake(t *testing.T, hits map[string][]time.Time, bound time.Duration) *fakePrometheus {
	t.Helper()

	return &fakePrometheus{respond: func(request *http.Request) string {
		query := request.URL.Query()
		at, _ := time.Parse(time.RFC3339Nano, query.Get("time"))
		span := time.Duration(queryRangeMillis(query.Get("query"))) * time.Millisecond

		if span > bound {
			t.Errorf("query over %v: %s", span, query.Get("query"))
		}

		pairs := []string{}

		for instance, times := range hits {
			switch querySymptom(query.Get("query")) {
			case coverageToken:
				pairs = append(pairs, instance, strconv.FormatInt(int64(span/(30*time.Second)), 10))
			case supportops.SymptomRedisPoolTimeouts:
				count := 0

				for _, hit := range times {
					if hit.After(at.Add(-span)) && !hit.After(at) {
						count++
					}
				}

				pairs = append(pairs, instance, strconv.Itoa(count))
			}
		}

		return vector(pairs...)
	}}
}

// TestTwelveHourDiagnosticsMatchTheirHours reproduces the clipping of a long window: with max_time_window 1h a
// twelve-hour diagnostics answer covered only its newest hour (PROMETHEUS_WINDOW_CLIPPED), while twelve hourly
// calls worked. The long window must be counted by parts of at most one hour each and equal the sum of its hours.
func TestTwelveHourDiagnosticsMatchTheirHours(t *testing.T) {
	until := time.Date(2026, time.November, 25, 16, 38, 0, 0, time.UTC)
	window := supportops.Window{From: until.Add(-12 * time.Hour), Until: until}
	hits := map[string][]time.Time{}

	for hour := range 12 {
		start := window.From.Add(time.Duration(hour) * time.Hour)
		hits["mx-1"] = append(hits["mx-1"], start.Add(time.Minute), start.Add(59*time.Minute))
		hits["mx-2"] = append(hits["mx-2"], start.Add(30*time.Minute))
	}

	source := newTestSource(t, hitFake(t, hits, time.Hour), nil)
	query := supportops.Query{Window: window, Now: until.Add(time.Minute), Components: []string{supportops.ComponentRedis}}

	long := source.Collect(context.Background(), query)
	if long.Report.Status != supportops.SourceStatusOK || long.Report.Code != "" || !long.Report.Coverage.From.Equal(window.From) {
		t.Fatalf("12h report = %+v", long.Report)
	}

	hourly := map[string]int64{}

	for hour := range 12 {
		query.Window = supportops.Window{From: window.From.Add(time.Duration(hour) * time.Hour), Until: window.From.Add(time.Duration(hour+1) * time.Hour)}

		for _, finding := range source.Collect(context.Background(), query).Findings {
			hourly[finding.Scope.Instance] += max(symptomCount(finding, supportops.SymptomRedisPoolTimeouts), 0)
		}
	}

	for instance, want := range map[string]int64{"mx-1": 24, "mx-2": 12} {
		got := symptomCount(findingFor(t, long, supportops.ComponentRedis, instance), supportops.SymptomRedisPoolTimeouts)
		if got != want || hourly[instance] != want {
			t.Fatalf("%s: 12h count %d, hourly sum %d, want %d", instance, got, hourly[instance], want)
		}
	}
}
