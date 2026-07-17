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

package stats

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestAuthenticationResponseTimeMetricContract fixes the public metric name and labels.
func TestAuthenticationResponseTimeMetricContract(t *testing.T) {
	metric := GetMetrics().GetAuthenticationResponseTimeSeconds()
	metric.WithLabelValues("http", "ok", "imap").Observe(0.02)

	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(metric)

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather authentication response metric: %v", err)
	}

	for _, family := range families {
		if family.GetName() != "authentication_response_time_seconds" {
			continue
		}

		metrics := family.GetMetric()
		if len(metrics) != 1 {
			t.Fatalf("metric family has %d series, want 1", len(metrics))
		}

		labels := metrics[0].GetLabel()
		wantLabels := []string{"outcome", "protocol", "transport"}

		if len(labels) != len(wantLabels) {
			t.Fatalf("metric labels = %d, want %d", len(labels), len(wantLabels))
		}

		for index, want := range wantLabels {
			if got := labels[index].GetName(); got != want {
				t.Fatalf("metric label %d = %q, want %q", index, got, want)
			}
		}

		buckets := metrics[0].GetHistogram().GetBucket()
		if len(buckets) != len(authenticationResponseTimeBuckets) {
			t.Fatalf("metric buckets = %d, want %d", len(buckets), len(authenticationResponseTimeBuckets))
		}

		for index, want := range authenticationResponseTimeBuckets {
			if got := buckets[index].GetUpperBound(); got != want {
				t.Fatalf("metric bucket %d = %v, want %v", index, got, want)
			}
		}

		return
	}

	t.Fatal("authentication_response_time_seconds metric family not gathered")
}
