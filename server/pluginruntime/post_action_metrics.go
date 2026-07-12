// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"time"

	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/prometheus/client_golang/prometheus"
)

type postActionPlanObserver interface {
	Observe(time.Duration, string)
}

// prometheusPostActionPlanObserver owns the aggregate plan histogram.
type prometheusPostActionPlanObserver struct {
	duration *prometheus.HistogramVec
}

// newPostActionPlanObserver creates the process-wide post-action plan metric observer.
func newPostActionPlanObserver() postActionPlanObserver {
	return &prometheusPostActionPlanObserver{
		duration: stats.GetMetrics().GetPostActionPlanDurationSeconds(),
	}
}

// Observe records one complete detached post-action plan execution.
func (o *prometheusPostActionPlanObserver) Observe(duration time.Duration, result string) {
	if o == nil || o.duration == nil {
		return
	}

	o.duration.WithLabelValues(result).Observe(duration.Seconds())
}
