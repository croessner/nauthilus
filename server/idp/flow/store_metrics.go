// Copyright (C) 2025 Christian Rößner
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

package flow

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	flowMetricLabelBackend = "backend"
	flowMetricLabelResult  = "result"
)

var flowStoreReadTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "flow_store_read_total",
		Help: "Number of flow store read operations by backend and result.",
	},
	[]string{flowMetricLabelBackend, flowMetricLabelResult},
)

var flowStoreWriteTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "flow_store_write_total",
		Help: "Number of flow store write operations by backend and result.",
	},
	[]string{flowMetricLabelBackend, flowMetricLabelResult},
)

var flowStoreTouchTTLTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "flow_store_touch_ttl_total",
		Help: "Number of flow store TTL touch operations by backend and result.",
	},
	[]string{flowMetricLabelBackend, flowMetricLabelResult},
)

func reportStoreRead(backend, result string) {
	flowStoreReadTotal.WithLabelValues(backend, result).Inc()
}

func reportStoreWrite(backend, result string) {
	flowStoreWriteTotal.WithLabelValues(backend, result).Inc()
}

func reportStoreTouchTTL(backend, result string) {
	flowStoreTouchTTLTotal.WithLabelValues(backend, result).Inc()
}
