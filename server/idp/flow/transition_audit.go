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

var flowTransitionViolationTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "flow_transition_violation_total",
		Help: "Number of blocked invalid flow transitions.",
	},
	[]string{"flow", "from", "to", "action"},
)

var flowStaleIDTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "flow_stale_id_total",
		Help: "Number of stale or missing flow identifiers handled by recovery.",
	},
)

func reportTransitionViolation(transitionErr TransitionError) {
	flowTransitionViolationTotal.WithLabelValues(
		string(transitionErr.FlowType),
		string(transitionErr.From),
		string(transitionErr.To),
		string(transitionErr.Action),
	).Inc()
}

func reportStaleFlow(_ string) {
	flowStaleIDTotal.Inc()
}
