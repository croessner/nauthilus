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

package service

import (
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
)

type checkpointEvaluation struct {
	request      decision.DecisionRequest
	checkpoint   decision.Checkpoint
	finalization decision.EvaluationFinalization
	supervisor   effectsupervisor.Acceptor
	generation   uint64
}

type runtimeEvaluation struct {
	response decision.DecisionResponse
	report   internalDecisionReport
}

type internalDecisionReport struct {
	checkpoint string
	generation uint64
	runtime    runtimeReport
}

// valid reports whether runtime input retains the admitted request and generation authorities.
func (e checkpointEvaluation) valid() bool {
	return e.request.Target().String() != "" &&
		e.checkpoint.Name() != "" &&
		!nilDependency(e.supervisor) &&
		e.generation > 0
}

// valid reports whether runtime output is safe to cross the application boundary.
func (r runtimeEvaluation) valid(generation uint64, checkpoint string) bool {
	return r.response.Effect().Valid() &&
		r.response.RequestID().String() != "" &&
		r.response.DecisionID().String() != "" &&
		r.response.Status().Code() != "" &&
		r.response.Policy().Generation() == generation &&
		r.report.generation == generation &&
		r.report.checkpoint == checkpoint
}
