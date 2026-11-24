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

package core

import (
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/report"
)

// noteEnvironmentTrigger remembers which configured environment source triggered. A trigger is only a policy fact:
// it must not reject the request, so the rejection state waits for the selected decision.
func (e *authnCandidateExecution) noteEnvironmentTrigger(environmentName string) {
	if e.environmentTrigger == "" {
		e.environmentTrigger = environmentName
	}
}

// applyEnvironmentRejection marks the request as rejected by the triggering environment source once the policy
// selected a pre-auth deny. A permit, a tempfail, or a deny presented at a later stage leaves the request
// unmarked, so brute-force learning, Lua actions, plugin hooks, and request snapshots follow the policy decision.
// The caller holds e.mu.
func (e *authnCandidateExecution) applyEnvironmentRejection(final *report.FinalDecision) {
	if e.environmentTrigger == "" || final.Effect != policy.DecisionDeny || final.Stage != policy.StagePreAuth {
		return
	}

	e.auth.processEnvironmentAction(e.ginCtx, e.environmentTrigger)
	markEnvironmentRejected(e.ginCtx, true)
}
