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

package core

import (
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/report"
)

// Bounded temporary-failure causes named by the terminal tempfail log line.
const (
	// tempFailReasonPolicyIndeterminate marks an authn policy checkpoint that could not decide reliably, for example
	// because a required fact provider failed or a rule selected a temporary failure.
	tempFailReasonPolicyIndeterminate = "policy_indeterminate"
	// tempFailReasonAuthFSMGuard marks a permit the auth FSM guard rejected for missing host evidence.
	tempFailReasonAuthFSMGuard = "auth_fsm_guard"
	// tempFailReasonBruteForce marks a brute-force check that failed technically.
	tempFailReasonBruteForce = "brute_force_error"
	// tempFailReasonEnvironment marks an environment check that answered a temporary failure.
	tempFailReasonEnvironment = "environment_tempfail"
)

// authTempFailCause records why a request ends in a temporary failure. The client only sees the generic text, so the
// terminal tempfail log line carries this cause to make the decision traceable.
type authTempFailCause struct {
	reason     string
	checkpoint string
	statusCode string
	policySet  string
	policyRule string
	outcome    string
}

// newPolicyTempFailCause describes an indeterminate authn policy evaluation at one checkpoint.
func newPolicyTempFailCause(checkpoint string, response decision.DecisionResponse) authTempFailCause {
	return authTempFailCause{
		reason:     tempFailReasonPolicyIndeterminate,
		checkpoint: checkpoint,
		statusCode: string(response.Status().Code()),
		policySet:  response.Policy().PolicySet(),
		policyRule: response.Policy().Rule(),
	}
}

// withPresentation adds the rule and outcome marker of the enforced presentation; its rule supersedes the checkpoint
// metadata because the presentation is what the request answers with.
func (c authTempFailCause) withPresentation(presentation *report.FinalDecision) authTempFailCause {
	if presentation == nil {
		return c
	}

	if presentation.PolicyName != "" {
		c.policyRule = presentation.PolicyName
	}

	c.outcome = presentation.OutcomeMarker

	return c
}

// logValues returns the non-empty cause fields as structured log key/value pairs.
func (c authTempFailCause) logValues() []any {
	fields := []struct {
		key   string
		value string
	}{
		{definitions.LogKeyTempFailReason, c.reason},
		{definitions.LogKeyPolicyCheckpoint, c.checkpoint},
		{definitions.LogKeyPolicyStatusCode, c.statusCode},
		{definitions.LogKeyPolicySet, c.policySet},
		{definitions.LogKeyPolicyRule, c.policyRule},
		{definitions.LogKeyPolicyOutcome, c.outcome},
	}

	keyvals := make([]any, 0, 2*len(fields))

	for _, field := range fields {
		if field.value != "" {
			keyvals = append(keyvals, field.key, field.value)
		}
	}

	return keyvals
}

// recordTempFailCause stores the cause that the terminal tempfail log line reports.
func (a *AuthState) recordTempFailCause(cause authTempFailCause) {
	if a == nil {
		return
	}

	a.Runtime.tempFailCause = cause
}
