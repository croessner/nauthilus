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
	"strings"

	"github.com/croessner/nauthilus/v4/server/conncause"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/report"

	"github.com/gin-gonic/gin"
)

// Bounded temporary-failure causes named by the terminal tempfail log line.
const (
	// tempFailReasonPolicyIndeterminate marks an authn policy checkpoint that could not decide reliably, for example
	// because a required fact provider failed or a rule selected a temporary failure.
	tempFailReasonPolicyIndeterminate = "policy_indeterminate"
	// tempFailReasonBackend marks a backend that settled without a result, for example because it was unreachable.
	// The checkpoint that reports it only skipped the providers depending on that result.
	tempFailReasonBackend = "backend_tempfail"
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
	// skippedProviders lists the provider instances that had no backend result to analyze.
	skippedProviders string
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

// withBackendFailure reattributes an indeterminate checkpoint to the backend that settled without a result. The
// checkpoint and status code stay as evidence of where the missing result surfaced.
func (c authTempFailCause) withBackendFailure(skippedProviders []string) authTempFailCause {
	c.reason = tempFailReasonBackend
	c.skippedProviders = strings.Join(skippedProviders, ",")

	return c
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
		{definitions.LogKeySkippedProviders, c.skippedProviders},
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

// recordTempFailError keeps the first technical error that can explain a temporary failure. Later errors and nil are
// ignored, so the root cause is not overwritten by follow-up failures.
func (a *AuthState) recordTempFailError(err error) {
	if a == nil || err == nil || a.Runtime.tempFailErr != nil {
		return
	}

	a.Runtime.tempFailErr = err
}

// tempFailErrorLogValues returns the recorded technical error as a structured log key/value pair, or nothing when
// the temporary failure has no technical error.
func (a *AuthState) tempFailErrorLogValues() []any {
	if a == nil || a.Runtime.tempFailErr == nil {
		return nil
	}

	return []any{definitions.LogKeyTempFailError, a.Runtime.tempFailErr.Error()}
}

// tempFailCancelDiagnostics classifies the recorded technical error against the own transport request context. The
// anchored transport context wins over the request context of ctx, which the application host derives for internal
// work.
func (a *AuthState) tempFailCancelDiagnostics(ctx *gin.Context) conncause.CancelDiagnostics {
	if a == nil || ctx == nil || ctx.Request == nil {
		return conncause.CancelDiagnostics{}
	}

	return conncause.DiagnoseCancel(conncause.OwnRequestContext(ctx.Request.Context()), a.Runtime.tempFailErr)
}
