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
	"context"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/policy/observability"
)

var _ decisionservice.AuthnTerminalEffectsSource = (*authnCandidateExecution)(nil)

// AuthnTerminalEffectsEnabled admits terminal post-actions for this run's own operation in enforce mode only, the
// same authority gate rule-selected effects pass, but independent of the checkpoint that answered the request.
func (e *authnCandidateExecution) AuthnTerminalEffectsEnabled(ctx context.Context, target decision.Target) bool {
	if e == nil || target.Action() != string(e.operation) {
		return false
	}

	mode, ok := decisionservice.CapturedPolicyMode(ctx)

	return ok && policyEffectsEnabled(mode)
}

// completeAuthnTerminal asks the session to run the target's terminal post-actions once after the outcome is known.
// It never touches the answered result; every attempted or skipped completion is recorded so gaps stay explainable.
func (e *authnCandidateExecution) completeAuthnTerminal(
	ctx context.Context,
	session decisionservice.DecisionSession,
	sealed bool,
) {
	if e == nil || e.auth == nil {
		return
	}

	completer, ok := session.(decisionservice.AuthnTerminalCompletionSession)
	if !ok {
		return
	}

	e.recordTerminalCompletion(ctx, completer.CompleteAuthnTerminal(ctx, decisionservice.AuthnTerminalCompletionInput{
		OutcomeSealed: sealed,
	}))
}

// recordTerminalCompletion counts every terminal post-action result and logs those that did not reach the supervisor.
func (e *authnCandidateExecution) recordTerminalCompletion(
	ctx context.Context,
	completion decisionservice.AuthnTerminalCompletion,
) {
	recorder := observability.DefaultRecorder()
	operation := string(e.operation)

	if completion.Skipped != "" {
		recorder.RecordTerminalPostAction(ctx, observability.TerminalPostActionMeasurement{
			Operation: operation, Result: string(completion.Skipped),
		})
		e.logTerminalCompletionGap("", completion.Skipped)

		return
	}

	for _, result := range completion.PostActions {
		recorder.RecordTerminalPostAction(ctx, observability.TerminalPostActionMeasurement{
			Operation: operation, PostAction: result.PostAction, Result: string(result.Result),
		})

		if result.Result != decisionservice.AuthnTerminalCompletionAccepted {
			e.logTerminalCompletionGap(result.PostAction, result.Result)
		}
	}
}

// recordTerminalCompletionAdmissionRejected counts a request answered before any Policy session existed. Such a
// request cannot run terminal post-actions, and starting more work under admission pressure would add load, so the
// gap is only made visible.
func recordTerminalCompletionAdmissionRejected(operation policy.Operation) {
	observability.DefaultRecorder().RecordTerminalPostAction(context.Background(), observability.TerminalPostActionMeasurement{
		Operation: string(operation), Result: string(decisionservice.AuthnTerminalCompletionAdmissionRejected),
	})
}

// logTerminalCompletionGap writes one bounded debug line naming the request and why its completion did not run. The
// metric is the authoritative signal; a per-request warning would itself flood the log during an attack.
func (e *authnCandidateExecution) logTerminalCompletionGap(
	postAction string,
	result decisionservice.AuthnTerminalCompletionResult,
) {
	level.Debug(e.auth.Logger()).Log(
		definitions.LogKeyGUID, e.auth.Runtime.GUID,
		definitions.LogKeyMsg, "Terminal post-action did not run",
		"terminal_post_action", postAction,
		"terminal_post_action_result", string(result),
	)
}
