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
	"context"

	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// AuthnTerminalCompletionResult is the bounded outcome vocabulary of one terminal post-action or of a completion
// that was skipped as a whole.
type AuthnTerminalCompletionResult string

const (
	// AuthnTerminalCompletionAccepted means the supervisor owns the post-action and runs it after finalization.
	AuthnTerminalCompletionAccepted AuthnTerminalCompletionResult = "accepted"

	// AuthnTerminalCompletionFailed means preparation or supervisor acceptance failed; the decision is unaffected.
	AuthnTerminalCompletionFailed AuthnTerminalCompletionResult = "failed"

	// AuthnTerminalCompletionDisabled means the request-local effect gate (observe mode) withholds every effect.
	AuthnTerminalCompletionDisabled AuthnTerminalCompletionResult = "disabled"

	// AuthnTerminalCompletionUnavailable means the session could not run a completion (closed, repeated, no host).
	AuthnTerminalCompletionUnavailable AuthnTerminalCompletionResult = "unavailable"

	// AuthnTerminalCompletionNoOutcome means the request ended without a sealed terminal outcome.
	AuthnTerminalCompletionNoOutcome AuthnTerminalCompletionResult = "no_outcome"

	// AuthnTerminalCompletionAdmissionRejected means the request was answered before a Policy session existed.
	AuthnTerminalCompletionAdmissionRejected AuthnTerminalCompletionResult = "admission_rejected"
)

// AuthnTerminalPostActionResult is the outcome of one declared terminal post-action.
type AuthnTerminalPostActionResult struct {
	PostAction string
	Result     AuthnTerminalCompletionResult
}

// AuthnTerminalCompletion reports one completion. Skipped is set when no declared post-action was attempted.
type AuthnTerminalCompletion struct {
	PostActions []AuthnTerminalPostActionResult
	Skipped     AuthnTerminalCompletionResult
}

// AuthnTerminalCompletionInput tells the session whether the host sealed a terminal outcome for this request.
type AuthnTerminalCompletionInput struct {
	OutcomeSealed bool
}

// AuthnTerminalCompletionSession runs a target's terminal post-actions once after the request outcome is fixed.
// Completion is best-effort: it never changes the answered decision, whatever the post-actions report.
type AuthnTerminalCompletionSession interface {
	CompleteAuthnTerminal(context.Context, AuthnTerminalCompletionInput) AuthnTerminalCompletion
}

// AuthnTerminalEffectsSource is the optional host gate for terminal post-actions. A host that does not implement it
// receives no completion, so effects stay withheld unless the host explicitly enables them.
type AuthnTerminalEffectsSource interface {
	AuthnTerminalEffectsEnabled(context.Context, decision.Target) bool
}

// authnTerminalCompleter is implemented by evaluators that can run target-declared terminal post-actions.
type authnTerminalCompleter interface {
	completeAuthnTerminal(context.Context, checkpointEvaluation, AuthnTerminalCompletionInput) AuthnTerminalCompletion
}

var _ AuthnTerminalCompletionSession = (*decisionSession)(nil)

// CompleteAuthnTerminal runs the declared terminal post-actions exactly once per session, after the last evaluation.
func (s *decisionSession) CompleteAuthnTerminal(
	ctx context.Context,
	input AuthnTerminalCompletionInput,
) AuthnTerminalCompletion {
	evaluation, ok := s.beginTerminalCompletion()
	if !ok {
		return AuthnTerminalCompletion{Skipped: AuthnTerminalCompletionUnavailable}
	}

	defer s.endEvaluation()

	completer, ok := s.generation.evaluator.(authnTerminalCompleter)
	if !ok {
		return AuthnTerminalCompletion{Skipped: AuthnTerminalCompletionUnavailable}
	}

	return completer.completeAuthnTerminal(normalizeContext(ctx), evaluation, input)
}

// beginTerminalCompletion claims the single completion slot and captures the terminal checkpoint inputs.
func (s *decisionSession) beginTerminalCompletion() (checkpointEvaluation, bool) {
	if s == nil {
		return checkpointEvaluation{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.evaluating || s.terminalCompleted || s.next == 0 || s.generation == nil || !s.generation.valid() {
		return checkpointEvaluation{}, false
	}

	s.terminalCompleted = true
	s.evaluating = true
	s.evaluations.Add(1)

	return checkpointEvaluation{
		request: s.request, facts: s.terminalFacts, finalization: s.finalization,
		supervisor: s.generation.supervisor, generation: s.generation.id,
	}, true
}

// completeAuthnTerminal prepares and hands every declared terminal post-action to the supervisor independently, so
// one failing post-action neither blocks the others nor reaches the answered decision.
func (r *checkpointRuntime) completeAuthnTerminal(
	ctx context.Context,
	input checkpointEvaluation,
	completion AuthnTerminalCompletionInput,
) AuthnTerminalCompletion {
	if r == nil || r.catalog == nil {
		return AuthnTerminalCompletion{Skipped: AuthnTerminalCompletionUnavailable}
	}

	target, ok := r.catalog.Lookup(input.request.Target())
	if !ok || target.Target().Namespace() != policy.AuthnNamespace || len(target.TerminalPostActions()) == 0 {
		return AuthnTerminalCompletion{}
	}

	switch {
	case !completion.OutcomeSealed:
		return AuthnTerminalCompletion{Skipped: AuthnTerminalCompletionNoOutcome}
	case !authnTerminalEffectsEnabled(ctx, target.Target()):
		return AuthnTerminalCompletion{Skipped: AuthnTerminalCompletionDisabled}
	case !input.finalization.Valid() || nilDependency(input.supervisor):
		return AuthnTerminalCompletion{Skipped: AuthnTerminalCompletionUnavailable}
	}

	uses := target.TerminalPostActions()

	decisionID, err := r.ids.Next("decision")
	if err != nil {
		return AuthnTerminalCompletion{Skipped: AuthnTerminalCompletionUnavailable}
	}

	completionContext, cancel := context.WithTimeout(ctx, r.evaluationTimeout)
	defer cancel()

	results := make([]AuthnTerminalPostActionResult, 0, len(uses))
	for index, use := range uses {
		result := r.completeTerminalPostAction(completionContext, input, target, decisionID, use, uint32(index+1))
		results = append(results, AuthnTerminalPostActionResult{PostAction: use.ID(), Result: result})
	}

	return AuthnTerminalCompletion{PostActions: results}
}

// completeTerminalPostAction prepares one declared post-action with the terminal facts and transfers it to the
// supervisor through the same binding and acceptance path as a rule-selected post-action.
func (r *checkpointRuntime) completeTerminalPostAction(
	ctx context.Context,
	input checkpointEvaluation,
	target policyruntime.CompiledTarget,
	decisionID string,
	use registry.EffectUse,
	ordinal uint32,
) AuthnTerminalCompletionResult {
	planned, _, hostOwned, err := r.prepareObligation(input, target, decisionID, input.facts, use, ordinal)
	if err != nil || !hostOwned {
		return AuthnTerminalCompletionFailed
	}

	// Best-effort acceptance keeps a flood of completions out of the capacity mandatory post-actions rely on.
	planned.bestEffort = true

	if outcome := r.executeEffect(ctx, input, planned); !outcome.accepted {
		return AuthnTerminalCompletionFailed
	}

	return AuthnTerminalCompletionAccepted
}

// authnTerminalEffectsEnabled asks the request-local host whether terminal post-actions may run.
func authnTerminalEffectsEnabled(ctx context.Context, target decision.Target) bool {
	source, ok := authnDecisionSourceFromContext(ctx).(AuthnTerminalEffectsSource)

	return ok && source.AuthnTerminalEffectsEnabled(ctx, target)
}

// withoutTerminalPostActions removes rule obligations owned by the target's terminal completion, so a rule that
// still names the same post-action neither produces a second execution nor makes it decision-relevant.
func withoutTerminalPostActions(
	target policyruntime.CompiledTarget,
	uses []registry.EffectUse,
) []registry.EffectUse {
	if len(uses) == 0 || len(target.TerminalPostActions()) == 0 {
		return uses
	}

	kept := make([]registry.EffectUse, 0, len(uses))
	for _, use := range uses {
		if !target.IsTerminalPostAction(use.ID()) {
			kept = append(kept, use)
		}
	}

	return kept
}
