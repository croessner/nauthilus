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
	"errors"
	"fmt"

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

type syncEffectProvider interface {
	Execute(context.Context, effectExecution) effectsupervisor.Result
}

type postActionProvider interface {
	Prepare(context.Context, effectExecution) (effectsupervisor.Work, error)
}

type syncEffectProviderCallCapturer interface {
	captureSyncEffectCall() (syncEffectProvider, error)
}

type postActionProviderCallCapturer interface {
	capturePostActionCall() (postActionProvider, error)
}

type syncEffectBinding struct {
	provider syncEffectProvider
}

type postActionBinding struct {
	provider postActionProvider
}

type effectExecution struct {
	facts      decision.FactSet
	caller     decision.CallerContext
	parameters decision.ValueMap
	target     decision.Target
	effectID   string
	decisionID string
	provider   string
	generation uint64
	ordinal    uint32
}

type plannedEffect struct {
	syncProvider syncEffectProvider
	postProvider postActionProvider
	definition   registry.EffectDefinition
	use          registry.EffectUse
	execution    effectExecution
}

type effectExecutionOutcome struct {
	state              effectsupervisor.State
	accepted           bool
	acceptanceRejected bool
}

type decisionSelection struct {
	obligations []registry.EffectUse
	advice      []registry.EffectUse
	policySet   string
	ruleName    string
	effect      decision.Effect
	code        decision.StatusCode
}

// finalizeSelection validates the full plan, executes host ownership, and builds the stable result.
func (r *checkpointRuntime) finalizeSelection(
	ctx context.Context,
	input checkpointEvaluation,
	target policyruntime.CompiledTarget,
	selection decisionSelection,
	decisionID string,
	requestID string,
	report runtimeReport,
) (decision.DecisionResponse, runtimeReport, bool) {
	report.policySet = selection.policySet
	report.rule = selection.ruleName
	report.outcomeCode = selection.code

	plan, projectedObligations, projectedAdvice, err := r.prepareEffects(
		input,
		target,
		decisionID,
		report.facts,
		selection.obligations,
		selection.advice,
	)
	if err != nil {
		appendSelectedUnstartedEffects(&report, target, selection.obligations)

		outcome := r.indeterminate(input, target, decisionID, requestID, decision.StatusCodeEvaluationFailed, report)

		return outcome.response, outcome.report.runtime, false
	}

	failureCode, failed := r.executePreparedEffects(ctx, input, plan, &report)
	if failed {
		outcome := r.indeterminate(input, target, decisionID, requestID, failureCode, report)

		return outcome.response, outcome.report.runtime, false
	}

	if ctx.Err() != nil {
		outcome := r.indeterminate(input, target, decisionID, requestID, decision.StatusCodeEvaluationFailed, report)

		return outcome.response, outcome.report.runtime, false
	}

	status, _ := decision.NewStatus(selection.code, safeStatusMessage(selection.effect), nil)
	metadata := policyMetadata(target, input.generation, selection.policySet, selection.ruleName)
	diagnostics := sanitizeDiagnostics(input.request, target, input.checkpoint.Name(), input.generation, selection.code, report)

	response, err := decision.NewDecisionResponse(decision.DecisionResponseInput{
		RequestID: requestID, DecisionID: decisionID, Effect: selection.effect, Status: status,
		Obligations: projectedObligations, Advice: projectedAdvice, Policy: metadata, Diagnostics: diagnostics,
	})
	if err != nil {
		outcome := r.indeterminate(input, target, decisionID, requestID, decision.StatusCodeEvaluationFailed, report)

		return outcome.response, outcome.report.runtime, false
	}

	return response, report, true
}

// projectDecisionSelection normalizes explicit rule and checkpoint fallback into one plan input.
func projectDecisionSelection(
	target policyruntime.CompiledTarget,
	checkpoint string,
	selected selectedRule,
) decisionSelection {
	effect, code := targetNoMatchProjection(target, checkpoint)
	result := decisionSelection{
		policySet: target.DefaultPolicySet().String(),
		effect:    effect,
		code:      code,
	}

	if !selected.matched {
		return result
	}

	result.effect = selected.rule.Decision()
	result.code = decisionCode(result.effect)
	result.policySet = selected.policySet
	result.ruleName = selected.rule.Name()
	result.obligations = selected.rule.Effects()
	result.advice = selected.rule.Advice()

	return result
}

// targetNoMatchProjection preserves neutral authn pre-auth and fail-closed final authority.
func targetNoMatchProjection(
	target policyruntime.CompiledTarget,
	checkpoint string,
) (decision.Effect, decision.StatusCode) {
	if target.Target().Namespace() != policy.AuthnNamespace {
		return noMatchProjection(target.NoMatch())
	}

	if checkpoint != string(policy.StageAuthDecision) {
		return decision.EffectNotApplicable, decision.StatusCodeNoApplicableRule
	}

	return decision.EffectDeny, decision.StatusCodeNoMatchDeny
}

// executePreparedEffects attempts every selected host effect at most once in policy order.
func (r *checkpointRuntime) executePreparedEffects(
	ctx context.Context,
	input checkpointEvaluation,
	plan []plannedEffect,
	report *runtimeReport,
) (decision.StatusCode, bool) {
	for index, planned := range plan {
		if ctx.Err() != nil {
			appendUnstartedPlannedEffects(report, plan[index:])

			return decision.StatusCodeEvaluationFailed, true
		}

		report.effects = append(report.effects, plannedEffectRecord(planned, effectsupervisor.StateAttempted))

		execution := r.executeEffect(ctx, input, planned)
		state := execution.state
		report.effects = append(report.effects, effectRecord{
			id: planned.definition.ID(), provider: planned.definition.Provider(), state: state, ordinal: planned.execution.ordinal,
		})

		if state == effectsupervisor.StateOutcomeUnknown {
			appendUnstartedPlannedEffects(report, plan[index+1:])

			return decision.StatusCodeEffectOutcomeUnknown, true
		}

		if state == effectsupervisor.StateFailed || !execution.accepted {
			appendUnstartedPlannedEffects(report, plan[index+1:])

			if execution.acceptanceRejected {
				return decision.StatusCodeEffectAcceptanceRejected, true
			}

			return decision.StatusCodeEvaluationFailed, true
		}

		if ctx.Err() != nil {
			appendUnstartedPlannedEffects(report, plan[index+1:])

			return decision.StatusCodeEvaluationFailed, true
		}
	}

	return "", false
}

// plannedEffectRecord projects one internal lifecycle state for a selected host effect.
func plannedEffectRecord(planned plannedEffect, state effectsupervisor.State) effectRecord {
	return effectRecord{
		id: planned.definition.ID(), provider: planned.definition.Provider(), state: state, ordinal: planned.execution.ordinal,
	}
}

// appendUnstartedPlannedEffects records selected host effects that never reached their owner.
func appendUnstartedPlannedEffects(report *runtimeReport, plan []plannedEffect) {
	for _, planned := range plan {
		report.effects = append(report.effects, plannedEffectRecord(planned, effectsupervisor.StateNotStarted))
	}
}

// appendSelectedUnstartedEffects records a validated selection when complete preparation fails.
func appendSelectedUnstartedEffects(
	report *runtimeReport,
	target policyruntime.CompiledTarget,
	uses []registry.EffectUse,
) {
	ordinal := uint32(0)

	for _, use := range uses {
		definition, ok := target.LookupEffect(use.ID())
		if !ok || definition.Execution() == registry.ExecutionReturnOnly {
			continue
		}

		ordinal++
		report.effects = append(report.effects, effectRecord{
			id: definition.ID(), provider: definition.Provider(), state: effectsupervisor.StateNotStarted, ordinal: ordinal,
		})
	}
}

// prepareEffects validates every selection and resolves its owner before execution starts.
func (r *checkpointRuntime) prepareEffects(
	input checkpointEvaluation,
	target policyruntime.CompiledTarget,
	decisionID string,
	facts decision.FactSet,
	obligations []registry.EffectUse,
	advice []registry.EffectUse,
) ([]plannedEffect, []decision.EffectRequest, []decision.EffectRequest, error) {
	plan := make([]plannedEffect, 0, len(obligations))
	projectedObligations := make([]decision.EffectRequest, 0, len(obligations))
	ordinal := uint32(0)

	for _, use := range obligations {
		planned, projected, hostOwned, err := r.prepareObligation(
			input,
			target,
			decisionID,
			facts,
			use,
			ordinal+1,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		if hostOwned {
			ordinal++

			plan = append(plan, planned)
		} else {
			projectedObligations = append(projectedObligations, projected)
		}
	}

	projectedAdvice, err := prepareAdvice(target, advice)
	if err != nil {
		return nil, nil, nil, err
	}

	return plan, projectedObligations, projectedAdvice, nil
}

// prepareObligation validates and captures one return-only or host-owned selection.
func (r *checkpointRuntime) prepareObligation(
	input checkpointEvaluation,
	target policyruntime.CompiledTarget,
	decisionID string,
	facts decision.FactSet,
	use registry.EffectUse,
	ordinal uint32,
) (plannedEffect, decision.EffectRequest, bool, error) {
	definition, ok := target.LookupEffect(use.ID())
	if !ok {
		return plannedEffect{}, decision.EffectRequest{}, false, fmt.Errorf("selected effect %s is absent", use.ID())
	}

	if err := definition.ValidateUse(use); err != nil {
		return plannedEffect{}, decision.EffectRequest{}, false, err
	}

	if definition.Execution() == registry.ExecutionReturnOnly {
		projected, err := projectEffectRequest(definition, use)

		return plannedEffect{}, projected, false, err
	}

	execution := effectExecution{
		facts: facts, caller: input.request.Caller(), parameters: use.Parameters(),
		target: target.Target(), effectID: definition.ID(), decisionID: decisionID,
		provider: definition.Provider(), generation: input.generation, ordinal: ordinal,
	}
	planned := plannedEffect{definition: definition, use: use, execution: execution}

	if err := r.bindHostEffect(input, &planned); err != nil {
		return plannedEffect{}, decision.EffectRequest{}, false, err
	}

	return planned, decision.EffectRequest{}, true, nil
}

// bindHostEffect resolves one exact owner without snapshotting mutable request state.
func (r *checkpointRuntime) bindHostEffect(
	input checkpointEvaluation,
	planned *plannedEffect,
) error {
	switch planned.definition.Execution() {
	case registry.ExecutionHostSync:
		binding, exists := r.syncEffects[planned.definition.Provider()]
		if !exists || binding.provider == nil {
			return fmt.Errorf("sync effect provider %s is absent", planned.definition.Provider())
		}

		planned.syncProvider = binding.provider

		return nil
	case registry.ExecutionHostPostAction:
		binding, exists := r.postActions[planned.definition.Provider()]
		if !exists || binding.provider == nil || !input.finalization.Valid() {
			return fmt.Errorf("post-action provider or finalization gate is absent")
		}

		planned.postProvider = binding.provider

		return nil
	default:
		return fmt.Errorf("effect execution class is invalid")
	}
}

// prepareAdvice validates and projects non-authoritative return-only selections.
func prepareAdvice(
	target policyruntime.CompiledTarget,
	advice []registry.EffectUse,
) ([]decision.EffectRequest, error) {
	projected := make([]decision.EffectRequest, 0, len(advice))

	for _, use := range advice {
		definition, ok := target.LookupEffect(use.ID())
		if !ok || definition.Kind() != registry.EffectKindAdvice || definition.Execution() != registry.ExecutionReturnOnly {
			return nil, fmt.Errorf("selected advice %s is invalid", use.ID())
		}

		if err := definition.ValidateUse(use); err != nil {
			return nil, err
		}

		request, err := projectEffectRequest(definition, use)
		if err != nil {
			return nil, err
		}

		projected = append(projected, request)
	}

	return projected, nil
}

// executeEffect transfers one selected host effect to its sole execution owner.
func (r *checkpointRuntime) executeEffect(
	ctx context.Context,
	input checkpointEvaluation,
	planned plannedEffect,
) effectExecutionOutcome {
	switch planned.definition.Execution() {
	case registry.ExecutionHostSync:
		result := make(chan effectsupervisor.Result, 1)

		provider, err := captureSyncEffectProvider(planned.syncProvider)
		if err != nil || nilDependency(provider) {
			return effectExecutionOutcome{state: effectsupervisor.StateFailed}
		}

		go executeSyncEffect(ctx, provider, planned.execution, result)

		select {
		case completed := <-result:
			return effectExecutionOutcome{
				state:    completed.State(),
				accepted: completed.State() == effectsupervisor.StateSucceeded,
			}
		case <-ctx.Done():
			return effectExecutionOutcome{state: effectsupervisor.StateOutcomeUnknown}
		}
	case registry.ExecutionHostPostAction:
		work, err := preparePostAction(ctx, planned.postProvider, planned.execution)
		if err != nil || nilDependency(work) {
			return effectExecutionOutcome{state: effectsupervisor.StateFailed}
		}

		plan, err := effectsupervisor.NewPlan(effectsupervisor.PlanInput{
			Gate: effectFinalizationGate{finalization: input.finalization}, Work: work,
			DecisionID: planned.execution.decisionID, Target: planned.execution.target.String(),
			Provider: planned.execution.provider, DeadlineBudget: r.postActionBudget,
			EffectOrdinal: planned.execution.ordinal,
			Observability: effectsupervisor.ObservabilityMetadata{RuntimeGeneration: input.generation, Source: "decision_service"},
		})
		if err != nil {
			releasePreparedWork(ctx, work)

			return effectExecutionOutcome{state: effectsupervisor.StateFailed}
		}

		if _, err = input.supervisor.Accept(ctx, plan); err != nil {
			releasePreparedWork(ctx, work)

			return effectExecutionOutcome{
				state:              effectsupervisor.StateFailed,
				acceptanceRejected: postActionAcceptanceRejected(err),
			}
		}

		return effectExecutionOutcome{state: effectsupervisor.StateAccepted, accepted: true}
	default:
		return effectExecutionOutcome{state: effectsupervisor.StateFailed}
	}
}

// postActionAcceptanceRejected excludes request cancellation from supervisor rejection.
func postActionAcceptanceRejected(err error) bool {
	return err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded)
}

type postActionPreparation struct {
	work effectsupervisor.Work
	err  error
}

// preparePostAction snapshots mutable request state at the selected post-action ordinal.
func preparePostAction(
	ctx context.Context,
	provider postActionProvider,
	execution effectExecution,
) (effectsupervisor.Work, error) {
	provider, err := capturePostActionProvider(provider)
	if err != nil || nilDependency(provider) {
		return nil, err
	}

	result := make(chan postActionPreparation)

	go func() {
		work, prepareErr := callPostActionPrepare(ctx, provider, execution)
		prepared := postActionPreparation{work: work, err: prepareErr}

		select {
		case result <- prepared:
		case <-ctx.Done():
			releasePreparedWork(ctx, work)
		}
	}()

	select {
	case prepared := <-result:
		return prepared.work, prepared.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// captureSyncEffectProvider reserves generation ownership before effect goroutines start.
func captureSyncEffectProvider(provider syncEffectProvider) (syncEffectProvider, error) {
	capturer, ok := provider.(syncEffectProviderCallCapturer)
	if !ok {
		return provider, nil
	}

	return capturer.captureSyncEffectCall()
}

// capturePostActionProvider reserves generation ownership before preparation goroutines start.
func capturePostActionProvider(provider postActionProvider) (postActionProvider, error) {
	capturer, ok := provider.(postActionProviderCallCapturer)
	if !ok {
		return provider, nil
	}

	return capturer.capturePostActionCall()
}

// callPostActionPrepare converts a provider panic into a preparation error.
func callPostActionPrepare(
	ctx context.Context,
	provider postActionProvider,
	execution effectExecution,
) (work effectsupervisor.Work, err error) {
	defer func() {
		if recover() != nil {
			work = nil
			err = fmt.Errorf("post-action preparation panicked")
		}
	}()

	return provider.Prepare(ctx, execution)
}

// executeSyncEffect contains provider panics and publishes at most one bounded result.
func executeSyncEffect(
	ctx context.Context,
	provider syncEffectProvider,
	execution effectExecution,
	result chan<- effectsupervisor.Result,
) {
	defer func() {
		if recover() != nil {
			result <- effectsupervisor.Failed("provider_panic")
		}
	}()

	result <- provider.Execute(ctx, execution)
}

// releasePreparedWork bounds idempotent pre-acceptance cleanup by evaluation cancellation.
func releasePreparedWork(ctx context.Context, work effectsupervisor.Work) {
	if nilDependency(work) {
		return
	}

	executable, ok := work.(effectsupervisor.ExecutableWork)
	if !ok || nilDependency(executable) {
		return
	}

	done := make(chan struct{})

	go cleanupPreparedWork(executable, done)

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// cleanupPreparedWork contains cleanup panics and always publishes completion.
func cleanupPreparedWork(work effectsupervisor.ExecutableWork, done chan<- struct{}) {
	defer func() {
		_ = recover()

		close(done)
	}()

	work.Cleanup()
}

type effectFinalizationGate struct {
	finalization decision.EvaluationFinalization
}

// Done exposes the host-created application finalization signal.
func (g effectFinalizationGate) Done() <-chan struct{} {
	return g.finalization.Done()
}

// Boundary maps the transport-neutral boundary into supervisor vocabulary.
func (g effectFinalizationGate) Boundary() effectsupervisor.Boundary {
	return effectsupervisor.Boundary(g.finalization.Boundary())
}

// projectEffectRequest creates one immutable return-only public selection.
func projectEffectRequest(
	definition registry.EffectDefinition,
	use registry.EffectUse,
) (decision.EffectRequest, error) {
	return decision.NewEffectRequest(decision.EffectRequestInput{ID: definition.ID(), Parameters: use.Parameters().Values()})
}

// decisionCode maps explicit rule outcomes to stable status taxonomy.
func decisionCode(effect decision.Effect) decision.StatusCode {
	switch effect {
	case decision.EffectPermit:
		return decision.StatusCodePermit
	case decision.EffectDeny:
		return decision.StatusCodePolicyDenied
	case decision.EffectNotApplicable:
		return decision.StatusCodeNoApplicableRule
	default:
		return decision.StatusCodeEvaluationFailed
	}
}

// noMatchProjection applies the target's explicit compiled fallback.
func noMatchProjection(noMatch registry.NoMatchBehavior) (decision.Effect, decision.StatusCode) {
	if noMatch == registry.NoMatchNotApplicable {
		return decision.EffectNotApplicable, decision.StatusCodeNoApplicableRule
	}

	return decision.EffectDeny, decision.StatusCodeNoMatchDeny
}

// cloneSyncEffectBindings copies one generation-owned synchronous binding map.
func cloneSyncEffectBindings(input map[string]syncEffectBinding) map[string]syncEffectBinding {
	result := make(map[string]syncEffectBinding, len(input))
	for id, binding := range input {
		result[id] = binding
	}

	return result
}

// clonePostActionBindings copies one generation-owned post-action binding map.
func clonePostActionBindings(input map[string]postActionBinding) map[string]postActionBinding {
	result := make(map[string]postActionBinding, len(input))
	for id, binding := range input {
		result[id] = binding
	}

	return result
}
