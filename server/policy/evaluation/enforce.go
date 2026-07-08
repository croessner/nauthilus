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

package evaluation

import (
	"context"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/observability"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	"go.opentelemetry.io/otel/attribute"
)

// EvaluateConfiguredPreAuth evaluates configured pre-auth policy rules in enforce mode.
func EvaluateConfiguredPreAuth(
	ctx context.Context,
	snapshot *policyruntime.Snapshot,
	policyReport *report.DecisionReport,
	input CompareInput,
) Result {
	return evaluateConfiguredEnforceStage(ctx, snapshot, policyReport, input, policy.StagePreAuth, configuredPreAuthEnabled, selectConfiguredPreAuth)
}

// EvaluateConfiguredAuth evaluates configured final auth rules in enforce mode.
func EvaluateConfiguredAuth(
	ctx context.Context,
	snapshot *policyruntime.Snapshot,
	policyReport *report.DecisionReport,
	input CompareInput,
) Result {
	return evaluateConfiguredEnforceStage(ctx, snapshot, policyReport, input, policy.StageAuthDecision, configuredAuthEnabled, selectConfiguredAuth)
}

type configuredStageEnabledFunc func(*policyruntime.Snapshot, policy.Operation) bool

type configuredStageSelector func(context.Context, *policyruntime.Snapshot, *report.DecisionReport, observability.Recorder, CompareInput) *report.FinalDecision

// evaluateConfiguredEnforceStage runs the shared configured-policy tracing and observability flow.
func evaluateConfiguredEnforceStage(
	ctx context.Context,
	snapshot *policyruntime.Snapshot,
	policyReport *report.DecisionReport,
	input CompareInput,
	stage policy.Stage,
	enabled configuredStageEnabledFunc,
	selectFinal configuredStageSelector,
) Result {
	ctx, policyReport, input = normalizeCompareInput(ctx, policyReport, input)
	if !enabled(snapshot, policyReport.Operation) {
		return Result{}
	}

	recorder := observability.SafeRecorder(input.Recorder)
	tracer := observability.NewTracer()
	start := time.Now()

	spanCtx, span := tracer.Start(ctx, "policy.evaluate")
	defer span.End()

	final := selectFinal(spanCtx, snapshot, policyReport, recorder, input)
	recordConfiguredDecision(spanCtx, recorder, input, policyReport.Operation, stage, final, time.Since(start))
	setConfiguredSpanAttributes(span, input, policyReport.Operation, stage, final)
	logConfiguredDecision(spanCtx, input, policyReport.Operation, final)

	return Result{Final: final}
}

func configuredPreAuthEnabled(snapshot *policyruntime.Snapshot, operation policy.Operation) bool {
	return configuredStageEnabled(snapshot, operation, policy.StagePreAuth)
}

func configuredAuthEnabled(snapshot *policyruntime.Snapshot, operation policy.Operation) bool {
	return configuredStageEnabled(snapshot, operation, policy.StageAuthDecision)
}

func configuredStageEnabled(snapshot *policyruntime.Snapshot, operation policy.Operation, stage policy.Stage) bool {
	if snapshot == nil || snapshot.Mode == modeObserve {
		return false
	}

	if snapshot.DefaultPolicy != "" && snapshot.DefaultPolicy != policy.BuiltinDefaultSet {
		return false
	}

	plan, ok := snapshot.StagePlans[operation][stage]

	return ok && len(plan.Policies) > 0
}

// selectConfiguredPreAuth chooses the first ready configured pre-auth policy decision.
func selectConfiguredPreAuth(
	ctx context.Context,
	snapshot *policyruntime.Snapshot,
	policyReport *report.DecisionReport,
	recorder observability.Recorder,
	input CompareInput,
) *report.FinalDecision {
	plan := snapshot.StagePlans[policyReport.Operation][policy.StagePreAuth]
	dependencies := checkDependencyMap(plan.Checks)

	for _, compiled := range plan.Policies {
		if !requiredChecksSatisfied(ctx, compiled, policyReport, recorder, input.Mode, dependencies) {
			continue
		}

		if !exprMatches(compiled.Root, policyReport) {
			continue
		}

		decision := reportDecisionFromCompiled(compiled, policyReport)
		appendConfiguredPreAuth(policyReport, decision)

		final := finalDecisionFromPolicy(decision)
		if terminalConfiguredDecision(final) || configuredPreAuthControl(final) {
			return final
		}

		return nil
	}

	return nil
}

// selectConfiguredAuth chooses the first ready configured auth decision or the configured default deny.
func selectConfiguredAuth(
	ctx context.Context,
	snapshot *policyruntime.Snapshot,
	policyReport *report.DecisionReport,
	recorder observability.Recorder,
	input CompareInput,
) *report.FinalDecision {
	plan := snapshot.StagePlans[policyReport.Operation][policy.StageAuthDecision]
	dependencies := checkDependencyMap(plan.Checks)

	for _, compiled := range plan.Policies {
		if !requiredChecksSatisfied(ctx, compiled, policyReport, recorder, input.Mode, dependencies) {
			continue
		}

		if !exprMatches(compiled.Root, policyReport) {
			continue
		}

		decision := reportDecisionFromCompiled(compiled, policyReport)
		appendConfiguredAuth(policyReport, decision)

		final := finalDecisionFromPolicy(decision)
		if terminalConfiguredDecision(final) {
			return final
		}
	}

	decision := configuredDefaultDenyDecision()
	appendConfiguredAuth(policyReport, decision)

	return finalDecisionFromPolicy(decision)
}

func appendConfiguredPreAuth(policyReport *report.DecisionReport, decision report.PolicyDecision) {
	policyReport.Policies = append(policyReport.Policies, decision)

	policyReport.Stage = decision.Stage
	if decision.Effect == policy.DecisionNeutral {
		return
	}

	policyReport.Final = finalDecisionFromPolicy(decision)
}

func appendConfiguredAuth(policyReport *report.DecisionReport, decision report.PolicyDecision) {
	policyReport.Policies = append(policyReport.Policies, decision)
	policyReport.Stage = decision.Stage
	policyReport.Final = finalDecisionFromPolicy(decision)
}

func configuredPreAuthControl(final *report.FinalDecision) bool {
	return final != nil &&
		final.Stage == policy.StagePreAuth &&
		final.Effect == policy.DecisionNeutral &&
		final.Control != nil &&
		final.Control.SkipRemainingStageChecks
}

func recordConfiguredDecision(
	ctx context.Context,
	recorder observability.Recorder,
	input CompareInput,
	operation policy.Operation,
	stage policy.Stage,
	final *report.FinalDecision,
	duration time.Duration,
) {
	recorder.RecordStageEvaluation(ctx, observability.StageMeasurement{
		Duration:  duration,
		Mode:      input.Mode,
		Operation: operation,
		Stage:     stage,
	})

	if final == nil {
		return
	}

	recorder.RecordDecision(ctx, observability.DecisionMeasurement{
		Mode:           input.Mode,
		PolicyName:     final.PolicyName,
		ResponseMarker: final.ResponseMarker,
		FSMEventMarker: final.FSMEventMarker,
		Operation:      operation,
		Stage:          final.Stage,
		Decision:       final.Effect,
	})
	recorder.RecordFSMTransition(ctx, observability.FSMMeasurement{
		Result:         observability.ResultSuccess,
		FSMEventMarker: final.FSMEventMarker,
		Operation:      operation,
		Stage:          final.Stage,
	})

	if input.Surface == "" {
		return
	}

	recorder.RecordResponseRender(ctx, observability.RendererMeasurement{
		Surface:        input.Surface,
		ResponseMarker: final.ResponseMarker,
		Result:         observability.ResultSuccess,
	})
}

func setConfiguredSpanAttributes(
	span interface{ SetAttributes(...attribute.KeyValue) },
	input CompareInput,
	operation policy.Operation,
	stage policy.Stage,
	final *report.FinalDecision,
) {
	attributes := []attribute.KeyValue{
		attribute.String("policy.mode", input.Mode),
		attribute.String("policy.operation", string(operation)),
		attribute.String("policy.stage", string(stage)),
		attribute.Int64("policy.snapshot_generation", int64(input.Generation)),
		attribute.Bool("policy.selected", final != nil),
	}
	if final != nil {
		attributes = append(attributes,
			attribute.String("policy.name", final.PolicyName),
			attribute.String("policy.decision", string(final.Effect)),
			attribute.String("policy.response_marker", final.ResponseMarker),
			attribute.String("policy.fsm_event_marker", final.FSMEventMarker),
		)
	}

	span.SetAttributes(attributes...)
}

func logConfiguredDecision(
	ctx context.Context,
	input CompareInput,
	operation policy.Operation,
	final *report.FinalDecision,
) {
	if final == nil {
		return
	}

	observability.LogDecision(ctx, input.Logger, observability.DecisionLogEntry{
		Mode:               input.Mode,
		Set:                input.Set,
		Name:               final.PolicyName,
		Reason:             final.Reason,
		ResponseMarker:     final.ResponseMarker,
		FSMEventMarker:     final.FSMEventMarker,
		Operation:          operation,
		Stage:              final.Stage,
		Decision:           final.Effect,
		SnapshotGeneration: input.Generation,
	})
}
