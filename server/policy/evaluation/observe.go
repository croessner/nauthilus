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
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/policy"
	policyfsm "github.com/croessner/nauthilus/server/policy/fsm"
	"github.com/croessner/nauthilus/server/policy/observability"
	"github.com/croessner/nauthilus/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"

	"go.opentelemetry.io/otel/attribute"
)

const (
	customDefaultDenyPolicy = "custom_default_deny"
	modeObserve             = "observe"
	requireResultMissing    = "missing"
	operatorGT              = "gt"
	operatorGTE             = "gte"
	operatorLT              = "lt"
	operatorLTE             = "lte"
)

// CompareCustomObserve compares configured policy output with the authoritative default set.
func CompareCustomObserve(
	ctx context.Context,
	snapshot *policyruntime.Snapshot,
	policyReport *report.DecisionReport,
	input CompareInput,
) CompareResult {
	ctx, policyReport, input = normalizeCompareInput(ctx, policyReport, input)
	if !customObserveEnabled(snapshot, policyReport.Operation) {
		return CompareResult{}
	}

	input.Mode = modeObserve
	recorder := observability.SafeRecorder(input.Recorder)
	tracer := observability.NewTracer()
	spanCtx, span := tracer.Start(ctx, "policy.observe.compare")
	defer span.End()

	defaultResult := EvaluateStandardAuth(policyReport)
	if defaultResult.Final == nil {
		return CompareResult{}
	}

	unavailable := markUnavailableCustomOnlyChecks(spanCtx, recorder, snapshot, policyReport)
	customFinal := evaluateConfiguredPolicySet(spanCtx, snapshot, policyReport, recorder, input)
	mismatchType, mismatch := compareObserveDecisions(defaultResult.Final, customFinal)
	policyReport.Observe = customObserveReport(defaultResult.Final, customFinal, input.Production.Surface, mismatchType, mismatch)
	recordCustomComparison(spanCtx, recorder, policyReport.Operation, customFinal, input.Production.Surface, mismatchType, mismatch)
	setCustomCompareSpanAttributes(span, input, policyReport.Operation, defaultResult.Final, customFinal, mismatchType, mismatch, unavailable)
	logCustomObserveMismatch(spanCtx, input, policyReport.Operation, defaultResult.Final, customFinal, mismatchType, mismatch)

	return CompareResult{
		Shadow:       customFinal,
		Production:   cloneFinal(defaultResult.Final),
		MismatchType: mismatchType,
		Mismatch:     mismatch,
	}
}

func customObserveEnabled(snapshot *policyruntime.Snapshot, operation policy.Operation) bool {
	if snapshot == nil || snapshot.Mode != modeObserve {
		return false
	}

	if snapshot.DefaultPolicy != "" && snapshot.DefaultPolicy != policy.BuiltinDefaultSet {
		return false
	}

	return hasConfiguredPolicies(snapshot.StagePlans, operation)
}

func hasConfiguredPolicies(
	stagePlans map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan,
	operation policy.Operation,
) bool {
	for _, plan := range stagePlans[operation] {
		if len(plan.Policies) > 0 {
			return true
		}
	}

	return false
}

func markUnavailableCustomOnlyChecks(
	ctx context.Context,
	recorder observability.Recorder,
	snapshot *policyruntime.Snapshot,
	policyReport *report.DecisionReport,
) []string {
	if snapshot == nil || policyReport == nil {
		return nil
	}

	var unavailable []string
	for _, check := range operationChecks(snapshot, policyReport.Operation) {
		if check.Name == "" || observeCheckSafe(snapshot, check) {
			continue
		}

		if _, exists := policyReport.Checks[check.Name]; exists {
			continue
		}

		if _, exists := policyReport.Unavailable[check.Name]; exists {
			continue
		}

		if policyReport.Unavailable == nil {
			policyReport.Unavailable = make(map[string]report.UnavailableFact)
		}

		policyReport.Unavailable[check.Name] = report.UnavailableFact{Name: check.Name, Reason: "not_observe_safe"}
		recorder.RecordObserveUnavailable(ctx, observability.ObserveUnavailableMeasurement{
			Operation:  policyReport.Operation,
			Stage:      check.Stage,
			Check:      check.Name,
			ReasonCode: "not_observe_safe",
		})
		unavailable = append(unavailable, check.Name)
	}

	sort.Strings(unavailable)

	return unavailable
}

func operationChecks(snapshot *policyruntime.Snapshot, operation policy.Operation) []policyruntime.CompiledCheck {
	if snapshot == nil {
		return nil
	}

	stages := snapshot.StagePlans[operation]
	checks := make([]policyruntime.CompiledCheck, 0)
	for _, plan := range stages {
		checks = append(checks, plan.Checks...)
	}

	return checks
}

func observeCheckSafe(snapshot *policyruntime.Snapshot, check policyruntime.CompiledCheck) bool {
	if check.ObserveSafe {
		return true
	}

	if snapshot == nil {
		return false
	}

	definition, ok := snapshot.CheckTypeRegistry[check.Type]

	return ok && definition.ObserveSafeDefault
}

func evaluateConfiguredPolicySet(
	ctx context.Context,
	snapshot *policyruntime.Snapshot,
	policyReport *report.DecisionReport,
	recorder observability.Recorder,
	input CompareInput,
) *report.FinalDecision {
	if policyReport.Operation == "" {
		policyReport.Operation = policy.OperationAuthenticate
	}

	for _, stage := range orderedStages(policyReport.Operation) {
		plan, ok := snapshot.StagePlans[policyReport.Operation][stage]
		if !ok || len(plan.Policies) == 0 {
			continue
		}

		start := time.Now()
		decision := evaluateConfiguredStage(ctx, plan.Policies, policyReport, recorder, input)
		recorder.RecordStageEvaluation(ctx, observability.StageMeasurement{
			Duration:  time.Since(start),
			Mode:      modeObserve,
			Operation: policyReport.Operation,
			Stage:     stage,
		})
		if decision == nil {
			continue
		}

		recorder.RecordDecision(ctx, observability.DecisionMeasurement{
			Mode:           modeObserve,
			PolicyName:     decision.PolicyName,
			ResponseMarker: decision.ResponseMarker,
			FSMEventMarker: decision.FSMEventMarker,
			Operation:      policyReport.Operation,
			Stage:          decision.Stage,
			Decision:       decision.Effect,
		})

		if terminalConfiguredDecision(decision) {
			return decision
		}
	}

	return configuredDefaultDeny()
}

func orderedStages(operation policy.Operation) []policy.Stage {
	if operation == policy.OperationListAccounts {
		return []policy.Stage{policy.StagePreAuth, policy.StageAccountProvider, policy.StageAuthDecision}
	}

	return []policy.Stage{
		policy.StagePreAuth,
		policy.StageAuthBackend,
		policy.StageAuthFilters,
		policy.StageAuthDecision,
	}
}

func evaluateConfiguredStage(
	ctx context.Context,
	policies []policyruntime.CompiledPolicy,
	policyReport *report.DecisionReport,
	recorder observability.Recorder,
	input CompareInput,
) *report.FinalDecision {
	for _, compiled := range policies {
		if !requiredChecksSatisfied(ctx, compiled, policyReport, recorder, input.Mode) {
			continue
		}

		if !exprMatches(compiled.Root, policyReport) {
			continue
		}

		decision := reportDecisionFromCompiled(compiled, policyReport)

		return finalDecisionFromPolicy(decision)
	}

	return nil
}

func requiredChecksSatisfied(
	ctx context.Context,
	compiled policyruntime.CompiledPolicy,
	policyReport *report.DecisionReport,
	recorder observability.Recorder,
	mode string,
) bool {
	if mode == "" {
		mode = modeObserve
	}

	satisfied := true
	for _, name := range compiled.RequireChecks {
		result := requireCheckResult(name, policyReport)
		recorder.RecordRequireCheck(ctx, observability.RequireCheckMeasurement{
			Mode:       mode,
			PolicyName: compiled.Name,
			Check:      name,
			Result:     result,
			Operation:  policyReport.Operation,
			Stage:      compiled.Stage,
		})
		if result != "satisfied" {
			satisfied = false
		}
	}

	return satisfied
}

func requireCheckResult(name string, policyReport *report.DecisionReport) string {
	if policyReport == nil {
		return requireResultMissing
	}

	if _, exists := policyReport.Unavailable[name]; exists {
		return "unavailable"
	}

	check, exists := policyReport.Checks[name]
	if !exists {
		return requireResultMissing
	}

	switch check.Status {
	case policy.CheckStatusOK, policy.CheckStatusError:
		return "satisfied"
	case policy.CheckStatusSkipped:
		return "skipped"
	default:
		return requireResultMissing
	}
}

func terminalConfiguredDecision(decision *report.FinalDecision) bool {
	if decision == nil {
		return false
	}

	if decision.Stage == policy.StagePreAuth {
		return decision.Effect == policy.DecisionDeny || decision.Effect == policy.DecisionTempFail
	}

	if decision.Stage == policy.StageAuthDecision {
		return decision.Effect == policy.DecisionDeny ||
			decision.Effect == policy.DecisionTempFail ||
			decision.Effect == policy.DecisionPermit
	}

	return false
}

func configuredDefaultDeny() *report.FinalDecision {
	return finalDecisionFromPolicy(configuredDefaultDenyDecision())
}

func configuredDefaultDenyDecision() report.PolicyDecision {
	return report.PolicyDecision{
		Name:            customDefaultDenyPolicy,
		Stage:           policy.StageAuthDecision,
		Effect:          policy.DecisionDeny,
		OutcomeMarker:   "auth.outcome.default_deny",
		FSMEventMarker:  policy.FSMEventMarkerAuthDeny,
		ResponseMarker:  policy.ResponseMarkerFail,
		ResponseMessage: defaultResponseMessage(policy.ResponseMarkerFail),
	}
}

func reportDecisionFromCompiled(
	compiled policyruntime.CompiledPolicy,
	policyReport *report.DecisionReport,
) report.PolicyDecision {
	return report.PolicyDecision{
		Name:            compiled.Name,
		Stage:           compiled.Stage,
		Effect:          compiled.Then.Decision,
		Reason:          compiled.Then.Reason,
		OutcomeMarker:   compiled.Then.OutcomeMarker,
		FSMEventMarker:  compiled.Then.FSMEventMarker,
		ResponseMarker:  compiled.Then.ResponseMarker,
		ResponseMessage: responseMessageFromPlan(compiled.Then.ResponseMessage, compiled.Then.ResponseMarker, policyReport),
		Control:         decisionControlFromPlan(compiled.Then.Control),
		Obligations:     effectRequestsFromPlan(compiled.Then.Obligations),
		Advice:          effectRequestsFromPlan(compiled.Then.Advice),
	}
}

func decisionControlFromPlan(control policyruntime.DecisionControl) *report.DecisionControl {
	if !control.SkipRemainingStageChecks {
		return nil
	}

	return &report.DecisionControl{SkipRemainingStageChecks: true}
}

func effectRequestsFromPlan(requests []policyruntime.EffectRequest) []report.EffectRequest {
	converted := make([]report.EffectRequest, 0, len(requests))
	for _, request := range requests {
		args := make(map[string]any, len(request.Args))
		for key, value := range request.Args {
			args[key] = value
		}

		converted = append(converted, report.EffectRequest{ID: request.ID, Args: args})
	}

	return converted
}

func responseMessageFromPlan(
	plan policyruntime.ResponseMessagePlan,
	responseMarker string,
	policyReport *report.DecisionReport,
) *report.ResponseMessageSelection {
	switch plan.Source {
	case "literal":
		return &report.ResponseMessageSelection{
			Source:  "literal",
			Message: sanitizeResponseMessage(plan.Literal, plan.MaxLength),
		}
	case "attribute_detail":
		return attributeDetailMessage(plan, policyReport, responseMarker)
	default:
		return defaultResponseMessage(responseMarker)
	}
}

func attributeDetailMessage(
	plan policyruntime.ResponseMessagePlan,
	policyReport *report.DecisionReport,
	responseMarker string,
) *report.ResponseMessageSelection {
	if policyReport != nil {
		if attributeValue, ok := policyReport.Attributes[plan.AttributeID]; ok {
			if detail, detailOK := attributeValue.Details[plan.Detail]; detailOK {
				if value, stringOK := detail.Value.(string); stringOK && strings.TrimSpace(value) != "" {
					detail.Selected = true
					attributeValue.Details[plan.Detail] = detail
					policyReport.Attributes[plan.AttributeID] = attributeValue

					return &report.ResponseMessageSelection{
						Source:      "attribute_detail",
						Message:     sanitizeResponseMessage(value, plan.MaxLength),
						AttributeID: plan.AttributeID,
						Detail:      plan.Detail,
					}
				}
			}
		}
	}

	if plan.Fallback != "" {
		return &report.ResponseMessageSelection{
			Source:       "attribute_detail",
			Message:      sanitizeResponseMessage(plan.Fallback, plan.MaxLength),
			AttributeID:  plan.AttributeID,
			Detail:       plan.Detail,
			Fallback:     plan.Fallback,
			FallbackUsed: true,
		}
	}

	return defaultResponseMessage(responseMarker)
}

func exprMatches(expr policyruntime.CompiledExpr, policyReport *report.DecisionReport) bool {
	switch expr.Kind {
	case policyruntime.ExprKindAlways:
		return true
	case policyruntime.ExprKindAll:
		for _, child := range expr.Children {
			if !exprMatches(child, policyReport) {
				return false
			}
		}

		return true
	case policyruntime.ExprKindAny:
		for _, child := range expr.Children {
			if exprMatches(child, policyReport) {
				return true
			}
		}

		return false
	case policyruntime.ExprKindNot:
		if len(expr.Children) != 1 {
			return false
		}

		return !exprMatches(expr.Children[0], policyReport)
	case policyruntime.ExprKindAttribute:
		return attributeExprMatches(expr, policyReport)
	default:
		return false
	}
}

func attributeExprMatches(expr policyruntime.CompiledExpr, policyReport *report.DecisionReport) bool {
	actual, exists := attributeValue(expr, policyReport)
	if expr.Operator == "exists" {
		expected, ok := expr.Expected.Value.(bool)

		return ok && exists == expected
	}

	if !exists {
		return false
	}

	return operatorMatches(expr.Operator, actual, expr.Expected.Value)
}

func attributeValue(expr policyruntime.CompiledExpr, policyReport *report.DecisionReport) (any, bool) {
	if policyReport == nil {
		return nil, false
	}

	attributeValue, ok := policyReport.Attributes[expr.AttributeID]
	if !ok {
		return nil, false
	}

	if expr.Detail == "" {
		return attributeValue.Value, true
	}

	detail, ok := attributeValue.Details[expr.Detail]
	if !ok {
		return nil, false
	}

	return detail.Value, true
}

func operatorMatches(operator policyruntime.Operator, actual any, expected any) bool {
	switch operator {
	case "is", "eq":
		return reflect.DeepEqual(actual, expected)
	case "ne":
		return !reflect.DeepEqual(actual, expected)
	case "in":
		return valueInList(actual, expected)
	case "not_in":
		return !valueInList(actual, expected)
	case "matches":
		value, ok := actual.(string)
		pattern, patternOK := expected.(*regexp.Regexp)

		return ok && patternOK && pattern.MatchString(value)
	case "contains":
		return stringSliceContains(actual, expected)
	case "contains_any":
		return stringSliceContainsAny(actual, expected)
	case "contains_all":
		return stringSliceContainsAll(actual, expected)
	case "contains_none":
		return !stringSliceContainsAny(actual, expected)
	case operatorGT, operatorGTE, operatorLT, operatorLTE:
		return compareOrdered(operator, actual, expected)
	case "cidr_contains":
		return cidrContains(actual, expected)
	case "within_time_window":
		return withinTimeWindow(actual, expected)
	default:
		return false
	}
}

func valueInList(actual any, expected any) bool {
	values := reflect.ValueOf(expected)
	if values.Kind() != reflect.Slice {
		return false
	}

	for index := 0; index < values.Len(); index++ {
		if reflect.DeepEqual(actual, values.Index(index).Interface()) {
			return true
		}
	}

	return false
}

func stringSliceContains(actual any, expected any) bool {
	values, ok := actual.([]string)
	candidate, candidateOK := expected.(string)

	return ok && candidateOK && stringsContain(values, candidate)
}

func stringSliceContainsAny(actual any, expected any) bool {
	values, ok := actual.([]string)
	candidates, candidatesOK := expected.([]string)
	if !ok || !candidatesOK {
		return false
	}

	for _, candidate := range candidates {
		if stringsContain(values, candidate) {
			return true
		}
	}

	return false
}

func stringSliceContainsAll(actual any, expected any) bool {
	values, ok := actual.([]string)
	candidates, candidatesOK := expected.([]string)
	if !ok || !candidatesOK {
		return false
	}

	for _, candidate := range candidates {
		if !stringsContain(values, candidate) {
			return false
		}
	}

	return true
}

func stringsContain(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}

	return false
}

func compareOrdered(operator policyruntime.Operator, actual any, expected any) bool {
	if actualTime, ok := actual.(time.Time); ok {
		expectedTime, expectedOK := expected.(time.Time)
		if !expectedOK {
			return false
		}

		return compareTimes(operator, actualTime, expectedTime)
	}

	actualNumber, ok := numericValue(actual)
	expectedNumber, expectedOK := numericValue(expected)
	if !ok || !expectedOK {
		return false
	}

	switch operator {
	case operatorGT:
		return actualNumber > expectedNumber
	case operatorGTE:
		return actualNumber >= expectedNumber
	case operatorLT:
		return actualNumber < expectedNumber
	case operatorLTE:
		return actualNumber <= expectedNumber
	default:
		return false
	}
}

func compareTimes(operator policyruntime.Operator, actual time.Time, expected time.Time) bool {
	switch operator {
	case operatorGT:
		return actual.After(expected)
	case operatorGTE:
		return actual.After(expected) || actual.Equal(expected)
	case operatorLT:
		return actual.Before(expected)
	case operatorLTE:
		return actual.Before(expected) || actual.Equal(expected)
	default:
		return false
	}
}

func numericValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case int32:
		return float64(typed), true
	default:
		return 0, false
	}
}

func cidrContains(actual any, expected any) bool {
	prefixes, ok := expected.([]netip.Prefix)
	if !ok {
		return false
	}

	switch value := actual.(type) {
	case netip.Addr:
		for _, prefix := range prefixes {
			if prefix.Contains(value) {
				return true
			}
		}
	case netip.Prefix:
		for _, prefix := range prefixes {
			if prefix.Contains(value.Addr()) {
				return true
			}
		}
	}

	return false
}

func withinTimeWindow(actual any, expected any) bool {
	timestamp, ok := actual.(time.Time)
	window, windowOK := expected.(policyruntime.CompiledTimeWindow)
	if !ok || !windowOK {
		return false
	}

	location, err := time.LoadLocation(window.LocationName)
	if err != nil {
		return false
	}

	local := timestamp.In(location)
	if !weekdayAllowed(local.Weekday(), window.Days) {
		return false
	}

	minute := local.Hour()*60 + local.Minute()
	for _, interval := range window.Intervals {
		if minute >= interval.StartMinute && minute < interval.EndMinute {
			return true
		}
	}

	return false
}

func weekdayAllowed(day time.Weekday, days []time.Weekday) bool {
	for _, allowed := range days {
		if day == allowed {
			return true
		}
	}

	return false
}

func compareObserveDecisions(defaultFinal *report.FinalDecision, customFinal *report.FinalDecision) (string, bool) {
	mismatches := make([]string, 0, 6)
	if defaultFinal == nil || customFinal == nil {
		return mismatchMultiple, true
	}

	if defaultFinal.Effect != customFinal.Effect {
		mismatches = append(mismatches, "effect")
	}

	if defaultFinal.OutcomeMarker != customFinal.OutcomeMarker {
		mismatches = append(mismatches, "outcome_marker")
	}

	if defaultFinal.FSMEventMarker != customFinal.FSMEventMarker {
		mismatches = append(mismatches, "fsm_event_marker")
	}

	if defaultFinal.ResponseMarker != customFinal.ResponseMarker {
		mismatches = append(mismatches, "response_marker")
	}

	if responseMessageSource(defaultFinal) != responseMessageSource(customFinal) {
		mismatches = append(mismatches, "response_message_source")
	}

	if responseMessageText(defaultFinal) != responseMessageText(customFinal) {
		mismatches = append(mismatches, "response_message")
	}

	if terminalState(defaultFinal) != terminalState(customFinal) {
		mismatches = append(mismatches, "terminal_state")
	}

	switch len(mismatches) {
	case 0:
		return mismatchNone, false
	case 1:
		return mismatches[0], true
	default:
		return mismatchMultiple, true
	}
}

func responseMessageSource(final *report.FinalDecision) string {
	if final == nil || final.ResponseMessage == nil {
		return ""
	}

	return final.ResponseMessage.Source
}

func responseMessageText(final *report.FinalDecision) string {
	if final == nil || final.ResponseMessage == nil {
		return ""
	}

	return final.ResponseMessage.Message
}

func terminalState(final *report.FinalDecision) string {
	if final == nil {
		return ""
	}

	return policyfsm.TerminalStateForDecision(final.Effect)
}

func customObserveReport(
	defaultFinal *report.FinalDecision,
	customFinal *report.FinalDecision,
	surface string,
	mismatchType string,
	mismatch bool,
) *report.ObserveReport {
	return &report.ObserveReport{
		Production:              cloneFinal(defaultFinal),
		Shadow:                  cloneFinal(customFinal),
		Surface:                 surface,
		MismatchType:            mismatchType,
		ProductionTerminalState: terminalState(defaultFinal),
		ShadowTerminalState:     terminalState(customFinal),
		Mismatch:                mismatch,
		ResponseMessageMatch:    responseMessageText(defaultFinal) == responseMessageText(customFinal),
		ObligationsMatch:        obligationsMatch(defaultFinal.Obligations, customFinal.Obligations),
	}
}

func recordCustomComparison(
	ctx context.Context,
	recorder observability.Recorder,
	operation policy.Operation,
	customFinal *report.FinalDecision,
	surface string,
	mismatchType string,
	mismatch bool,
) {
	recorder.RecordObserveComparison(ctx, observability.ObserveMeasurement{
		Result:       observeResult(mismatch),
		MismatchType: mismatchType,
		Operation:    operation,
		Stage:        customFinal.Stage,
	})
	if surface == "" {
		return
	}

	recorder.RecordResponseRender(ctx, observability.RendererMeasurement{
		Surface:        surface,
		ResponseMarker: customFinal.ResponseMarker,
		Result:         observeResult(mismatch),
	})
}

func setCustomCompareSpanAttributes(
	span interface{ SetAttributes(...attribute.KeyValue) },
	input CompareInput,
	operation policy.Operation,
	defaultFinal *report.FinalDecision,
	customFinal *report.FinalDecision,
	mismatchType string,
	mismatch bool,
	unavailable []string,
) {
	span.SetAttributes(
		attribute.String("policy.mode", modeObserve),
		attribute.String("policy.operation", string(operation)),
		attribute.String("policy.stage", string(customFinal.Stage)),
		attribute.String("policy.name", customFinal.PolicyName),
		attribute.String("policy.decision", string(customFinal.Effect)),
		attribute.String("policy.response_marker", customFinal.ResponseMarker),
		attribute.String("policy.fsm_event_marker", customFinal.FSMEventMarker),
		attribute.String("policy.default.name", defaultFinal.PolicyName),
		attribute.String("policy.default.decision", string(defaultFinal.Effect)),
		attribute.String("policy.default.response_marker", defaultFinal.ResponseMarker),
		attribute.String("policy.default.fsm_event_marker", defaultFinal.FSMEventMarker),
		attribute.Int64("policy.snapshot_generation", int64(input.Generation)),
		attribute.Bool("policy.observe_mismatch", mismatch),
		attribute.String("policy.mismatch_type", mismatchType),
		attribute.StringSlice("policy.unavailable_checks", unavailable),
	)
}

func logCustomObserveMismatch(
	ctx context.Context,
	input CompareInput,
	operation policy.Operation,
	defaultFinal *report.FinalDecision,
	customFinal *report.FinalDecision,
	mismatchType string,
	mismatch bool,
) {
	if !mismatch || input.Logger == nil || defaultFinal == nil || customFinal == nil {
		return
	}

	_ = level.Warn(input.Logger).WithContext(ctx).Log(
		"policy_mode", modeObserve,
		"policy_set", policy.BuiltinDefaultSet,
		"policy_name", customFinal.PolicyName,
		"operation", string(operation),
		"stage", string(customFinal.Stage),
		"decision", string(customFinal.Effect),
		"reason", customFinal.Reason,
		"response_marker", customFinal.ResponseMarker,
		"fsm_event_marker", customFinal.FSMEventMarker,
		"snapshot_generation", input.Generation,
		"observe_mismatch", true,
		"default_policy_name", defaultFinal.PolicyName,
		"custom_policy_name", customFinal.PolicyName,
		"default_effect", string(defaultFinal.Effect),
		"custom_effect", string(customFinal.Effect),
		"default_outcome_marker", defaultFinal.OutcomeMarker,
		"custom_outcome_marker", customFinal.OutcomeMarker,
		"default_fsm_event_marker", defaultFinal.FSMEventMarker,
		"custom_fsm_event_marker", customFinal.FSMEventMarker,
		"default_response_marker", defaultFinal.ResponseMarker,
		"custom_response_marker", customFinal.ResponseMarker,
		"default_response_message_source", responseMessageSource(defaultFinal),
		"custom_response_message_source", responseMessageSource(customFinal),
		"default_response_message", responseMessageText(defaultFinal),
		"custom_response_message", responseMessageText(customFinal),
		"default_terminal_state", terminalState(defaultFinal),
		"custom_terminal_state", terminalState(customFinal),
		"mismatch_type", mismatchType,
		"msg", "Custom policy observe result differs from authoritative default policy",
	)
}
