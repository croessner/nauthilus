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

// Package collection maps current auth mechanisms into policy check facts.
package collection

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/policy"
	"github.com/croessner/nauthilus/server/policy/evaluation"
	"github.com/croessner/nauthilus/server/policy/observability"
	"github.com/croessner/nauthilus/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	modeEnforce                = "enforce"
	modeObserve                = "observe"
	runIfSkipReason            = "run_if"
	schedulerGuardMissingRun   = "run"
	schedulerGuardReasonPrefix = "scheduler_guard:"
)

// AuthState describes the scheduler-visible authentication state.
type AuthState string

const (
	// AuthStateAny indicates that no auth-state restriction applies.
	AuthStateAny AuthState = policy.RunIfAny

	// AuthStateAuthenticated indicates that backend authentication succeeded.
	AuthStateAuthenticated AuthState = policy.RunIfAuthenticated

	// AuthStateUnauthenticated indicates that backend authentication has not succeeded.
	AuthStateUnauthenticated AuthState = policy.RunIfUnauthenticated
)

// AttributeValue is the request-time policy attribute value shape.
type AttributeValue = report.AttributeValue

// DetailValue is the request-time policy attribute detail shape.
type DetailValue = report.DetailValue

// CheckResult is the internal result produced by one mechanism adapter.
type CheckResult struct {
	Err          error
	Attributes   []AttributeValue
	Tags         []string
	Duration     time.Duration
	Reason       string
	Outcome      string
	Status       policy.CheckStatus
	DecisionHint policy.Decision
	Matched      bool
}

// CheckSelector locates the configured check that corresponds to a mechanism.
type CheckSelector struct {
	CheckType string
	Stage     policy.Stage
	Name      string
	ConfigRef string
}

// DecisionContext stores request-local collected policy facts.
type DecisionContext struct {
	snapshot *policyruntime.Snapshot
	recorder observability.Recorder
	report   *report.DecisionReport
	tracer   monittrace.Tracer
	checks   map[string]policyruntime.CompiledCheck
	mu       sync.Mutex
}

// NewDecisionContext creates a request-local collection context.
func NewDecisionContext(
	snapshot *policyruntime.Snapshot,
	operation policy.Operation,
	recorder observability.Recorder,
) *DecisionContext {
	policyReport := report.NewDecisionReport()
	policyReport.Operation = operation

	return &DecisionContext{
		snapshot: snapshot,
		recorder: observability.SafeRecorder(recorder),
		report:   policyReport,
		tracer:   observability.NewTracer(),
		checks:   make(map[string]policyruntime.CompiledCheck),
	}
}

// Report returns the mutable request report owned by this context.
func (c *DecisionContext) Report() *report.DecisionReport {
	if c == nil || c.report == nil {
		return report.NewDecisionReport()
	}

	return c.report
}

// Snapshot returns the runtime snapshot captured for this request.
func (c *DecisionContext) Snapshot() *policyruntime.Snapshot {
	if c == nil || c.snapshot == nil {
		return nil
	}

	return c.snapshot.Clone()
}

// SnapshotMetadata returns stable metadata for request-local comparison output.
func (c *DecisionContext) SnapshotMetadata() (string, string, uint64) {
	if c == nil || c.snapshot == nil {
		return modeEnforce, policy.BuiltinDefaultSet, 0
	}

	mode := c.snapshot.Mode
	if mode == "" {
		mode = modeEnforce
	}

	defaultPolicy := c.snapshot.DefaultPolicy
	if defaultPolicy == "" {
		defaultPolicy = policy.BuiltinDefaultSet
	}

	return mode, defaultPolicy, c.snapshot.Generation
}

// BuiltinDefaultAuthoritative reports whether request handling may use the built-in default set as production authority.
func (c *DecisionContext) BuiltinDefaultAuthoritative() bool {
	if c == nil || c.snapshot == nil {
		return false
	}

	defaultPolicy := c.snapshot.DefaultPolicy
	if defaultPolicy == "" {
		defaultPolicy = policy.BuiltinDefaultSet
	}

	if defaultPolicy != policy.BuiltinDefaultSet {
		return false
	}

	if c.snapshot.Mode == modeObserve {
		return true
	}

	return !hasConfiguredRules(c.snapshot.StagePlans)
}

// BuiltinDefaultAuthoritativeForStage reports whether the built-in default set owns one production stage.
func (c *DecisionContext) BuiltinDefaultAuthoritativeForStage(stage policy.Stage) bool {
	if c == nil || c.snapshot == nil || c.report == nil {
		return false
	}

	defaultPolicy := c.snapshot.DefaultPolicy
	if defaultPolicy == "" {
		defaultPolicy = policy.BuiltinDefaultSet
	}

	if defaultPolicy != policy.BuiltinDefaultSet {
		return false
	}

	if c.snapshot.Mode == modeObserve {
		return true
	}

	return !hasConfiguredRulesForStage(c.snapshot.StagePlans, c.report.Operation, stage)
}

// ConfiguredPreAuthAuthoritative reports whether configured pre-auth policy rules decide production output.
func (c *DecisionContext) ConfiguredPreAuthAuthoritative() bool {
	return c.configuredAuthorityForStage(policy.StagePreAuth)
}

// ConfiguredAuthDecisionAuthoritative reports whether configured final auth rules decide production output.
func (c *DecisionContext) ConfiguredAuthDecisionAuthoritative() bool {
	return c.configuredAuthorityForStage(policy.StageAuthDecision)
}

func (c *DecisionContext) configuredAuthorityForStage(stage policy.Stage) bool {
	if c == nil || c.snapshot == nil || c.report == nil {
		return false
	}

	if c.snapshot.Mode == modeObserve {
		return false
	}

	defaultPolicy := c.snapshot.DefaultPolicy
	if defaultPolicy == "" {
		defaultPolicy = policy.BuiltinDefaultSet
	}

	if defaultPolicy != policy.BuiltinDefaultSet {
		return false
	}

	plan := c.snapshot.StagePlans[c.report.Operation][stage]

	return len(plan.Policies) > 0
}

// ScriptScheduled reports whether a script should run for the current request state.
func (c *DecisionContext) ScriptScheduled(selector CheckSelector, authState AuthState) bool {
	if c == nil || c.snapshot == nil || c.report == nil {
		return true
	}

	checks := c.stageChecks(selector.Stage)
	if len(checks) == 0 {
		return true
	}

	for _, check := range checks {
		if !checkMatchesSelector(check, selector) {
			continue
		}

		return c.compiledCheckSelected(check, authState)
	}

	return false
}

// CheckScheduled reports whether a configured check should run for the current request.
func (c *DecisionContext) CheckScheduled(ctx context.Context, selector CheckSelector, authState AuthState) bool {
	if c == nil || c.snapshot == nil || c.report == nil {
		return true
	}

	check := c.resolveCheck(selector)
	if check.Name == "" {
		return true
	}

	return c.compiledCheckScheduled(ctx, check, authState)
}

func (c *DecisionContext) compiledCheckScheduled(ctx context.Context, check policyruntime.CompiledCheck, authState AuthState) bool {
	if c == nil || c.snapshot == nil || c.report == nil || check.Name == "" {
		return true
	}

	c.mu.Lock()
	if existing, exists := c.report.Checks[check.Name]; exists {
		c.mu.Unlock()

		return existing.Status != policy.CheckStatusSkipped
	}

	reason, scheduled := c.checkScheduleLocked(check, authState)
	if scheduled {
		c.mu.Unlock()

		return true
	}

	c.recordSkippedLocked(ctx, check, reason)
	c.mu.Unlock()

	return false
}

func (c *DecisionContext) compiledCheckSelected(check policyruntime.CompiledCheck, authState AuthState) bool {
	if c == nil || c.snapshot == nil || c.report == nil || check.Name == "" {
		return true
	}

	c.mu.Lock()
	_, scheduled := c.checkScheduleLocked(check, authState)
	c.mu.Unlock()

	return scheduled
}

func (c *DecisionContext) checkScheduleLocked(check policyruntime.CompiledCheck, authState AuthState) (string, bool) {
	if !runIfMatches(check.RunIf.AuthState, authState) {
		return runIfSkipReason, false
	}

	if reason, matched := c.schedulerGuardSkipReasonLocked(check); matched {
		return reason, false
	}

	return "", true
}

func (c *DecisionContext) schedulerGuardSkipReasonLocked(check policyruntime.CompiledCheck) (string, bool) {
	if len(check.SkipIf) == 0 || c.snapshot == nil {
		return "", false
	}

	for _, guardName := range check.SkipIf {
		guard, exists := c.snapshot.SchedulerGuards[guardName]
		if !exists {
			continue
		}

		if schedulerGuardRunsOnMissing(guard) && c.guardHasMissingAttributeLocked(guard.Root) {
			continue
		}

		if evaluation.ExprMatches(guard.Root, c.report) {
			return schedulerGuardReasonPrefix + guardName, true
		}
	}

	return "", false
}

func schedulerGuardRunsOnMissing(guard policyruntime.CompiledSchedulerGuard) bool {
	return guard.OnMissingAttribute == "" || guard.OnMissingAttribute == schedulerGuardMissingRun
}

func (c *DecisionContext) guardHasMissingAttributeLocked(expr policyruntime.CompiledExpr) bool {
	switch expr.Kind {
	case policyruntime.ExprKindAttribute:
		if expr.AttributeID == "" {
			return false
		}

		value, exists := c.report.Attributes[expr.AttributeID]
		if !exists {
			return true
		}

		if expr.Detail == "" {
			return false
		}

		_, exists = value.Details[expr.Detail]

		return !exists
	case policyruntime.ExprKindAll, policyruntime.ExprKindAny, policyruntime.ExprKindNot:
		for _, child := range expr.Children {
			if c.guardHasMissingAttributeLocked(child) {
				return true
			}
		}
	}

	return false
}

func (c *DecisionContext) recordSkippedLocked(ctx context.Context, check policyruntime.CompiledCheck, reason string) {
	c.recordLocked(CheckResult{
		Status: policy.CheckStatusSkipped,
		Reason: reason,
	}, check)
	c.recorder.RecordCheck(ctx, observability.CheckMeasurement{
		Operation:  c.report.Operation,
		Stage:      check.Stage,
		Check:      check.Name,
		CheckType:  check.Type,
		Status:     policy.CheckStatusSkipped,
		ReasonCode: reason,
	})
}

// BeginCheck opens metric and tracing collection for one check adapter.
func (c *DecisionContext) BeginCheck(ctx context.Context, selector CheckSelector) *ActiveCheck {
	if c == nil {
		return &ActiveCheck{}
	}

	check := c.resolveCheck(selector)
	if check.Name == "" {
		check = fallbackCheck(selector, c.report.Operation)
	}

	c.mu.Lock()
	if existing, exists := c.report.Checks[check.Name]; exists && existing.Status == policy.CheckStatusSkipped {
		c.mu.Unlock()

		return &ActiveCheck{finished: true}
	}
	c.mu.Unlock()

	spanCtx, span := c.tracer.Start(ctx, "policy.check",
		attribute.String("policy.operation", string(c.report.Operation)),
		attribute.String("policy.stage", string(check.Stage)),
		attribute.String("policy.check", check.Name),
		attribute.String("policy.check_type", check.Type),
	)

	return &ActiveCheck{
		ctx:      spanCtx,
		parent:   c,
		check:    check,
		span:     span,
		started:  time.Now(),
		finished: false,
	}
}

// CompleteStage records skipped and missing entries for configured checks not observed.
func (c *DecisionContext) CompleteStage(stage policy.Stage, authState AuthState) {
	if c == nil || c.snapshot == nil || c.report == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, check := range c.stageChecks(stage) {
		if _, exists := c.report.Checks[check.Name]; exists {
			continue
		}

		if !runIfMatches(check.RunIf.AuthState, authState) {
			c.recordSkippedLocked(context.Background(), check, runIfSkipReason)

			continue
		}

		if reason, matched := c.schedulerGuardSkipReasonLocked(check); matched {
			c.recordSkippedLocked(context.Background(), check, reason)

			continue
		}

		if c.observeMode() && !c.checkObserveSafe(check) {
			c.recordUnavailableLocked(check, "not_observe_safe")

			continue
		}

		if c.report.MissingChecks == nil {
			c.report.MissingChecks = make(map[string]string)
		}

		c.report.MissingChecks[check.Name] = "not_recorded"
	}
}

// MarkUnavailable records a fact source that cannot run in the current mode.
func (c *DecisionContext) MarkUnavailable(name string, reason string) {
	if c == nil || c.report == nil || strings.TrimSpace(name) == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.report.Unavailable == nil {
		c.report.Unavailable = make(map[string]report.UnavailableFact)
	}

	c.report.Unavailable[name] = report.UnavailableFact{Name: name, Reason: reason}
}

func (c *DecisionContext) recordUnavailableLocked(check policyruntime.CompiledCheck, reason string) {
	if check.Name == "" {
		return
	}

	if c.report.Unavailable == nil {
		c.report.Unavailable = make(map[string]report.UnavailableFact)
	}

	c.report.Unavailable[check.Name] = report.UnavailableFact{Name: check.Name, Reason: reason}
	c.recorder.RecordObserveUnavailable(context.Background(), observability.ObserveUnavailableMeasurement{
		Operation:  c.report.Operation,
		Stage:      check.Stage,
		Check:      check.Name,
		ReasonCode: reason,
	})
}

// Record stores a completed check result.
func (c *DecisionContext) Record(result CheckResult, check policyruntime.CompiledCheck) {
	if c == nil || c.report == nil || check.Name == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.recordLocked(result, check)
}

func (c *DecisionContext) recordLocked(result CheckResult, check policyruntime.CompiledCheck) {
	if result.Status == "" {
		result.Status = policy.CheckStatusOK
	}

	if c.report.Checks == nil {
		c.report.Checks = make(map[string]report.CheckResult)
	}

	attributeIDs := make([]string, 0, len(result.Attributes))
	for _, value := range result.Attributes {
		if value.ID == "" {
			continue
		}

		attributeIDs = append(attributeIDs, value.ID)
		c.recordAttributeLocked(value)
	}

	c.report.Checks[check.Name] = report.CheckResult{
		Name:         check.Name,
		Type:         check.Type,
		Reason:       result.Reason,
		Operation:    c.report.Operation,
		Stage:        check.Stage,
		Status:       result.Status,
		DecisionHint: result.DecisionHint,
		Matched:      result.Matched,
		Attributes:   attributeIDs,
	}

	c.checks[check.Name] = check
}

// RecordAttribute stores one emitted policy attribute.
func (c *DecisionContext) RecordAttribute(value AttributeValue) {
	if c == nil || c.report == nil || value.ID == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.recordAttributeLocked(value)
}

func (c *DecisionContext) recordAttributeLocked(value AttributeValue) {
	if c.report.Attributes == nil {
		c.report.Attributes = make(map[string]report.AttributeValue)
	}

	c.report.Attributes[value.ID] = value
}

func hasConfiguredRules(stagePlans map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan) bool {
	for _, stages := range stagePlans {
		for _, plan := range stages {
			if len(plan.Policies) > 0 {
				return true
			}
		}
	}

	return false
}

func hasConfiguredRulesForStage(
	stagePlans map[policy.Operation]map[policy.Stage]policyruntime.CompiledStagePlan,
	operation policy.Operation,
	stage policy.Stage,
) bool {
	plan := stagePlans[operation][stage]

	return len(plan.Policies) > 0
}

func (c *DecisionContext) resolveCheck(selector CheckSelector) policyruntime.CompiledCheck {
	if c == nil || c.snapshot == nil || c.report == nil {
		return policyruntime.CompiledCheck{}
	}

	for _, check := range c.stageChecks(selector.Stage) {
		if checkMatchesSelector(check, selector) {
			return check
		}
	}

	return policyruntime.CompiledCheck{}
}

func checkMatchesSelector(check policyruntime.CompiledCheck, selector CheckSelector) bool {
	if check.Type != selector.CheckType {
		return false
	}

	if selector.ConfigRef != "" {
		return check.ConfigRef == selector.ConfigRef
	}

	return selector.Name == "" || check.Name == selector.Name
}

func (c *DecisionContext) stageChecks(stage policy.Stage) []policyruntime.CompiledCheck {
	if c == nil || c.snapshot == nil || c.report == nil {
		return nil
	}

	stages := c.snapshot.StagePlans[c.report.Operation]
	if stages == nil {
		return nil
	}

	plan, ok := stages[stage]
	if !ok {
		return nil
	}

	return plan.Checks
}

func (c *DecisionContext) observeMode() bool {
	return c != nil && c.snapshot != nil && c.snapshot.Mode == modeObserve
}

func (c *DecisionContext) checkObserveSafe(check policyruntime.CompiledCheck) bool {
	if check.ObserveSafe {
		return true
	}

	if c == nil || c.snapshot == nil {
		return false
	}

	definition, ok := c.snapshot.CheckTypeRegistry[check.Type]

	return ok && definition.ObserveSafeDefault
}

func fallbackCheck(selector CheckSelector, operation policy.Operation) policyruntime.CompiledCheck {
	name := selector.Name
	if name == "" {
		name = selector.CheckType
	}

	return policyruntime.CompiledCheck{
		Name:       name,
		Type:       selector.CheckType,
		Stage:      selector.Stage,
		ConfigRef:  selector.ConfigRef,
		Operations: []policy.Operation{operation},
		RunIf:      policyruntime.RunIfPlan{AuthState: policy.RunIfAny},
	}
}

func runIfMatches(runIf string, authState AuthState) bool {
	if runIf == "" || runIf == policy.RunIfAny {
		return true
	}

	return runIf == string(authState)
}

// ActiveCheck tracks one running check adapter.
type ActiveCheck struct {
	parent   *DecisionContext
	span     trace.Span
	check    policyruntime.CompiledCheck
	ctx      context.Context
	started  time.Time
	finished bool
}

// Finish stores the check result and records metrics.
func (a *ActiveCheck) Finish(result CheckResult) {
	if a == nil || a.finished {
		return
	}

	a.finished = true
	if a.parent == nil {
		return
	}

	duration := time.Since(a.started)
	if result.Duration > 0 {
		duration = result.Duration
	}
	if result.Status == "" {
		result.Status = policy.CheckStatusOK
	}
	if result.Err != nil {
		result.Status = policy.CheckStatusError
		if result.Reason == "" {
			result.Reason = "technical_error"
		}

		if a.span != nil {
			a.span.RecordError(result.Err)
		}
	}

	a.parent.Record(result, a.check)
	a.parent.recorder.RecordCheck(a.ctx, observability.CheckMeasurement{
		Duration:   duration,
		Operation:  a.parent.report.Operation,
		Stage:      a.check.Stage,
		Check:      a.check.Name,
		CheckType:  a.check.Type,
		Status:     result.Status,
		ReasonCode: result.Reason,
	})

	if a.span != nil {
		a.span.SetAttributes(
			attribute.String("policy.status", string(result.Status)),
			attribute.Bool("policy.matched", result.Matched),
		)
		a.span.End()
	}
}

// BoolAttribute creates a bool policy attribute value.
func BoolAttribute(
	id string,
	stage policy.Stage,
	operation policy.Operation,
	value bool,
	details map[string]DetailValue,
) AttributeValue {
	return AttributeValue{
		ID:        id,
		Stage:     stage,
		Operation: operation,
		Value:     value,
		Details:   details,
	}
}

// NumberAttribute creates a numeric policy attribute value.
func NumberAttribute(id string, stage policy.Stage, operation policy.Operation, value float64, details map[string]DetailValue) AttributeValue {
	return AttributeValue{
		ID:        id,
		Stage:     stage,
		Operation: operation,
		Value:     value,
		Details:   details,
	}
}

// StringListAttribute creates a string-list policy attribute value.
func StringListAttribute(
	id string,
	stage policy.Stage,
	operation policy.Operation,
	value []string,
	details map[string]DetailValue,
) AttributeValue {
	return AttributeValue{
		ID:        id,
		Stage:     stage,
		Operation: operation,
		Value:     append([]string(nil), value...),
		Details:   details,
	}
}

// StringAttribute creates a string policy attribute value.
func StringAttribute(id string, stage policy.Stage, operation policy.Operation, value string) AttributeValue {
	return AttributeValue{
		ID:        id,
		Stage:     stage,
		Operation: operation,
		Value:     value,
	}
}

// StringAttributeWithDetails creates a string policy attribute value with details.
func StringAttributeWithDetails(
	id string,
	stage policy.Stage,
	operation policy.Operation,
	value string,
	details map[string]DetailValue,
) AttributeValue {
	return AttributeValue{
		ID:        id,
		Stage:     stage,
		Operation: operation,
		Value:     value,
		Details:   details,
	}
}

// TimeAttribute creates a timestamp policy attribute value.
func TimeAttribute(id string, stage policy.Stage, operation policy.Operation, value time.Time) AttributeValue {
	return AttributeValue{
		ID:        id,
		Stage:     stage,
		Operation: operation,
		Value:     value,
	}
}

// InternalDetail creates a redacted internal detail value.
func InternalDetail(value any) DetailValue {
	return DetailValue{Value: value, Sensitivity: report.SensitivityInternal}
}

// PublicMessageDetail creates a public response-message candidate detail.
func PublicMessageDetail(value string) DetailValue {
	return DetailValue{
		Value:       value,
		Sensitivity: report.SensitivityPublic,
		Purpose:     report.PurposeResponseMessage,
	}
}

func scriptAttributeID(kind ScriptKind, name string, suffix string) string {
	return fmt.Sprintf("auth.lua.%s.%s.%s", kind.policySegment(), name, suffix)
}
