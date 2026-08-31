// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"fmt"
	"slices"

	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

// AuthnHostDisposition is the generation-owned instruction for one exact host instance.
type AuthnHostDisposition string

const (
	// AuthnHostDispositionRun requires the host to execute the exact instance once.
	AuthnHostDispositionRun AuthnHostDisposition = "run"

	// AuthnHostDispositionSkipped records a scheduler-owned non-execution result.
	AuthnHostDispositionSkipped AuthnHostDisposition = "skipped"
)

const (
	// AuthnHostReasonScheduled identifies an admitted runnable host instance.
	AuthnHostReasonScheduled = "scheduled"
	// AuthnHostReasonAction identifies an instance excluded from the target action.
	AuthnHostReasonAction = "action"
	// AuthnHostReasonAuthState identifies a dynamic authentication-state exclusion.
	AuthnHostReasonAuthState = "auth_state"
	// AuthnHostReasonDependency identifies a skipped or failed dependency.
	AuthnHostReasonDependency = "dependency"
	// AuthnHostReasonSchedulerGuardPrefix qualifies the exact matched plan-local guard identity.
	AuthnHostReasonSchedulerGuardPrefix = "scheduler_guard:"
	// AuthnHostReasonNotObserveSafe identifies a custom provider excluded from observe mode.
	AuthnHostReasonNotObserveSafe = "not_observe_safe"
	// AuthnHostReasonTerminal identifies remaining host instances closed after a terminal host result.
	AuthnHostReasonTerminal = "terminal"
)

// AuthnHostReceiptState is the exact result reported for one scheduler-admitted host callback.
type AuthnHostReceiptState string

const (
	// AuthnHostReceiptCompleted records reliable host completion.
	AuthnHostReceiptCompleted AuthnHostReceiptState = "completed"
	// AuthnHostReceiptFailed records a host callback failure.
	AuthnHostReceiptFailed AuthnHostReceiptState = "failed"
	// AuthnHostReceiptTimedOut records a host callback deadline failure.
	AuthnHostReceiptTimedOut AuthnHostReceiptState = "timed_out"
)

// AuthnHostScheduleInput carries current request-local facts and authentication state to the sole scheduler.
type AuthnHostScheduleInput struct {
	Facts         decision.FactSet
	Checkpoint    string
	Authenticated bool
}

// AuthnHostReceipt records one exact returned run directive by checkpoint-local instance name.
type AuthnHostReceipt struct {
	Checkpoint    string
	Instance      string
	State         AuthnHostReceiptState
	Authenticated bool
	Terminal      bool
}

// AuthnHostDirective is one exact scheduler result returned under the captured session lease.
type AuthnHostDirective struct {
	instance    CheckpointProviderInstance
	disposition AuthnHostDisposition
	reason      string
}

// Instance returns the exact detached provider instance.
func (d AuthnHostDirective) Instance() CheckpointProviderInstance { return d.instance.clone() }

// Disposition returns whether the callback must run or was scheduler-skipped.
func (d AuthnHostDirective) Disposition() AuthnHostDisposition { return d.disposition }

// Reason returns the stable scheduler disposition reason.
func (d AuthnHostDirective) Reason() string { return d.reason }

// AuthnHostExecutionSession exposes the sole exact scheduler and instance-receipt authority.
type AuthnHostExecutionSession interface {
	DecisionSession
	NextAuthnHostProvider(AuthnHostScheduleInput) (AuthnHostDirective, bool, error)
	RecordAuthnHostProvider(AuthnHostReceipt) error
	CompleteAuthnHostSchedule(string) error
}

type hostScheduleInput struct {
	target        decision.Target
	facts         decision.FactSet
	states        map[string]providerState
	checkpoint    string
	cursor        int
	authenticated bool
}

type authnHostScheduler interface {
	hasAuthnHostProviders(decision.Target, string) bool
	nextAuthnHostProvider(hostScheduleInput) (AuthnHostDirective, int, bool, error)
	remainingAuthnHostProviders(decision.Target, string, int) ([]string, int, error)
}

type guardMatch uint8

const (
	guardUnknown guardMatch = iota
	guardFalse
	guardTrue
)

// nextAuthnHostProvider resolves the next exact host instance without executing transport-owned work.
func (r *checkpointRuntime) nextAuthnHostProvider(
	input hostScheduleInput,
) (AuthnHostDirective, int, bool, error) {
	if r == nil || r.catalog == nil || input.checkpoint == "" || input.cursor < 0 {
		return AuthnHostDirective{}, input.cursor, false, fmt.Errorf("%w: invalid host schedule input", ErrDecisionEvaluation)
	}

	target, exists := r.catalog.Lookup(input.target)
	if !exists {
		return AuthnHostDirective{}, input.cursor, false, fmt.Errorf("%w: admitted target is absent", ErrDecisionEvaluation)
	}

	checkpoint, exists := target.DomainPlan().Checkpoint(input.checkpoint)
	if !exists {
		return AuthnHostDirective{}, input.cursor, false, fmt.Errorf("%w: admitted checkpoint is absent", ErrDecisionEvaluation)
	}

	instances, err := orderedCheckpointProviderInstances(checkpoint)
	if err != nil {
		return AuthnHostDirective{}, input.cursor, false, err
	}

	for index := input.cursor; index < len(instances); index++ {
		instance := instances[index]
		if !target.HostPreparesProvider(instance.Use()) {
			continue
		}

		disposition, reason, err := r.providerDisposition(target, instance, input)
		if err != nil {
			return AuthnHostDirective{}, index, false, err
		}

		return AuthnHostDirective{
			instance: checkpointProviderInstance(instance), disposition: disposition, reason: reason,
		}, index + 1, true, nil
	}

	return AuthnHostDirective{}, len(instances), false, nil
}

// hasAuthnHostProviders reports whether one exact checkpoint requires host execution.
func (r *checkpointRuntime) hasAuthnHostProviders(targetID decision.Target, checkpointName string) bool {
	if r == nil || r.catalog == nil || checkpointName == "" {
		return false
	}

	target, exists := r.catalog.Lookup(targetID)
	if !exists {
		return false
	}

	checkpoint, exists := target.DomainPlan().Checkpoint(checkpointName)
	if !exists {
		return false
	}

	for _, instance := range checkpoint.ProviderInstances() {
		if target.HostPreparesProvider(instance.Use()) {
			return true
		}
	}

	return false
}

// remainingAuthnHostProviders resolves exact unvisited host instances for terminal schedule closure.
func (r *checkpointRuntime) remainingAuthnHostProviders(
	targetID decision.Target,
	checkpointName string,
	cursor int,
) ([]string, int, error) {
	if r == nil || r.catalog == nil || checkpointName == "" || cursor < 0 {
		return nil, cursor, fmt.Errorf("%w: invalid host schedule completion", ErrDecisionEvaluation)
	}

	target, exists := r.catalog.Lookup(targetID)
	if !exists {
		return nil, cursor, fmt.Errorf("%w: admitted target is absent", ErrDecisionEvaluation)
	}

	checkpoint, exists := target.DomainPlan().Checkpoint(checkpointName)
	if !exists {
		return nil, cursor, fmt.Errorf("%w: admitted checkpoint is absent", ErrDecisionEvaluation)
	}

	instances, err := orderedCheckpointProviderInstances(checkpoint)
	if err != nil {
		return nil, cursor, err
	}

	if cursor > len(instances) {
		return nil, cursor, fmt.Errorf("%w: host schedule cursor is invalid", ErrDecisionEvaluation)
	}

	result := make([]string, 0, len(instances)-cursor)
	for index := cursor; index < len(instances); index++ {
		if target.HostPreparesProvider(instances[index].Use()) {
			result = append(result, instances[index].Name())
		}
	}

	return result, len(instances), nil
}

// orderedCheckpointProviderInstances resolves the exact dependency-level execution order.
func orderedCheckpointProviderInstances(
	checkpoint policyruntime.CompiledCheckpoint,
) ([]policyruntime.CompiledProviderInstance, error) {
	levels := checkpoint.ProviderLevels()
	result := make([]policyruntime.CompiledProviderInstance, 0, len(checkpoint.ProviderInstances()))

	for _, level := range levels {
		for _, instanceName := range level {
			instance, exists := checkpoint.LookupProviderInstance(instanceName)
			if !exists {
				return nil, fmt.Errorf(
					"%w: checkpoint provider instance %s is unavailable",
					ErrDecisionEvaluation,
					instanceName,
				)
			}

			result = append(result, instance)
		}
	}

	if len(result) != len(checkpoint.ProviderInstances()) {
		return nil, fmt.Errorf("%w: checkpoint provider levels are incomplete", ErrDecisionEvaluation)
	}

	return result, nil
}

// providerDisposition applies the shared action, auth-state, dependency, mode, and skip-guard contract.
func (r *checkpointRuntime) providerDisposition(
	target policyruntime.CompiledTarget,
	instance policyruntime.CompiledProviderInstance,
	input hostScheduleInput,
) (AuthnHostDisposition, string, error) {
	if disposition, reason, resolved := staticProviderDisposition(target, instance, input); resolved {
		return disposition, reason, nil
	}

	descriptor, exists := target.LookupProvider(instance.Use())
	if !exists {
		return "", "", fmt.Errorf("%w: host provider %s is unavailable", ErrDecisionEvaluation, instance.Use())
	}

	if providerExcludedFromObserveMode(target, instance, descriptor) {
		return AuthnHostDispositionSkipped, AuthnHostReasonNotObserveSafe, nil
	}

	return r.schedulerGuardDisposition(target, instance, input.facts)
}

// staticProviderDisposition resolves exclusions that do not need provider catalog lookup.
func staticProviderDisposition(
	target policyruntime.CompiledTarget,
	instance policyruntime.CompiledProviderInstance,
	input hostScheduleInput,
) (AuthnHostDisposition, string, bool) {
	if actions := instance.Actions(); len(actions) > 0 && !slices.Contains(actions, target.Target().Action()) {
		return AuthnHostDispositionSkipped, AuthnHostReasonAction, true
	}

	if !authnRunStateMatches(instance.RunIfAuthState(), input.authenticated) {
		return AuthnHostDispositionSkipped, AuthnHostReasonAuthState, true
	}

	if providerDependencySkipped(instance.Dependencies(), input.states) {
		return AuthnHostDispositionSkipped, AuthnHostReasonDependency, true
	}

	return "", "", false
}

// providerExcludedFromObserveMode rejects custom providers without explicit observe-safe authorship.
func providerExcludedFromObserveMode(
	target policyruntime.CompiledTarget,
	instance policyruntime.CompiledProviderInstance,
	descriptor registry.ProviderDefinition,
) bool {
	return target.AuthorityMode() == registry.AuthorityModeObserve && !descriptor.IsBuiltin() &&
		(!instance.ObserveSafeAuthored() || !instance.ObserveSafe())
}

// schedulerGuardDisposition evaluates plan-local skip guards in authored order.
func (r *checkpointRuntime) schedulerGuardDisposition(
	target policyruntime.CompiledTarget,
	instance policyruntime.CompiledProviderInstance,
	facts decision.FactSet,
) (AuthnHostDisposition, string, error) {
	plan := target.DomainPlan()
	for _, guardName := range instance.SkipIf() {
		guard, found := plan.SchedulerGuard(guardName)
		if !found {
			return "", "", fmt.Errorf("%w: scheduler guard %s is unavailable", ErrDecisionEvaluation, guardName)
		}

		if r.guardMatches(target.Target().Namespace(), guard, facts) {
			return AuthnHostDispositionSkipped, AuthnHostReasonSchedulerGuardPrefix + guardName, nil
		}
	}

	return AuthnHostDispositionRun, AuthnHostReasonScheduled, nil
}

// authnRunStateMatches evaluates the closed dynamic authentication-state vocabulary.
func authnRunStateMatches(required string, authenticated bool) bool {
	switch required {
	case "", policy.RunIfAny:
		return true
	case policy.RunIfAuthenticated:
		return authenticated
	case policy.RunIfUnauthenticated:
		return !authenticated
	default:
		return false
	}
}

// guardMatches applies run-on-missing semantics to one immutable plan-local expression.
func (r *checkpointRuntime) guardMatches(
	namespace string,
	guard registry.SchedulerGuardDefinition,
	facts decision.FactSet,
) bool {
	matched := r.guardExpressionMatch(namespace, guard.Expression(), facts)

	return matched == guardTrue
}

// guardExpressionMatch evaluates conditions with an explicit unknown state for missing facts or references.
func (r *checkpointRuntime) guardExpressionMatch(
	namespace string,
	expression registry.PolicyExpression,
	facts decision.FactSet,
) guardMatch {
	switch expression.Kind() {
	case registry.ExpressionKindAlways:
		return guardTrue
	case registry.ExpressionKindAll:
		return r.guardAll(namespace, expression.Children(), facts)
	case registry.ExpressionKindAny:
		return r.guardAny(namespace, expression.Children(), facts)
	case registry.ExpressionKindNot:
		children := expression.Children()
		if len(children) != 1 {
			return guardUnknown
		}

		return negateGuardMatch(r.guardExpressionMatch(namespace, children[0], facts))
	case registry.ExpressionKindAttribute:
		return r.guardAttributeMatch(namespace, expression, facts)
	default:
		return guardUnknown
	}
}

// guardAll evaluates a conjunction without treating an unknown child as true under negation.
func (r *checkpointRuntime) guardAll(
	namespace string,
	children []registry.PolicyExpression,
	facts decision.FactSet,
) guardMatch {
	result := guardTrue

	for _, child := range children {
		matched := r.guardExpressionMatch(namespace, child, facts)
		if matched == guardFalse {
			return guardFalse
		}

		if matched == guardUnknown {
			result = guardUnknown
		}
	}

	return result
}

// guardAny evaluates a disjunction while retaining unresolved missing-fact state.
func (r *checkpointRuntime) guardAny(
	namespace string,
	children []registry.PolicyExpression,
	facts decision.FactSet,
) guardMatch {
	result := guardFalse

	for _, child := range children {
		matched := r.guardExpressionMatch(namespace, child, facts)
		if matched == guardTrue {
			return guardTrue
		}

		if matched == guardUnknown {
			result = guardUnknown
		}
	}

	return result
}

// guardAttributeMatch evaluates one strict predicate and distinguishes absence from false.
func (r *checkpointRuntime) guardAttributeMatch(
	namespace string,
	expression registry.PolicyExpression,
	facts decision.FactSet,
) guardMatch {
	fact, exists := facts.Get(expression.FactID())
	if expression.Operator() == registry.ExpressionOperatorExists {
		expected, _ := expression.Values()[0].Boolean()
		if exists == expected {
			return guardTrue
		}

		return guardFalse
	}

	if !exists {
		return guardUnknown
	}

	if fact.Value().Kind() != expression.FactKind() {
		return guardFalse
	}

	if expression.Operator() == registry.ExpressionOperatorWithinTimeWindow {
		key := policyruntime.ConditionMaterialKey(namespace, expression.Reference())
		if _, exists = r.timeWindows[key]; !exists {
			return guardUnknown
		}

		return booleanGuardMatch(r.runtimeWithinTimeWindow(namespace, fact.Value(), expression.Reference()))
	}

	operands := expression.Values()
	if expression.Reference() != "" {
		var found bool

		key := policyruntime.ConditionMaterialKey(namespace, expression.Reference())

		operands, found = r.conditionSets[key]
		if !found {
			return guardUnknown
		}
	}

	return booleanGuardMatch(matchAttributeOperator(expression.Operator(), fact.Value(), operands))
}

// negateGuardMatch preserves unknown instead of converting missing facts into a matched skip guard.
func negateGuardMatch(input guardMatch) guardMatch {
	switch input {
	case guardTrue:
		return guardFalse
	case guardFalse:
		return guardTrue
	default:
		return guardUnknown
	}
}

// booleanGuardMatch projects an exact boolean into the tri-state guard result.
func booleanGuardMatch(input bool) guardMatch {
	if input {
		return guardTrue
	}

	return guardFalse
}

// NextAuthnHostProvider returns the next exact disposition for the current checkpoint.
func (s *decisionSession) NextAuthnHostProvider(
	input AuthnHostScheduleInput,
) (AuthnHostDirective, bool, error) {
	if s == nil {
		return AuthnHostDirective{}, false, fmt.Errorf("%w: invalid host session", ErrDecisionEvaluation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.nextAuthnHostDirective(input)
}

// nextAuthnHostDirective advances one scheduler step while the session lock is held.
func (s *decisionSession) nextAuthnHostDirective(
	input AuthnHostScheduleInput,
) (AuthnHostDirective, bool, error) {
	if !s.hostScheduleInputValid(input) {
		return AuthnHostDirective{}, false, fmt.Errorf("%w: invalid host schedule input", ErrDecisionEvaluation)
	}

	scheduler, err := s.capturedAuthnHostScheduler()
	if err != nil {
		return AuthnHostDirective{}, false, err
	}

	facts, err := mergeAdmittedFacts(s.facts, input.Facts)
	if err != nil {
		return AuthnHostDirective{}, false, fmt.Errorf("%w: host schedule facts are invalid", ErrDecisionEvaluation)
	}

	directive, cursor, found, err := scheduler.nextAuthnHostProvider(hostScheduleInput{
		target: s.request.Target(), facts: facts, states: cloneProviderStates(s.hostStates),
		checkpoint: input.Checkpoint, cursor: s.hostCursor, authenticated: input.Authenticated,
	})
	if err != nil {
		return AuthnHostDirective{}, false, err
	}

	return s.acceptAuthnHostDirective(input, directive, cursor, found)
}

// acceptAuthnHostDirective records one scheduler result while the session lock is held.
func (s *decisionSession) acceptAuthnHostDirective(
	input AuthnHostScheduleInput,
	directive AuthnHostDirective,
	cursor int,
	found bool,
) (AuthnHostDirective, bool, error) {
	s.hostPlan = input.Checkpoint
	s.hostCursor = cursor
	s.hostAuthn = input.Authenticated

	if !found {
		s.hostExhausted = true

		return AuthnHostDirective{}, false, nil
	}

	s.hostExhausted = false
	s.hostReasons[directive.Instance().Name()] = directive.Reason()

	if directive.Disposition() == AuthnHostDispositionSkipped {
		state := providerStateSkipped
		if directive.Reason() == AuthnHostReasonNotObserveSafe {
			state = providerStateUnavailable
		}

		s.hostStates[directive.Instance().Name()] = state

		return directive, true, nil
	}

	if directive.Disposition() != AuthnHostDispositionRun {
		return AuthnHostDirective{}, false, fmt.Errorf("%w: invalid host disposition", ErrDecisionEvaluation)
	}

	s.hostPending = directive.Instance().Name()

	return directive, true, nil
}

// RecordAuthnHostProvider accepts exactly one receipt for the last returned run directive.
func (s *decisionSession) RecordAuthnHostProvider(receipt AuthnHostReceipt) error {
	if s == nil {
		return fmt.Errorf("%w: invalid host session", ErrDecisionEvaluation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed || s.evaluating || receipt.Checkpoint == "" || receipt.Checkpoint != s.hostPlan ||
		receipt.Instance == "" || receipt.Instance != s.hostPending {
		return fmt.Errorf("%w: unexpected host provider receipt", ErrDecisionEvaluation)
	}

	state, ok := hostReceiptProviderState(receipt.State)
	if !ok {
		return fmt.Errorf("%w: invalid host provider receipt state", ErrDecisionEvaluation)
	}

	if receipt.Terminal && state != providerStateCompleted {
		return fmt.Errorf("%w: terminal host receipt must be completed", ErrDecisionEvaluation)
	}

	s.hostStates[receipt.Instance] = state
	s.hostPending = ""
	s.hostAuthn = receipt.Authenticated
	s.hostLastReceipt = receipt.Instance
	s.hostTerminal = receipt.Terminal

	return nil
}

// CompleteAuthnHostSchedule closes every unvisited host instance after an exact terminal host result.
func (s *decisionSession) CompleteAuthnHostSchedule(checkpoint string) error {
	if s == nil {
		return fmt.Errorf("%w: invalid host session", ErrDecisionEvaluation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.completeAuthnHostSchedule(checkpoint)
}

// completeAuthnHostSchedule closes unvisited instances while the session lock is held.
func (s *decisionSession) completeAuthnHostSchedule(checkpoint string) error {
	if !s.hostScheduleCompletionValid(checkpoint) {
		return fmt.Errorf("%w: invalid host schedule completion", ErrDecisionEvaluation)
	}

	scheduler, err := s.capturedAuthnHostScheduler()
	if err != nil {
		return err
	}

	remaining, cursor, err := scheduler.remainingAuthnHostProviders(
		s.request.Target(), checkpoint, s.hostCursor,
	)
	if err != nil {
		return err
	}

	for _, instanceName := range remaining {
		s.hostStates[instanceName] = providerStateSkipped
		s.hostReasons[instanceName] = AuthnHostReasonTerminal
	}

	s.hostCursor = cursor
	s.hostExhausted = true
	s.hostTerminal = false

	return nil
}

// hostScheduleCompletionValid requires one exact terminal receipt before early closure.
func (s *decisionSession) hostScheduleCompletionValid(checkpoint string) bool {
	return !s.closed && !s.evaluating && checkpoint != "" && checkpoint == s.hostPlan &&
		s.hostPending == "" && !s.hostExhausted && s.hostLastReceipt != "" && s.hostTerminal
}

// capturedAuthnHostScheduler returns the scheduler owned by the session generation.
func (s *decisionSession) capturedAuthnHostScheduler() (authnHostScheduler, error) {
	scheduler, ok := s.generation.evaluator.(authnHostScheduler)
	if !ok {
		return nil, fmt.Errorf("%w: host scheduler is unavailable", ErrDecisionEvaluation)
	}

	return scheduler, nil
}

// hostScheduleInputValid enforces current-plan ordering and one outstanding callback at a time.
func (s *decisionSession) hostScheduleInputValid(input AuthnHostScheduleInput) bool {
	return !s.closed && !s.evaluating && s.generation != nil && s.generation.valid() &&
		s.next < len(s.checkpoints) && input.Checkpoint != "" &&
		s.checkpoints[s.next].Name() == input.Checkpoint && s.hostPending == "" &&
		(s.hostPlan == "" || s.hostPlan == input.Checkpoint)
}

// hostReceiptProviderState converts the closed public receipt vocabulary into evaluator state.
func hostReceiptProviderState(receipt AuthnHostReceiptState) (providerState, bool) {
	switch receipt {
	case AuthnHostReceiptCompleted:
		return providerStateCompleted, true
	case AuthnHostReceiptFailed:
		return providerStateFailed, true
	case AuthnHostReceiptTimedOut:
		return providerStateTimedOut, true
	default:
		return "", false
	}
}

// cloneProviderStates detaches one checkpoint-local scheduler receipt map.
func cloneProviderStates(input map[string]providerState) map[string]providerState {
	result := make(map[string]providerState, len(input))
	for instance, state := range input {
		result[instance] = state
	}

	return result
}

// cloneProviderReasons detaches scheduler-owned disposition reasons by exact instance name.
func cloneProviderReasons(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for instance, reason := range input {
		result[instance] = reason
	}

	return result
}

var _ AuthnHostExecutionSession = (*decisionSession)(nil)
