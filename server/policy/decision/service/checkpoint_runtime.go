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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	defaultEvaluationTimeout = 5 * time.Second
	defaultPostActionBudget  = 30 * time.Second
)

type correlationIDGenerator interface {
	Next(string) (string, error)
}

type factProvider interface {
	Collect(context.Context, factProviderInput) ([]providedFact, error)
}

type factProviderCallCapturer interface {
	captureFactProviderCall() (factProvider, error)
}

type factProviderInput struct {
	facts      decision.FactSet
	target     decision.Target
	checkpoint string
}

type providedFact struct {
	id       string
	value    decision.Value
	category decision.FactCategory
}

type factProviderBinding struct {
	provider  factProvider
	source    decision.FactSource
	authority string
	component string
}

type checkpointRuntimeConfig struct {
	catalog           *policyruntime.TargetCatalog
	factProviders     map[string]factProviderBinding
	syncEffects       map[string]syncEffectBinding
	postActions       map[string]postActionBinding
	conditionSets     map[string][]decision.Value
	timeWindows       map[string]policyruntime.CompiledTimeWindow
	ids               correlationIDGenerator
	evaluationTimeout time.Duration
	postActionBudget  time.Duration
}

type checkpointRuntime struct {
	catalog           *policyruntime.TargetCatalog
	factProviders     map[string]factProviderBinding
	syncEffects       map[string]syncEffectBinding
	postActions       map[string]postActionBinding
	conditionSets     map[string][]decision.Value
	timeWindows       map[string]policyruntime.CompiledTimeWindow
	ids               correlationIDGenerator
	evaluationTimeout time.Duration
	postActionBudget  time.Duration
}

type providerState string

const (
	providerStateCompleted providerState = "completed"
	providerStateSkipped   providerState = "skipped"
	providerStateFailed    providerState = "failed"
	providerStateTimedOut  providerState = "timed_out"
)

type providerRecord struct {
	id    string
	state providerState
}

type effectRecord struct {
	id       string
	provider string
	state    effectsupervisor.State
	ordinal  uint32
}

type runtimeReport struct {
	facts       decision.FactSet
	providers   []providerRecord
	effects     []effectRecord
	policySet   string
	rule        string
	outcomeCode decision.StatusCode
}

// newCheckpointRuntime constructs the package-private catalog-bound evaluator.
func newCheckpointRuntime(config checkpointRuntimeConfig) (*checkpointRuntime, error) {
	if config.catalog == nil {
		return nil, fmt.Errorf("%w: target catalog is required", ErrDecisionServiceDependencyMissing)
	}

	timeout := config.evaluationTimeout
	if timeout == 0 {
		timeout = defaultEvaluationTimeout
	}

	budget := config.postActionBudget
	if budget == 0 {
		budget = defaultPostActionBudget
	}

	if timeout <= 0 || budget <= 0 {
		return nil, fmt.Errorf("%w: runtime timeouts must be positive", ErrDecisionServiceDependencyMissing)
	}

	ids := config.ids
	if ids == nil {
		ids = randomCorrelationIDGenerator{}
	}

	return &checkpointRuntime{
		catalog:           config.catalog.Clone(),
		factProviders:     cloneFactProviderBindings(config.factProviders),
		syncEffects:       cloneSyncEffectBindings(config.syncEffects),
		postActions:       clonePostActionBindings(config.postActions),
		conditionSets:     cloneConditionSets(config.conditionSets),
		timeWindows:       cloneTimeWindows(config.timeWindows),
		ids:               ids,
		evaluationTimeout: timeout,
		postActionBudget:  budget,
	}, nil
}

// Evaluate executes one complete checkpoint lifecycle on captured generation state.
func (r *checkpointRuntime) Evaluate(ctx context.Context, input checkpointEvaluation) (runtimeEvaluation, error) {
	if r == nil || !input.valid() {
		return runtimeEvaluation{}, fmt.Errorf("%w: invalid runtime input", ErrDecisionEvaluation)
	}

	target, ok := r.catalog.Lookup(input.request.Target())
	if !ok {
		return runtimeEvaluation{}, fmt.Errorf("%w: admitted target is absent", ErrDecisionEvaluation)
	}

	checkpoint, ok := target.DomainPlan().Checkpoint(input.checkpoint.Name())
	if !ok {
		return runtimeEvaluation{}, fmt.Errorf("%w: admitted checkpoint is absent", ErrDecisionEvaluation)
	}

	evaluationContext, cancel := context.WithTimeout(normalizeContext(ctx), r.evaluationTimeout)
	defer cancel()

	decisionID, requestID, err := r.correlationIDs(input.request)
	if err != nil {
		return runtimeEvaluation{}, fmt.Errorf("%w: correlation identity generation failed", ErrDecisionEvaluation)
	}

	facts, err := buildAdmittedFacts(input.request, input.checkpoint.Facts(), target.Schema())
	if err != nil {
		return r.indeterminate(input, target, decisionID, requestID, decision.StatusCodeEvaluationFailed, runtimeReport{}), nil
	}

	if err = validateAdmittedFacts(facts, target, checkpoint); err != nil {
		return r.indeterminate(input, target, decisionID, requestID, decision.StatusCodeEvaluationFailed, runtimeReport{facts: facts}), nil
	}

	report := runtimeReport{facts: facts}
	facts, providersReliable := r.runProviders(evaluationContext, target, checkpoint, facts, &report)
	report.facts = facts

	if !providersReliable || evaluationContext.Err() != nil {
		code := decision.StatusCodeProviderUnavailable
		if errors.Is(evaluationContext.Err(), context.Canceled) {
			code = decision.StatusCodeEvaluationFailed
		}

		return r.indeterminate(input, target, decisionID, requestID, code, report), nil
	}

	if err := target.Schema().ValidateFacts(facts); err != nil {
		return r.indeterminate(input, target, decisionID, requestID, decision.StatusCodeProviderUnavailable, report), nil
	}

	selected := r.selectRule(target, checkpoint, facts, report.providers)
	response, report, _ := r.finalizeSelection(evaluationContext, input, target, selected, decisionID, requestID, report)

	return runtimeEvaluation{
		response: response,
		report: internalDecisionReport{
			checkpoint: input.checkpoint.Name(),
			generation: input.generation,
			runtime:    report,
		},
	}, nil
}

// validateAdmittedFacts rejects invalid supplied values and impossible required facts before providers run.
func validateAdmittedFacts(
	facts decision.FactSet,
	target policyruntime.CompiledTarget,
	checkpoint policyruntime.CompiledCheckpoint,
) error {
	schema := target.Schema()
	if err := schema.ValidatePresentFacts(facts); err != nil {
		return err
	}

	produced := make(map[string]struct{})

	for _, providerID := range checkpoint.ProviderIDs() {
		provider, _ := target.LookupProvider(providerID)

		for _, factID := range provider.ProducedFacts() {
			produced[factID] = struct{}{}
		}
	}

	for _, definition := range schema.Facts() {
		if !definition.Required() {
			continue
		}

		if _, exists := facts.Get(definition.ID()); exists {
			continue
		}

		if _, exists := produced[definition.ID()]; !exists {
			return fmt.Errorf("required fact %s has no admitted value or scheduled producer", definition.ID())
		}
	}

	return nil
}

// correlationIDs creates fresh decision identity and fills an omitted request correlation value.
func (r *checkpointRuntime) correlationIDs(request decision.DecisionRequest) (string, string, error) {
	decisionID, err := r.ids.Next("decision")
	if err != nil {
		return "", "", err
	}

	requestID := request.RequestID().String()
	if requestID == "" {
		requestID, err = r.ids.Next("request")
	}

	return decisionID, requestID, err
}

// runProviders executes dependency levels and discards unreliable concurrent-level output.
func (r *checkpointRuntime) runProviders(
	ctx context.Context,
	target policyruntime.CompiledTarget,
	checkpoint policyruntime.CompiledCheckpoint,
	facts decision.FactSet,
	report *runtimeReport,
) (decision.FactSet, bool) {
	states := make(map[string]providerState)

	for _, level := range checkpoint.ProviderLevels() {
		levelFacts, reliable := r.runProviderLevel(ctx, target, checkpoint.Name(), level, facts, states, report)
		if !reliable {
			return facts, false
		}

		combined := append(facts.Facts(), levelFacts...)

		owned, err := decision.NewFactSet(combined)
		if err != nil {
			return facts, false
		}

		facts = owned
	}

	return facts, true
}

type providerLevelResult struct {
	id       string
	facts    []decision.Fact
	state    providerState
	failure  registry.ProviderFailureBehavior
	reliable bool
}

// runProviderLevel executes one deterministic concurrent dependency level.
func (r *checkpointRuntime) runProviderLevel(
	ctx context.Context,
	target policyruntime.CompiledTarget,
	checkpoint string,
	level []string,
	facts decision.FactSet,
	states map[string]providerState,
	report *runtimeReport,
) ([]decision.Fact, bool) {
	levelContext, cancel := context.WithCancel(ctx)
	defer cancel()

	results, pending := r.startProviderLevel(levelContext, target, checkpoint, level, facts, states, report)
	ordered := make([]providerLevelResult, 0, len(pending))

	for len(pending) > 0 {
		select {
		case result := <-results:
			delete(pending, result.id)
			ordered = append(ordered, result)

			if !result.reliable && result.failure == registry.ProviderFailureIndeterminate {
				cancel()

				ordered = append(ordered, canceledProviderResults(pending, providerStateFailed)...)

				return applyProviderResults(sortProviderResults(ordered), states, report)
			}
		case <-ctx.Done():
			cancel()

			state := providerStateFailed
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				state = providerStateTimedOut
			}

			ordered = append(ordered, canceledProviderResults(pending, state)...)

			return applyProviderResults(sortProviderResults(ordered), states, report)
		}
	}

	return applyProviderResults(sortProviderResults(ordered), states, report)
}

// startProviderLevel opens every runnable member before result processing begins.
func (r *checkpointRuntime) startProviderLevel(
	ctx context.Context,
	target policyruntime.CompiledTarget,
	checkpoint string,
	level []string,
	facts decision.FactSet,
	states map[string]providerState,
	report *runtimeReport,
) (<-chan providerLevelResult, map[string]struct{}) {
	results := make(chan providerLevelResult, len(level))
	pending := make(map[string]struct{}, len(level))
	started := make(chan struct{}, len(level))

	for _, providerID := range level {
		descriptor, _ := target.LookupProvider(providerID)
		if providerDependencySkipped(descriptor, states) {
			states[providerID] = providerStateSkipped
			report.providers = append(report.providers, providerRecord{id: providerID, state: providerStateSkipped})

			continue
		}

		pending[providerID] = struct{}{}

		binding, err := captureFactProviderBinding(r.factProviders[providerID])
		if err != nil {
			started <- struct{}{}

			results <- providerLevelResult{
				id: providerID, failure: descriptor.Failure(), state: providerStateFailed,
			}

			continue
		}

		go func(provider registry.ProviderDefinition, captured factProviderBinding) {
			started <- struct{}{}

			results <- r.collectProviderSafely(ctx, target.Target(), checkpoint, provider, captured, facts)
		}(descriptor, binding)
	}

	for range pending {
		<-started
	}

	return results, pending
}

// captureFactProviderBinding reserves generation ownership before provider goroutines start.
func captureFactProviderBinding(binding factProviderBinding) (factProviderBinding, error) {
	capturer, ok := binding.provider.(factProviderCallCapturer)
	if !ok {
		return binding, nil
	}

	provider, err := capturer.captureFactProviderCall()
	if err != nil {
		return factProviderBinding{}, err
	}

	binding.provider = provider

	return binding, nil
}

// collectProviderSafely contains provider panics and returns a fail-closed level result.
func (r *checkpointRuntime) collectProviderSafely(
	ctx context.Context,
	target decision.Target,
	checkpoint string,
	descriptor registry.ProviderDefinition,
	binding factProviderBinding,
	facts decision.FactSet,
) (result providerLevelResult) {
	result = providerLevelResult{
		id: descriptor.ID(), failure: registry.ProviderFailureIndeterminate, state: providerStateFailed,
	}

	defer func() {
		if recover() != nil {
			result = providerLevelResult{
				id: descriptor.ID(), failure: registry.ProviderFailureIndeterminate, state: providerStateFailed,
			}
		}
	}()

	return r.collectProvider(ctx, target, checkpoint, descriptor, binding, facts)
}

// canceledProviderResults projects deterministic failure records for output that will be discarded.
func canceledProviderResults(pending map[string]struct{}, state providerState) []providerLevelResult {
	results := make([]providerLevelResult, 0, len(pending))

	for providerID := range pending {
		results = append(results, providerLevelResult{
			id: providerID, state: state, failure: registry.ProviderFailureIndeterminate,
		})
	}

	return results
}

// sortProviderResults orders one completed or canceled level by canonical provider identity.
func sortProviderResults(results []providerLevelResult) []providerLevelResult {
	sort.Slice(results, func(left int, right int) bool { return results[left].id < results[right].id })

	return results
}

// applyProviderResults records state and retains facts only from a reliable level.
func applyProviderResults(
	ordered []providerLevelResult,
	states map[string]providerState,
	report *runtimeReport,
) ([]decision.Fact, bool) {
	levelReliable := true

	for _, result := range ordered {
		states[result.id] = result.state
		report.providers = append(report.providers, providerRecord{id: result.id, state: result.state})

		if !result.reliable && result.failure == registry.ProviderFailureIndeterminate {
			levelReliable = false
		}
	}

	if !levelReliable {
		return nil, false
	}

	collected := make([]decision.Fact, 0)

	for _, result := range ordered {
		if result.reliable {
			collected = append(collected, result.facts...)
		}
	}

	return collected, true
}

// collectProvider invokes one exact binding and assigns host-owned provenance.
func (r *checkpointRuntime) collectProvider(
	ctx context.Context,
	target decision.Target,
	checkpoint string,
	descriptor registry.ProviderDefinition,
	binding factProviderBinding,
	facts decision.FactSet,
) providerLevelResult {
	result := providerLevelResult{id: descriptor.ID(), failure: descriptor.Failure(), state: providerStateFailed}

	if nilDependency(binding.provider) {
		return result
	}

	providerContext, cancel := context.WithTimeout(ctx, descriptor.Timeout())
	defer cancel()

	provided, err := binding.provider.Collect(providerContext, factProviderInput{facts: facts, target: target, checkpoint: checkpoint})
	if err != nil {
		if errors.Is(providerContext.Err(), context.DeadlineExceeded) {
			result.state = providerStateTimedOut
		}

		return result
	}

	provenance, err := decision.NewProvenance(binding.source, binding.authority, binding.component)
	if err != nil {
		result.failure = registry.ProviderFailureIndeterminate

		return result
	}

	declared := stringSet(descriptor.ProducedFacts())
	result.facts = make([]decision.Fact, 0, len(provided))

	for _, output := range provided {
		if _, ok := declared[output.id]; !ok {
			result.failure = registry.ProviderFailureIndeterminate

			return result
		}

		fact, factErr := decision.NewFact(output.id, output.category, output.value, provenance)
		if factErr != nil {
			result.failure = registry.ProviderFailureIndeterminate

			return result
		}

		result.facts = append(result.facts, fact)
	}

	result.state = providerStateCompleted
	result.reliable = true

	return result
}

// providerDependencySkipped applies transitive safe skipping through level state.
func providerDependencySkipped(provider registry.ProviderDefinition, states map[string]providerState) bool {
	for _, dependency := range provider.Requires() {
		if states[dependency] != providerStateCompleted {
			return true
		}
	}

	return false
}

// indeterminate constructs one stable safe evaluation-failure projection.
func (r *checkpointRuntime) indeterminate(
	input checkpointEvaluation,
	target policyruntime.CompiledTarget,
	decisionID string,
	requestID string,
	code decision.StatusCode,
	report runtimeReport,
) runtimeEvaluation {
	status, _ := decision.NewStatus(code, "The admitted policy evaluation could not complete reliably.", nil)
	metadata := policyMetadata(target, input.generation, report.policySet, report.rule)
	diagnostics := sanitizeDiagnostics(input.request, target, input.checkpoint.Name(), input.generation, code, report)
	response, _ := decision.NewDecisionResponse(decision.DecisionResponseInput{
		RequestID: requestID, DecisionID: decisionID, Effect: decision.EffectIndeterminate,
		Status: status, Policy: metadata, Diagnostics: diagnostics,
	})

	return runtimeEvaluation{
		response: response,
		report:   internalDecisionReport{checkpoint: input.checkpoint.Name(), generation: input.generation, runtime: report},
	}
}

// policyMetadata creates bounded metadata for selected rules and explicit no-match outcomes.
func policyMetadata(
	target policyruntime.CompiledTarget,
	generation uint64,
	policySet string,
	rule string,
) decision.PolicyMetadata {
	if policySet == "" {
		policySet = target.DefaultPolicySet().String()
	}

	if _, err := registry.ParsePolicySetID("runtime.policy", policySet); err != nil {
		policySet = target.Target().Namespace() + "/no_match"
	}

	metadata, _ := decision.NewPolicyMetadata(policySet, target.Schema().Identity().Version().String(), rule, generation)

	return metadata
}

// buildAdmittedFacts constructs request-local caller and trusted facts without mutating schema state.
func buildAdmittedFacts(
	request decision.DecisionRequest,
	checkpointFacts decision.FactSet,
	schema policyruntime.CompiledSchema,
) (decision.FactSet, error) {
	definitions := make(map[string]registry.FactSchema)
	for _, definition := range schema.Facts() {
		definitions[definition.ID()] = definition
	}

	callerProvenance, err := decision.NewProvenance(decision.FactSourceCaller, request.Caller().Principal(), "request")
	if err != nil {
		return decision.FactSet{}, err
	}

	facts := append([]decision.Fact(nil), checkpointFacts.Facts()...)
	if err := appendCallerAttributes(&facts, "subject", request.Subject().Attributes(), definitions, callerProvenance); err != nil {
		return decision.FactSet{}, err
	}

	if err := appendCallerAttributes(&facts, "resource", request.Resource().Attributes(), definitions, callerProvenance); err != nil {
		return decision.FactSet{}, err
	}

	if err := appendCallerAttributes(&facts, "environment", request.Environment().Attributes(), definitions, callerProvenance); err != nil {
		return decision.FactSet{}, err
	}

	if err := appendCallerAttributes(&facts, "input", request.Attributes(), definitions, callerProvenance); err != nil {
		return decision.FactSet{}, err
	}

	trusted, err := trustedRequestFacts(request, definitions)
	if err != nil {
		return decision.FactSet{}, err
	}

	facts = append(facts, trusted...)

	return decision.NewFactSet(facts)
}

// appendCallerAttributes adds one exact admitted assertion category with caller provenance.
func appendCallerAttributes(
	facts *[]decision.Fact,
	prefix string,
	values decision.ValueMap,
	definitions map[string]registry.FactSchema,
	provenance decision.Provenance,
) error {
	owned := values.Values()

	for _, key := range sortedValueKeys(values) {
		id := prefix + "." + key

		definition, exists := definitions[id]
		if !exists {
			return fmt.Errorf("caller fact %s is undeclared", id)
		}

		fact, err := decision.NewFact(id, definition.Category(), owned[key], provenance)
		if err != nil {
			return err
		}

		*facts = append(*facts, fact)
	}

	return nil
}

// trustedRequestFacts projects only exact schema-declared caller, token, and transport evidence.
func trustedRequestFacts(
	request decision.DecisionRequest,
	definitions map[string]registry.FactSchema,
) ([]decision.Fact, error) {
	caller := request.Caller()
	values := make(map[string]trustedFactValue)
	addTrustedString(values, decision.FactCallerPrincipal, caller.Principal(), decision.FactSourceNauthilus)
	addTrustedString(values, decision.FactCallerClientID, caller.ClientID(), decision.FactSourceNauthilus)
	addTrustedString(values, decision.FactCallerAuthenticationKind, caller.AuthenticationKind(), decision.FactSourceNauthilus)
	addTrustedStrings(values, decision.FactCallerScopes, caller.Scopes(), decision.FactSourceNauthilus)
	addTrustedString(values, decision.FactTokenSubject, caller.Subject(), decision.FactSourceToken)
	addTrustedString(values, decision.FactTokenIssuer, caller.Issuer(), decision.FactSourceToken)
	addTrustedString(values, decision.FactTransportKind, caller.TransportKind(), decision.FactSourceTransport)
	addTrustedString(values, decision.FactTransportListener, caller.Listener(), decision.FactSourceTransport)
	addTrustedString(values, decision.FactTransportHTTPRoute, caller.HTTPRoute(), decision.FactSourceTransport)
	addTrustedString(values, decision.FactTransportGRPCMethod, caller.GRPCMethod(), decision.FactSourceTransport)
	addTrustedString(values, decision.FactTransportMTLSIdentity, caller.MTLSIdentity(), decision.FactSourceTransport)

	if caller.SourceIP().IsValid() {
		addTrustedString(values, decision.FactTransportSourceIP, caller.SourceIP().String(), decision.FactSourceTransport)
	}

	result := make([]decision.Fact, 0, len(values))
	keys := make([]string, 0, len(values))

	for id := range values {
		keys = append(keys, id)
	}

	sort.Strings(keys)

	for _, id := range keys {
		definition, declared := definitions[id]
		if !declared {
			continue
		}

		entry := values[id]

		provenance, provenanceErr := decision.NewProvenance(entry.source, caller.Principal(), "authenticator")
		if provenanceErr != nil {
			return nil, provenanceErr
		}

		fact, factErr := decision.NewFact(id, definition.Category(), entry.value, provenance)
		if factErr != nil {
			return nil, factErr
		}

		result = append(result, fact)
	}

	return result, nil
}

type trustedFactValue struct {
	value  decision.Value
	source decision.FactSource
}

// addTrustedString constructs one non-empty trusted scalar without exposing raw caller input.
func addTrustedString(values map[string]trustedFactValue, id string, input string, source decision.FactSource) {
	if input == "" {
		return
	}

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err == nil {
		values[id] = trustedFactValue{value: value, source: source}
	}
}

// addTrustedStrings constructs one deterministic non-empty trusted string list.
func addTrustedStrings(values map[string]trustedFactValue, id string, input []string, source decision.FactSource) {
	if len(input) == 0 {
		return
	}

	owned := append([]string(nil), input...)
	sort.Strings(owned)

	value, err := decision.NewValue(decision.ValueInput{Strings: owned})
	if err == nil {
		values[id] = trustedFactValue{value: value, source: source}
	}
}

// sortedValueKeys returns deterministic immutable map traversal order.
func sortedValueKeys(values decision.ValueMap) []string {
	owned := values.Values()
	keys := make([]string, 0, len(owned))

	for key := range owned {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

// stringSet indexes exact immutable identities.
func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}

	return result
}

// cloneFactProviderBindings copies one generation-owned binding map.
func cloneFactProviderBindings(input map[string]factProviderBinding) map[string]factProviderBinding {
	result := make(map[string]factProviderBinding, len(input))
	for id, binding := range input {
		result[id] = binding
	}

	return result
}

// cloneConditionSets deeply owns referenced strict operands.
func cloneConditionSets(input map[string][]decision.Value) map[string][]decision.Value {
	result := make(map[string][]decision.Value, len(input))
	for id, values := range input {
		result[id] = append([]decision.Value(nil), values...)
	}

	return result
}

// cloneTimeWindows deeply owns recurring time-window inputs from the captured generation.
func cloneTimeWindows(input map[string]policyruntime.CompiledTimeWindow) map[string]policyruntime.CompiledTimeWindow {
	result := make(map[string]policyruntime.CompiledTimeWindow, len(input))

	for id, window := range input {
		window.Days = append([]time.Weekday(nil), window.Days...)
		window.Intervals = append([]policyruntime.CompiledTimeInterval(nil), window.Intervals...)
		result[id] = window
	}

	return result
}

type randomCorrelationIDGenerator struct{}

// Next generates one fresh cryptographically random bounded identity.
func (randomCorrelationIDGenerator) Next(prefix string) (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	return prefix + "-" + hex.EncodeToString(buffer), nil
}

// safeStatusMessage returns one stable public message for completed outcomes.
func safeStatusMessage(effect decision.Effect) string {
	switch effect {
	case decision.EffectPermit:
		return "The policy explicitly permitted the operation."
	case decision.EffectDeny:
		return "The policy denied the operation."
	case decision.EffectNotApplicable:
		return "No applicable policy rule selected a decision."
	default:
		return "The policy evaluation completed."
	}
}

// selectedProviderCompleted reports whether one required provider completed successfully.
func selectedProviderCompleted(records []providerRecord, id string) bool {
	for _, record := range records {
		if record.id == id {
			return record.state == providerStateCompleted
		}
	}

	return false
}

// providerAliasStatus maps internal provider state to the fixed public vocabulary.
func providerAliasStatus(state providerState) string {
	switch state {
	case providerStateCompleted:
		return "completed"
	case providerStateSkipped:
		return "skipped"
	case providerStateTimedOut:
		return "timed_out"
	default:
		return string(providerStateFailed)
	}
}
