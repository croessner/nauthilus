package main

import (
	"context"
	"errors"
	"slices"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	componentStorage       = "storage"
	effectStoreObservation = "store_observation"
)

type observationStorageProvider struct{ plugin *Plugin }

// Descriptor fixes synchronous idempotent storage to the exact admitted producer event ID.
func (observationStorageProvider) Descriptor() pluginapi.DecisionEffectProviderDescriptor {
	return pluginapi.DecisionEffectProviderDescriptor{Namespace: pluginName, Name: componentStorage, Effects: []pluginapi.DecisionEffectDescriptor{
		{Name: effectStoreObservation, Targets: []pluginapi.DecisionTargetSelector{observeTarget}, Execution: pluginapi.DecisionEffectExecutionHostSync,
			ReplaySafety: pluginapi.DecisionEffectReplayIdempotent, IdempotencyKey: observationPrefix + fieldEventID},
	}}
}

// Execute revalidates the complete protected plan and stores only an explicitly Policy-selected independent observation.
func (p observationStorageProvider) Execute(ctx context.Context, request pluginapi.DecisionEffectRequest) (pluginapi.DecisionEffectResult, error) {
	metric := learningRejected
	defer func() { p.plugin.recordLearning(ctx, learningExternal, metric) }()

	if !p.validRequest(request) {
		return failedObservationEffect(pluginapi.DecisionErrorClassInvalidInput), nil
	}

	identity := request.ExecutionIdentity()

	p.plugin.mu.RLock()
	state := p.plugin.state
	p.plugin.mu.RUnlock()

	if state == nil || !state.ready.Load() {
		metric = learningUnavailable
		return failedObservationEffect(pluginapi.DecisionErrorClassUnavailable), nil
	}

	input, frozen, err := decodeObservationEffectFacts(request.Facts(), identity.Module())
	if err != nil {
		return failedObservationEffect(pluginapi.DecisionErrorClassInvalidInput), nil
	}
	// This transport effect intentionally selects only API sources; its own host execution identity cannot impersonate an internal producer.
	source := state.config.sourceForCaller(request.Caller())

	admitted, reason, err := state.admitForPolicy(ctx, source, input, nil)
	if err != nil {
		metric = learningUnavailable
		return failedObservationEffect(pluginapi.DecisionErrorClassUnavailable), nil
	}

	if reason != reasonValid || !slices.Equal(admitted.subjects, frozen) {
		return failedObservationEffect(pluginapi.DecisionErrorClassInvalidInput), nil
	}

	result, err := state.ingest(ctx, admitted)
	metric = learningIngestionResult(result, err)

	return observationEffectOutcome(result, err), nil
}

// failedObservationEffect reports a definite pre-write rejection without inventing retry diagnostics.
func failedObservationEffect(class pluginapi.DecisionErrorClass) pluginapi.DecisionEffectResult {
	return pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeFailed, ErrorClass: class}
}

// observationEffectOutcome distinguishes successful duplicates, definite rejection and potentially partial writes.
func observationEffectOutcome(result ingestionResult, err error) pluginapi.DecisionEffectResult {
	if err == nil {
		return pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeSucceeded}
	}

	if result.Applied > 0 || result.Duplicates > 0 || errors.Is(err, errStateUnavailable) {
		return pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeUnknown, ErrorClass: pluginapi.DecisionErrorClassUnavailable}
	}

	if errors.Is(err, errEventConflict) || errors.Is(err, errEventTime) || errors.Is(err, errManifestPlan) {
		return failedObservationEffect(pluginapi.DecisionErrorClassInvalidInput)
	}

	return failedObservationEffect(pluginapi.DecisionErrorClassUnavailable)
}

// validRequest admits only the exact host-selected storage callback with no caller-selected parameters.
func (p observationStorageProvider) validRequest(request pluginapi.DecisionEffectRequest) bool {
	identity := request.ExecutionIdentity()

	return p.plugin != nil && request.Target() == observeTarget && request.Effect() == effectStoreObservation && len(request.Parameters()) == 0 &&
		identity.Component() == componentStorage && identity.ExtensionPoint() == "decision_effect" && identity.Operation() == effectStoreObservation
}
