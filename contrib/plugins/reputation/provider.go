package main

import (
	"context"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type observationProvider struct {
	plugin *Plugin
	config *configuration
}

// Descriptor declares bounded safe summaries and a provider-owned protected subject collection.
func (p observationProvider) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	outputs := []pluginapi.DecisionFactOutputDescriptor{
		{Name: outputValid, Kind: pluginapi.DecisionValueKindBoolean},
		{Name: outputEligible, Kind: pluginapi.DecisionValueKindBoolean},
		{Name: outputReason, Kind: pluginapi.DecisionValueKindString, MaxLength: 32},
		{Name: outputSourceClass, Kind: pluginapi.DecisionValueKindString, MaxLength: 64},
		{Name: outputOrigin, Kind: pluginapi.DecisionValueKindString, MaxLength: 32},
		{Name: outputKinds, Kind: pluginapi.DecisionValueKindStrings, MaxLength: 16, MaxItems: 6},
		{Name: outputSubjects, Kind: pluginapi.DecisionValueKindRecords},
	}
	for index := range outputs {
		outputs[index].Category = pluginapi.DecisionFactCategoryResource
	}

	return pluginapi.DecisionFactProviderDescriptor{Inputs: asnProviderInputs(p.config), Namespace: pluginName, Name: componentObservation, Targets: []pluginapi.DecisionTargetSelector{observeTarget}, Outputs: outputs, Timeout: time.Second}
}

// Collect validates source-owned evidence with a non-mutating manifest probe before Policy may select storage.
func (p observationProvider) Collect(ctx context.Context, request pluginapi.DecisionFactRequest) (pluginapi.DecisionFactResult, error) {
	if p.plugin == nil || request.Target() != observeTarget {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassInvalidInput}, nil
	}

	state, metrics := p.plugin.observedState()
	source := p.plugin.config.sourceForCaller(request.Caller())

	if state == nil || !state.ready.Load() {
		metrics.recordAdmission(ctx, source, metricUnknown, learningUnavailable, nil)
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassUnavailable}, nil
	}

	facts, resolver, err := state.config.splitASNProviderFacts(source, request.Facts())
	if err != nil {
		metrics.recordAdmission(ctx, source, metricUnknown, learningUnavailable, nil)
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassUnavailable}, nil
	}

	input, err := decodeObservationFacts(facts)
	if err != nil {
		state.telemetry.recordAdmission(ctx, source, metricUnknown, reasonInput, nil)
		return observationResult(admittedObservation{}, reasonInput)
	}

	admitted, reason, err := state.admitForPolicy(ctx, source, input, resolver)
	if err != nil {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassUnavailable}, nil
	}

	return observationResult(admitted, reason)
}
