package main

import (
	"context"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type observationProvider struct{ plugin *Plugin }

// Descriptor declares bounded safe summaries and a provider-owned protected subject collection.
func (observationProvider) Descriptor() pluginapi.DecisionFactProviderDescriptor {
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

	return pluginapi.DecisionFactProviderDescriptor{Namespace: pluginName, Name: "observation_context", Targets: []pluginapi.DecisionTargetSelector{observeTarget}, Outputs: outputs, Timeout: time.Second}
}

// Collect validates source-owned pre-policy evidence without storage or final-outcome inference.
func (p observationProvider) Collect(ctx context.Context, request pluginapi.DecisionFactRequest) (pluginapi.DecisionFactResult, error) {
	if p.plugin == nil || request.Target() != observeTarget {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassInvalidInput}, nil
	}

	cfg, tagger := p.plugin.snapshot()
	if cfg == nil || tagger == nil {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassUnavailable}, nil
	}

	input, err := decodeObservationFacts(request.Facts())
	if err != nil {
		return observationResult(admittedObservation{}, reasonInput)
	}

	admitted, reason, err := cfg.admitObservation(ctx, cfg.sourceForCaller(request.Caller()), input, time.Now().UTC(), tagger, nil)
	if err != nil {
		return pluginapi.DecisionFactResult{ErrorClass: pluginapi.DecisionErrorClassUnavailable}, nil
	}

	return observationResult(admitted, reason)
}
