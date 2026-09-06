// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"fmt"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"strings"
)

const geoIPFactsSchema = "geoip.facts.v1"

type rawDecisionBinding struct {
	Targets      []string         `mapstructure:"targets"`
	Input        rawDecisionInput `mapstructure:"input"`
	Component    string           `mapstructure:"component"`
	OutputSchema string           `mapstructure:"output_schema"`
	OutputFact   string           `mapstructure:"output_fact"`
}

type rawDecisionInput struct {
	Records  *rawDecisionRecordInput        `mapstructure:"records"`
	Fact     string                         `mapstructure:"fact"`
	Category pluginapi.DecisionFactCategory `mapstructure:"category"`
}

// decisionBinding owns exact immutable registration metadata independently of lifecycle reloads.
type decisionBinding struct {
	descriptor pluginapi.DecisionFactProviderDescriptor
	input      rawDecisionInput
	outputFact string
}

// compileDecisionBindings rejects implicit, ambiguous, or incompatible target/input declarations.
func compileDecisionBindings(raw []rawDecisionBinding) ([]decisionBinding, error) {
	if len(raw) == 0 || len(raw) > 32 {
		return nil, fmt.Errorf("decision_bindings requires between 1 and 32 exact bindings")
	}

	bindings := make([]decisionBinding, 0, len(raw))
	components := make(map[string]struct{}, len(raw))
	targets := make(map[string]struct{})

	for _, candidate := range raw {
		binding, err := compileDecisionBinding(candidate)
		if err != nil {
			return nil, err
		}

		if _, duplicate := components[candidate.Component]; duplicate {
			return nil, fmt.Errorf("decision_bindings contains a duplicate component")
		}

		components[candidate.Component] = struct{}{}
		for _, target := range candidate.Targets {
			if _, duplicate := targets[target]; duplicate {
				return nil, fmt.Errorf("decision_bindings contains a target/output collision")
			}

			targets[target] = struct{}{}
		}

		bindings = append(bindings, binding)
	}

	return bindings, nil
}

// compileDecisionBinding builds one closed descriptor without any domain-specific target or input identity.
func compileDecisionBinding(raw rawDecisionBinding) (decisionBinding, error) {
	if len(raw.Targets) == 0 || len(raw.Targets) > 32 {
		return decisionBinding{}, fmt.Errorf("decision binding requires a closed output schema and bounded exact targets")
	}

	descriptor := pluginapi.DecisionFactProviderDescriptor{
		Name: raw.Component, Timeout: pluginapi.MaximumDecisionFactProviderTimeout,
		Outputs: geoIPDecisionFactOutputs(),
		Inputs:  []pluginapi.DecisionFactInputDescriptor{{ID: raw.Input.Fact, Category: raw.Input.Category, Kind: pluginapi.DecisionValueKindString}},
	}
	if err := compileDecisionInputOutput(raw, &descriptor); err != nil {
		return decisionBinding{}, err
	}

	for _, value := range raw.Targets {
		namespace, action, valid := strings.Cut(value, "/")
		if !valid || (descriptor.Namespace != "" && descriptor.Namespace != namespace) {
			return decisionBinding{}, fmt.Errorf("decision binding targets must share one exact namespace")
		}

		descriptor.Namespace = namespace
		descriptor.Targets = append(descriptor.Targets, pluginapi.DecisionTargetSelector{Namespace: namespace, Action: action})
	}

	if err := pluginapi.ValidateDecisionFactProviderDescriptor(descriptor); err != nil {
		return decisionBinding{}, fmt.Errorf("decision binding: %w", err)
	}

	return decisionBinding{descriptor: descriptor, input: raw.Input, outputFact: raw.OutputFact}, nil
}
