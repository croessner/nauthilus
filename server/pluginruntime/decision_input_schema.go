// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginruntime

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"slices"
)

// ValidateInputSchema verifies captured exact input types and provider-visible record fields before activation.
func (p *nativeDecisionFactProvider) ValidateInputSchema(facts []policyregistry.FactSchema) error {
	declared := make(map[string]policyregistry.FactSchema, len(facts))
	for _, fact := range facts {
		declared[fact.ID()] = fact
	}

	for _, input := range p.descriptor.Inputs {
		fact, exists := declared[input.ID]
		if !exists || string(fact.Category()) != string(input.Category) || string(fact.Kind()) != string(input.Kind) {
			return invalidDecisionBinding("required input fact is absent or has an incompatible category or kind")
		}

		if input.Provider != "" && !slices.Equal(fact.AllowedSources(), []decision.FactSource{decision.FactSourcePlugin}) {
			return invalidDecisionBinding("upstream input must be exclusively provider-owned")
		}

		if err := validateNativeInputFields(input, fact, p.definition.ID()); err != nil {
			return err
		}
	}

	return nil
}

// validateNativeInputFields rejects hidden, absent, or incompatible fields before any request can invoke the provider.
func validateNativeInputFields(input pluginapi.DecisionFactInputDescriptor, fact policyregistry.FactSchema, providerID string) error {
	if input.Kind != pluginapi.DecisionValueKindRecords {
		return nil
	}

	schema, exists := fact.RecordSchema()
	if !exists {
		return invalidDecisionBinding("required input record schema is absent")
	}

	for _, required := range input.Fields {
		field, found := schema.LookupField(required.Name)
		if !found || field.Kind() != decision.ValueKind(required.Kind) || !field.VisibleToProvider(providerID) {
			return invalidDecisionBinding("required input field is absent, hidden, or has an incompatible kind")
		}
	}

	return nil
}

// ValidateInputTarget requires exact upstream ownership and scheduling as well as input schema compatibility.
func (p *nativeDecisionFactProvider) ValidateInputTarget(target policyruntime.CompiledTarget) error {
	if err := p.ValidateInputSchema(target.Schema().Facts()); err != nil {
		return err
	}

	for _, input := range p.descriptor.Inputs {
		if input.Provider == "" {
			continue
		}

		producer, exists := target.LookupProvider(input.Provider)
		if !exists || !slices.Contains(producer.ProducedFacts(), input.ID) || !slices.Contains(p.definition.Requires(), input.Provider) {
			return invalidDecisionBinding("input requires its exact upstream provider owner and scheduler dependency")
		}
	}

	return nil
}
