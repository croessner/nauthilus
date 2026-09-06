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
	registry "github.com/croessner/nauthilus/v4/server/policy/registry"
	"testing"
)

func TestNativeDecisionInputSchemaRejectsHiddenOrWrongKindFields(t *testing.T) {
	input := pluginapi.DecisionFactInputDescriptor{
		ID: "resource.peers", Category: pluginapi.DecisionFactCategoryResource, Kind: pluginapi.DecisionValueKindRecords,
		Fields: []pluginapi.DecisionFactInputFieldDescriptor{{Name: "ip", Kind: pluginapi.DecisionValueKindString}},
	}
	provider := &nativeDecisionFactProvider{definition: nativeDecisionFactDefinition(t), descriptor: nativeDecisionFactDescriptor()}
	provider.descriptor.Inputs = []pluginapi.DecisionFactInputDescriptor{input}

	for _, test := range []struct {
		name       string
		visibility []string
		kind       decision.ValueKind
		valid      bool
	}{
		{name: "exact visibility", visibility: []string{testNativeDecisionFactProviderID}, kind: decision.ValueKindString, valid: true},
		{name: "hidden", visibility: []string{"mail/plugin.other.reader"}, kind: decision.ValueKindString},
		{name: "wrong kind", kind: decision.ValueKindBoolean},
	} {
		t.Run(test.name, func(t *testing.T) {
			fieldInput := registry.RecordFieldSchemaInput{Name: "ip", Kind: test.kind, ProviderVisibility: test.visibility}
			if test.kind == decision.ValueKindString {
				fieldInput.MaxLength = 64
			}

			field, err := registry.NewRecordFieldSchema(fieldInput)
			if err != nil {
				t.Fatal(err)
			}

			schema, err := registry.NewRecordSchema(registry.RecordSchemaInput{
				ID: "peers", Version: "v1", Fields: []registry.RecordFieldSchema{field}, MaxRecords: 8, MaxFields: 1, MaxAggregateBytes: 1024,
			})
			if err != nil {
				t.Fatal(err)
			}

			fact, err := registry.NewFactSchema(registry.FactSchemaInput{
				ID: input.ID, Category: decision.FactCategoryResource, Kind: decision.ValueKindRecords,
				AllowedSources: []decision.FactSource{decision.FactSourceCaller}, RecordSchema: &schema,
			})
			if err != nil {
				t.Fatal(err)
			}

			err = provider.ValidateInputSchema([]registry.FactSchema{fact})
			if (err == nil) != test.valid {
				t.Errorf("input schema validation error = %v, valid = %v", err, test.valid)
			}
		})
	}

	if err := provider.ValidateInputSchema(nil); err == nil {
		t.Fatal("missing input schema was accepted")
	}
}
