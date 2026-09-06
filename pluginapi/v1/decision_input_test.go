// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginapi

import (
	"errors"
	"testing"
)

func TestDecisionProviderInputContractRejectsInvalidDeclarations(t *testing.T) {
	for _, input := range []DecisionFactInputDescriptor{
		{ID: "plugin.geoip.ip", Provider: "authn/plugin.*", Category: DecisionFactCategoryEnvironment, Kind: DecisionValueKindString},
		{ID: " caller.ip", Category: DecisionFactCategoryEnvironment, Kind: DecisionValueKindString},
		{ID: "resource.peer", Category: "caller", Kind: DecisionValueKindString},
		{ID: "resource.peer", Category: DecisionFactCategoryResource, Kind: "ip"},
		{ID: "resource.peer", Category: DecisionFactCategoryResource, Kind: DecisionValueKindString, Fields: []DecisionFactInputFieldDescriptor{{Name: "ip", Kind: DecisionValueKindString}}},
		{ID: "resource.peers", Category: DecisionFactCategoryResource, Kind: DecisionValueKindRecords},
		{ID: "resource.peers", Category: DecisionFactCategoryResource, Kind: DecisionValueKindRecords, Fields: []DecisionFactInputFieldDescriptor{{Name: "ip", Kind: DecisionValueKindString}, {Name: "ip", Kind: DecisionValueKindString}}},
	} {
		descriptor := validDecisionFactProviderDescriptor(t)

		descriptor.Inputs = []DecisionFactInputDescriptor{input}
		if err := ValidateDecisionFactProviderDescriptor(descriptor); !errors.Is(err, ErrInvalidDecisionContract) {
			t.Errorf("invalid input declaration accepted: %#v", input)
		}
	}
}
