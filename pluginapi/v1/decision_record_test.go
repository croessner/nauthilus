// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginapi

import "testing"

func TestDecisionRecordValueIsNonRecursiveAndDeeplyOwned(t *testing.T) {
	stringsValue := []string{"one"}

	leaf, err := NewDecisionValue(DecisionValueInput{Strings: stringsValue})
	if err != nil {
		t.Fatalf("NewDecisionValue(strings) error = %v", err)
	}

	fieldValue, _ := NewDecisionRecordFieldValue(leaf)
	field, _ := NewDecisionRecordField("labels", fieldValue)
	record, _ := NewDecisionRecord([]DecisionRecordField{field})
	records, _ := NewDecisionRecordList([]DecisionRecord{record})

	value, err := NewDecisionValue(DecisionValueInput{Records: &records})
	if err != nil {
		t.Fatalf("NewDecisionValue(records) error = %v", err)
	}

	stringsValue[0] = "changed"
	owned, _ := value.Records()
	member, _ := owned.Records()[0].Fields()[0].Value().Value().Strings()

	if len(member) != 1 || member[0] != "one" {
		t.Fatalf("owned record member = %#v", member)
	}

	if _, err = NewDecisionRecordFieldValue(value); err == nil {
		t.Fatal("NewDecisionRecordFieldValue() accepted recursive records")
	}
}

func TestDecisionEffectParameterDescriptorRejectsRecords(t *testing.T) {
	descriptor := DecisionEffectProviderDescriptor{
		Namespace: "mail", Name: "audit",
		Effects: []DecisionEffectDescriptor{{
			Name: "audit", Execution: DecisionEffectExecutionHostSync,
			Targets:    []DecisionTargetSelector{{Namespace: "mail", Action: "submit"}},
			Parameters: []DecisionEffectParameterDescriptor{{Name: "records", Kind: DecisionValueKindRecords}},
		}},
	}

	if err := ValidateDecisionEffectProviderDescriptor(descriptor); err == nil {
		t.Fatal("ValidateDecisionEffectProviderDescriptor() accepted record-valued parameters")
	}
}
