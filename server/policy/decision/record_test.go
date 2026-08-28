// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package decision

import "testing"

func TestRecordValueDeepCopiesEveryMutableMember(t *testing.T) {
	stringsValue := []string{"one"}
	bytesValue := []byte("two")

	stringsField, err := NewRecordFieldValue(RecordFieldValueInput{Strings: stringsValue})
	if err != nil {
		t.Fatalf("NewRecordFieldValue(strings) error = %v", err)
	}

	bytesField, err := NewRecordFieldValue(RecordFieldValueInput{Bytes: bytesValue})
	if err != nil {
		t.Fatalf("NewRecordFieldValue(bytes) error = %v", err)
	}

	record, err := NewRecord([]RecordField{
		mustRecordField(t, "labels", stringsField),
		mustRecordField(t, "digest", bytesField),
	})
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}

	records, err := NewRecordList([]Record{record})
	if err != nil {
		t.Fatalf("NewRecordList() error = %v", err)
	}

	value, err := NewValue(ValueInput{Records: &records})
	if err != nil {
		t.Fatalf("NewValue(records) error = %v", err)
	}

	stringsValue[0] = "changed"
	bytesValue[0] = 'X'

	first, ok := value.Records()
	if !ok {
		t.Fatal("records branch is not active")
	}

	owned := first.Records()
	fields := owned[0].Fields()
	gotStrings, _ := fields[0].Value().Strings()

	gotBytes, _ := fields[1].Value().Bytes()
	if gotStrings[0] != "one" || string(gotBytes) != "two" {
		t.Fatalf("owned values = %q, %q, want one, two", gotStrings, gotBytes)
	}

	gotStrings[0] = "later"
	gotBytes[0] = 'Y'

	second, _ := value.Records()
	secondFields := second.Records()[0].Fields()
	gotStrings, _ = secondFields[0].Value().Strings()

	gotBytes, _ = secondFields[1].Value().Bytes()
	if gotStrings[0] != "one" || string(gotBytes) != "two" {
		t.Fatalf("accessor mutation leaked into value: %q, %q", gotStrings, gotBytes)
	}
}

func TestRecordRejectsDuplicateFieldsAndRecursion(t *testing.T) {
	text := "value"

	fieldValue, err := NewRecordFieldValue(RecordFieldValueInput{String: &text})
	if err != nil {
		t.Fatalf("NewRecordFieldValue() error = %v", err)
	}

	field := mustRecordField(t, "name", fieldValue)
	if _, err = NewRecord([]RecordField{field, field}); err == nil {
		t.Fatal("NewRecord() accepted duplicate field names")
	}

	if _, err = NewRecord(nil); err == nil {
		t.Fatal("NewRecord() accepted an empty record")
	}

	if _, err = NewRecordFieldValue(RecordFieldValueInput{}); err == nil {
		t.Fatal("NewRecordFieldValue() accepted an absent kind")
	}
}

func TestRecordValuesAreExcludedFromEffectParameters(t *testing.T) {
	records, err := NewRecordList(nil)
	if err != nil {
		t.Fatalf("NewRecordList() error = %v", err)
	}

	value, err := NewValue(ValueInput{Records: &records})
	if err != nil {
		t.Fatalf("NewValue(records) error = %v", err)
	}

	if _, err = NewEffectRequest(EffectRequestInput{
		ID: "mail/audit", Parameters: map[string]Value{"records": value},
	}); err == nil {
		t.Fatal("NewEffectRequest() accepted record-valued parameters")
	}
}

func TestDiagnosticsRejectRecordValues(t *testing.T) {
	records, err := NewRecordList(nil)
	if err != nil {
		t.Fatalf("NewRecordList() error = %v", err)
	}

	value, err := NewValue(ValueInput{Records: &records})
	if err != nil {
		t.Fatalf("NewValue(records) error = %v", err)
	}

	if _, err = NewDiagnostics(map[string]Value{"records": value}); err == nil {
		t.Fatal("NewDiagnostics() accepted a record-list value")
	}
}

func TestRecordFactProvenanceKeepsCallerAndProviderCollectionsSeparate(t *testing.T) {
	records, _ := NewRecordList(nil)
	value, _ := NewValue(ValueInput{Records: &records})
	caller, _ := NewProvenance(FactSourceCaller, "client", "request")
	provider, _ := NewProvenance(FactSourcePlugin, "risk", "mail/plugin.risk.reader")

	callerFact, err := NewFact("resource.chain", FactCategoryResource, value, caller)
	if err != nil {
		t.Fatalf("NewFact(caller) error = %v", err)
	}

	providerFact, err := NewFact("plugin.risk.chain", FactCategoryResource, value, provider)
	if err != nil {
		t.Fatalf("NewFact(provider) error = %v", err)
	}

	if _, err = NewFact("plugin.risk.chain", FactCategoryResource, value, caller); err == nil {
		t.Fatal("NewFact() accepted forged caller ownership of a provider record collection")
	}

	separate, err := NewFactSet([]Fact{callerFact, providerFact})
	if err != nil || separate.Len() != 2 {
		t.Fatalf("separate caller/provider facts = %#v, %v", separate, err)
	}

	if _, err = NewFactSet([]Fact{providerFact, providerFact}); err == nil {
		t.Fatal("NewFactSet() accepted provider overwrite of an existing record-list fact")
	}
}

// mustRecordField constructs one test field through the public invariant.
func mustRecordField(t *testing.T, name string, value RecordFieldValue) RecordField {
	t.Helper()

	field, err := NewRecordField(name, value)
	if err != nil {
		t.Fatalf("NewRecordField(%q) error = %v", name, err)
	}

	return field
}
