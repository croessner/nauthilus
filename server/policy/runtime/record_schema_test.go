// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package runtime

import (
	"fmt"
	"sync"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

func TestRecordSchemaNormalizesFieldsAndEnforcesAllLimits(t *testing.T) {
	schema := recordCompiledSchema(t, 2, 2, 16)
	value := recordValue(t, []recordTestField{{"result", "pass"}, {"sequence", int64(1)}})

	normalized, err := schema.NormalizeValue("resource.chain", value)
	if err != nil {
		t.Fatalf("NormalizeValue() error = %v", err)
	}

	records, _ := normalized.Records()
	fields := records.Records()[0].Fields()

	if len(fields) != 2 || fields[0].Name() != "sequence" || fields[1].Name() != "result" {
		t.Fatalf("normalized field order = %#v", fields)
	}

	tests := map[string]decision.Value{
		"record count": recordValue(t,
			[]recordTestField{{"sequence", int64(1)}},
			[]recordTestField{{"sequence", int64(2)}},
			[]recordTestField{{"sequence", int64(3)}},
		),
		"field count": recordValue(t, []recordTestField{{"sequence", int64(1)}, {"result", "pass"}, {"extra", true}}),
		"per value":   recordValue(t, []recordTestField{{"sequence", int64(1)}, {"result", "toolong"}}),
		"aggregate": recordValue(t,
			[]recordTestField{{"sequence", int64(1)}, {"result", "123456"}},
			[]recordTestField{{"sequence", int64(2)}},
		),
	}

	for name, invalid := range tests {
		t.Run(name, func(t *testing.T) {
			if _, normalizeErr := schema.NormalizeValue("resource.chain", invalid); normalizeErr == nil {
				t.Fatal("NormalizeValue() accepted an out-of-bounds record collection")
			}
		})
	}
}

func TestRecordSchemaFiltersFreshProviderViewsWithoutExposingProtectedFields(t *testing.T) {
	schema, facts := recordProviderSchemaAndFacts(t)

	facts, err := schema.NormalizeFacts(facts)
	if err != nil {
		t.Fatalf("NormalizeFacts() error = %v", err)
	}

	assessor, err := schema.FactsForProvider(facts, "mail/plugin.reputation.assessor")
	if err != nil {
		t.Fatalf("FactsForProvider(assessor) error = %v", err)
	}

	other, err := schema.FactsForProvider(facts, "mail/plugin.other.reader")
	if err != nil {
		t.Fatalf("FactsForProvider(other) error = %v", err)
	}

	assessorFact, _ := assessor.Get("resource.chain")
	assessorRecords, _ := assessorFact.Value().Records()

	if len(assessorRecords.Records()[0].Fields()) != 2 {
		t.Fatal("authorized provider did not receive both fields")
	}

	assessorBytes, _ := assessorRecords.Records()[0].Fields()[1].Value().Bytes()
	assessorBytes[0] = 'X'
	freshAssessor, _ := schema.FactsForProvider(facts, "mail/plugin.reputation.assessor")
	freshFact, _ := freshAssessor.Get("resource.chain")
	freshRecords, _ := freshFact.Value().Records()
	freshBytes, _ := freshRecords.Records()[0].Fields()[1].Value().Bytes()

	if string(freshBytes) != "secret" {
		t.Fatalf("provider mutation leaked into a later snapshot: %q", freshBytes)
	}

	otherFact, _ := other.Get("resource.chain")
	otherRecords, _ := otherFact.Value().Records()
	fields := otherRecords.Records()[0].Fields()

	if len(fields) != 1 || fields[0].Name() != "sequence" {
		t.Fatalf("protected field leaked to another provider: %#v", fields)
	}
}

func TestRecordSchemaConcurrentProviderSnapshotsRemainIsolated(t *testing.T) {
	schema, facts := recordProviderSchemaAndFacts(t)

	normalized, err := schema.NormalizeFacts(facts)
	if err != nil {
		t.Fatalf("NormalizeFacts() error = %v", err)
	}

	const workers = 32

	errorsFound := make(chan error, workers)
	wait := sync.WaitGroup{}
	wait.Add(workers)

	for index := range workers {
		go func() {
			defer wait.Done()

			if err := mutateAndCheckProviderSnapshot(schema, normalized, index); err != nil {
				errorsFound <- err
			}
		}()
	}

	wait.Wait()
	close(errorsFound)

	for workerErr := range errorsFound {
		if workerErr != nil {
			t.Fatal(workerErr)
		}
	}
}

// mutateAndCheckProviderSnapshot proves one provider mutation cannot escape its detached view.
func mutateAndCheckProviderSnapshot(schema CompiledSchema, facts decision.FactSet, index int) error {
	snapshot, err := schema.FactsForProvider(facts, "mail/plugin.reputation.assessor")
	if err != nil {
		return err
	}

	value, err := providerPayloadBytes(snapshot)
	if err != nil {
		return err
	}

	value[0] = byte('A' + index%26)

	fresh, err := schema.FactsForProvider(facts, "mail/plugin.reputation.assessor")
	if err != nil {
		return err
	}

	freshValue, err := providerPayloadBytes(fresh)
	if err != nil {
		return err
	}

	if string(freshValue) != "secret" {
		return fmt.Errorf("fresh provider payload = %q", freshValue)
	}

	return nil
}

// providerPayloadBytes returns one detached protected payload from a provider snapshot.
func providerPayloadBytes(facts decision.FactSet) ([]byte, error) {
	fact, exists := facts.Get("resource.chain")
	if !exists {
		return nil, fmt.Errorf("resource.chain fact is missing")
	}

	records, exists := fact.Value().Records()
	if !exists || len(records.Records()) != 1 {
		return nil, fmt.Errorf("resource.chain records are invalid")
	}

	fields := records.Records()[0].Fields()
	if len(fields) != 2 || fields[1].Name() != "payload" {
		return nil, fmt.Errorf("protected payload field is missing")
	}

	value, exists := fields[1].Value().Bytes()
	if !exists {
		return nil, fmt.Errorf("protected payload kind is invalid")
	}

	return value, nil
}

// recordProviderSchemaAndFacts constructs one caller snapshot with a provider-protected field.
func recordProviderSchemaAndFacts(t *testing.T) (CompiledSchema, decision.FactSet) {
	t.Helper()

	sequence := recordFieldSchema(t, registry.RecordFieldSchemaInput{
		Name: "sequence", Kind: decision.ValueKindInteger, Required: true, ExpressionVisible: true,
	})
	payload := recordFieldSchema(t, registry.RecordFieldSchemaInput{
		Name: "payload", Kind: decision.ValueKindBytes, MaxBytes: 16,
		ProviderVisibility: []string{"mail/plugin.reputation.assessor"},
	})
	records, _ := registry.NewRecordSchema(registry.RecordSchemaInput{
		ID: "chain", Version: "v1", Fields: []registry.RecordFieldSchema{sequence, payload},
		MaxRecords: 2, MaxFields: 2, MaxAggregateBytes: 64,
	})
	factSchema, _ := registry.NewFactSchema(registry.FactSchemaInput{
		ID: "resource.chain", Category: decision.FactCategoryResource, Kind: decision.ValueKindRecords,
		AllowedSources: []decision.FactSource{decision.FactSourceCaller}, RecordSchema: &records,
	})
	identity, _ := registry.NewSchemaIdentity("mail", "submit", "v1")
	schema := newCompiledSchema(identity, []registry.FactSchema{factSchema})
	provenance, _ := decision.NewProvenance(decision.FactSourceCaller, "client", "request")
	value := recordValue(t, []recordTestField{{"payload", []byte("secret")}, {"sequence", int64(1)}})
	fact, _ := decision.NewFact("resource.chain", decision.FactCategoryResource, value, provenance)
	facts, _ := decision.NewFactSet([]decision.Fact{fact})

	return schema, facts
}

type recordTestField struct {
	name  string
	value any
}

// recordCompiledSchema constructs one exact schema for normalization tests.
func recordCompiledSchema(t *testing.T, maxRecords int, maxFields int, maxAggregate int) CompiledSchema {
	t.Helper()

	sequence := recordFieldSchema(t, registry.RecordFieldSchemaInput{
		Name: "sequence", Kind: decision.ValueKindInteger, Required: true, ExpressionVisible: true,
	})
	result := recordFieldSchema(t, registry.RecordFieldSchemaInput{
		Name: "result", Kind: decision.ValueKindString, MaxLength: 6, ExpressionVisible: true,
	})
	records, _ := registry.NewRecordSchema(registry.RecordSchemaInput{
		ID: "chain", Version: "v1", Fields: []registry.RecordFieldSchema{sequence, result},
		MaxRecords: maxRecords, MaxFields: maxFields, MaxAggregateBytes: maxAggregate,
	})
	fact, _ := registry.NewFactSchema(registry.FactSchemaInput{
		ID: "resource.chain", Category: decision.FactCategoryResource, Kind: decision.ValueKindRecords,
		AllowedSources: []decision.FactSource{decision.FactSourceCaller}, RecordSchema: &records,
	})
	identity, _ := registry.NewSchemaIdentity("mail", "submit", "v1")

	return newCompiledSchema(identity, []registry.FactSchema{fact})
}

// recordFieldSchema constructs one test field schema.
func recordFieldSchema(t *testing.T, input registry.RecordFieldSchemaInput) registry.RecordFieldSchema {
	t.Helper()

	field, err := registry.NewRecordFieldSchema(input)
	if err != nil {
		t.Fatalf("NewRecordFieldSchema(%s) error = %v", input.Name, err)
	}

	return field
}

// recordValue constructs one records value from concise leaf fixtures.
func recordValue(t *testing.T, inputs ...[]recordTestField) decision.Value {
	t.Helper()

	records := make([]decision.Record, 0, len(inputs))
	for _, input := range inputs {
		fields := make([]decision.RecordField, 0, len(input))
		for _, configured := range input {
			valueInput := decision.ValueInput{}

			switch value := configured.value.(type) {
			case string:
				valueInput.String = &value
			case int64:
				valueInput.Integer = &value
			case bool:
				valueInput.Boolean = &value
			case []byte:
				valueInput.Bytes = value
			}

			leaf, err := decision.NewValue(valueInput)
			if err != nil {
				t.Fatalf("NewValue(%s) error = %v", configured.name, err)
			}

			fieldValue, _ := decision.NewRecordFieldValueFromValue(leaf)
			field, _ := decision.NewRecordField(configured.name, fieldValue)
			fields = append(fields, field)
		}

		record, err := decision.NewRecord(fields)
		if err != nil {
			t.Fatalf("NewRecord() error = %v", err)
		}

		records = append(records, record)
	}

	list, _ := decision.NewRecordList(records)
	value, _ := decision.NewValue(decision.ValueInput{Records: &list})

	return value
}
