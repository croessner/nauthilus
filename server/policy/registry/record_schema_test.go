// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package registry

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

func TestRecordSchemaOwnsClosedOrderedFieldsAndLimits(t *testing.T) {
	sequence := mustRecordFieldSchema(t, RecordFieldSchemaInput{
		Name: "sequence", Kind: decision.ValueKindInteger, Required: true, ExpressionVisible: true,
	})
	payload := mustRecordFieldSchema(t, RecordFieldSchemaInput{
		Name: "payload", Kind: decision.ValueKindBytes, MaxBytes: 128,
		ProviderVisibility: []string{"mail/plugin.reputation.assessor"},
	})

	records, err := NewRecordSchema(RecordSchemaInput{
		ID: "chain", Version: "v1", Fields: []RecordFieldSchema{sequence, payload},
		MinRecords: 0, MaxRecords: 8, MaxFields: 2, MaxAggregateBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewRecordSchema() error = %v", err)
	}

	fact, err := NewFactSchema(FactSchemaInput{
		ID: "resource.chain", AllowedSources: []decision.FactSource{decision.FactSourceCaller},
		Category: decision.FactCategoryResource, Kind: decision.ValueKindRecords, RecordSchema: &records,
	})
	if err != nil {
		t.Fatalf("NewFactSchema(records) error = %v", err)
	}

	owned, ok := fact.RecordSchema()
	if !ok || owned.ID() != "chain" || owned.Version() != "v1" {
		t.Fatalf("record schema = %#v, %t", owned, ok)
	}

	fields := owned.Fields()
	if len(fields) != 2 || fields[0].Name() != "sequence" || fields[1].Name() != "payload" {
		t.Fatalf("field order = %#v", fields)
	}

	if fields[1].ExpressionVisible() || !fields[1].VisibleToProvider("mail/plugin.reputation.assessor") ||
		fields[1].VisibleToProvider("mail/plugin.other.reader") {
		t.Fatal("provider-only visibility was not preserved")
	}
}

func TestRecordSchemaRejectsDuplicateAndRecursiveFields(t *testing.T) {
	field := mustRecordFieldSchema(t, RecordFieldSchemaInput{Name: "name", Kind: decision.ValueKindString, MaxLength: 64})

	if _, err := NewRecordSchema(RecordSchemaInput{
		ID: "chain", Version: "v1", Fields: []RecordFieldSchema{field, field},
		MaxRecords: 2, MaxFields: 1, MaxAggregateBytes: 128,
	}); err == nil {
		t.Fatal("NewRecordSchema() accepted a duplicate field")
	}

	if _, err := NewRecordFieldSchema(RecordFieldSchemaInput{Name: "nested", Kind: decision.ValueKindRecords}); err == nil {
		t.Fatal("NewRecordFieldSchema() accepted recursive records")
	}
}

func TestRecordSchemaEquivalentRequiresOneExactOrderedContract(t *testing.T) {
	first := mustRecordFieldSchema(t, RecordFieldSchemaInput{
		Name: "payload", Kind: decision.ValueKindBytes, MaxBytes: 128,
		ProviderVisibility: []string{"mail/plugin.second.reader", "mail/plugin.first.reader"},
	})
	same := mustRecordFieldSchema(t, RecordFieldSchemaInput{
		Name: "payload", Kind: decision.ValueKindBytes, MaxBytes: 128,
		ProviderVisibility: []string{"mail/plugin.first.reader", "mail/plugin.second.reader"},
	})
	different := mustRecordFieldSchema(t, RecordFieldSchemaInput{
		Name: "payload", Kind: decision.ValueKindString, MaxLength: 128,
		ProviderVisibility: []string{"mail/plugin.first.reader", "mail/plugin.second.reader"},
	})

	left, _ := NewRecordSchema(RecordSchemaInput{
		ID: "chain", Version: "v1", Fields: []RecordFieldSchema{first},
		MaxRecords: 2, MaxFields: 1, MaxAggregateBytes: 128,
	})
	equal, _ := NewRecordSchema(RecordSchemaInput{
		ID: "chain", Version: "v1", Fields: []RecordFieldSchema{same},
		MaxRecords: 2, MaxFields: 1, MaxAggregateBytes: 128,
	})
	unequal, _ := NewRecordSchema(RecordSchemaInput{
		ID: "chain", Version: "v1", Fields: []RecordFieldSchema{different},
		MaxRecords: 2, MaxFields: 1, MaxAggregateBytes: 128,
	})

	if !left.Equivalent(equal) {
		t.Fatal("Equivalent() rejected the same canonical provider visibility contract")
	}

	if left.Equivalent(unequal) {
		t.Fatal("Equivalent() accepted an incompatible field kind")
	}
}

// mustRecordFieldSchema constructs one test field schema through the public invariant.
func mustRecordFieldSchema(t *testing.T, input RecordFieldSchemaInput) RecordFieldSchema {
	t.Helper()

	field, err := NewRecordFieldSchema(input)
	if err != nil {
		t.Fatalf("NewRecordFieldSchema(%q) error = %v", input.Name, err)
	}

	return field
}
