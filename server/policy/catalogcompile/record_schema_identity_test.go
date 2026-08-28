// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package catalogcompile

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

func TestTargetCatalogRejectsIncompatibleSharedRecordSchemaIdentity(t *testing.T) {
	first := compilerRecordSchemaDefinition(t, "submit", decision.ValueKindInteger)
	second := compilerRecordSchemaDefinition(t, "archive", decision.ValueKindString)
	contribution := mustCompilerDefinitionContribution(
		t,
		"test.records",
		"mail",
		nil,
		[]registry.SchemaDefinition{first, second},
	)

	if _, err := NewTargetCatalogCompiler(testCatalogContributor{contribution: contribution}).Compile(context.Background(), nil); err == nil {
		t.Fatal("Compile() accepted incompatible definitions for one record schema ID/version")
	}
}

// compilerRecordSchemaDefinition constructs one target schema that shares the stable chain identity.
func compilerRecordSchemaDefinition(
	t *testing.T,
	action string,
	kind decision.ValueKind,
) registry.SchemaDefinition {
	t.Helper()

	fieldInput := registry.RecordFieldSchemaInput{Name: "sequence", Kind: kind, Required: true}
	if kind == decision.ValueKindString {
		fieldInput.MaxLength = 16
	}

	field, err := registry.NewRecordFieldSchema(fieldInput)
	if err != nil {
		t.Fatalf("NewRecordFieldSchema() error = %v", err)
	}

	records, err := registry.NewRecordSchema(registry.RecordSchemaInput{
		ID: "chain", Version: "v1", Fields: []registry.RecordFieldSchema{field},
		MaxRecords: 4, MaxFields: 1, MaxAggregateBytes: 64,
	})
	if err != nil {
		t.Fatalf("NewRecordSchema() error = %v", err)
	}

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID: "resource.chain", Category: decision.FactCategoryResource, Kind: decision.ValueKindRecords,
		AllowedSources: []decision.FactSource{decision.FactSourceCaller}, RecordSchema: &records,
	})
	if err != nil {
		t.Fatalf("NewFactSchema() error = %v", err)
	}

	identity, err := registry.NewSchemaIdentity("mail", action, "v1")
	if err != nil {
		t.Fatalf("NewSchemaIdentity() error = %v", err)
	}

	schema, err := registry.NewSchemaDefinition(identity, []registry.FactSchema{fact})
	if err != nil {
		t.Fatalf("NewSchemaDefinition() error = %v", err)
	}

	return schema
}
