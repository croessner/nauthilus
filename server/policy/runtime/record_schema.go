// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package runtime

import (
	"fmt"
	"math"
	"slices"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// NormalizeValue validates one fact value and returns a schema-ordered detached snapshot.
func (s CompiledSchema) NormalizeValue(factID string, value decision.Value) (decision.Value, error) {
	definition, exists := s.facts[factID]
	if !exists {
		return decision.Value{}, schemaFactError(s.identity, factID, "fact is not declared by the selected exact schema")
	}

	if value.Kind() != definition.Kind() {
		return decision.Value{}, schemaFactError(s.identity, factID, "value kind does not match the selected exact schema")
	}

	if definition.Kind() != decision.ValueKindRecords {
		if err := validateCompiledFactBounds(definition, value); err != nil {
			return decision.Value{}, schemaFactError(s.identity, factID, err.Error())
		}

		return value, nil
	}

	recordSchema, exists := definition.RecordSchema()
	if !exists {
		return decision.Value{}, schemaFactError(s.identity, factID, "records fact has no closed record schema")
	}

	normalized, err := normalizeRecordValue(recordSchema, value)
	if err != nil {
		return decision.Value{}, schemaFactError(s.identity, factID, err.Error())
	}

	return normalized, nil
}

// NormalizeFacts returns one detached schema-normalized fact snapshot without changing provenance.
func (s CompiledSchema) NormalizeFacts(facts decision.FactSet) (decision.FactSet, error) {
	result := make([]decision.Fact, 0, facts.Len())
	for _, fact := range facts.Facts() {
		definition, exists := s.facts[fact.ID()]
		if !exists {
			return decision.FactSet{}, schemaFactError(s.identity, fact.ID(), "fact is not declared by the selected exact schema")
		}

		if fact.Category() != definition.Category() || !slices.Contains(definition.AllowedSources(), fact.Provenance().Source()) {
			return decision.FactSet{}, schemaFactError(s.identity, fact.ID(), "category or source does not match the selected exact schema")
		}

		value, err := s.NormalizeValue(fact.ID(), fact.Value())
		if err != nil {
			return decision.FactSet{}, err
		}

		owned, err := decision.NewFact(fact.ID(), fact.Category(), value, fact.Provenance())
		if err != nil {
			return decision.FactSet{}, err
		}

		result = append(result, owned)
	}

	return decision.NewFactSet(result)
}

// FactsForProvider returns a fresh snapshot with record fields filtered by exact provider visibility.
func (s CompiledSchema) FactsForProvider(
	facts decision.FactSet,
	providerID string,
) (decision.FactSet, error) {
	filtered := make([]decision.Fact, 0, facts.Len())

	for _, fact := range facts.Facts() {
		definition, exists := s.facts[fact.ID()]
		if !exists {
			return decision.FactSet{}, schemaFactError(s.identity, fact.ID(), "fact is not declared by the selected exact schema")
		}

		value := fact.Value()

		if definition.Kind() == decision.ValueKindRecords {
			var visible bool

			value, visible = filterRecordValueForProvider(definition, value, providerID)
			if !visible {
				continue
			}
		}

		owned, err := decision.NewFact(fact.ID(), fact.Category(), value, fact.Provenance())
		if err != nil {
			return decision.FactSet{}, err
		}

		filtered = append(filtered, owned)
	}

	return decision.NewFactSet(filtered)
}

// normalizeRecordValue rejects unknown, missing, wrongly typed, oversized, or ambiguous fields.
func normalizeRecordValue(schema registry.RecordSchema, value decision.Value) (decision.Value, error) {
	recordList, ok := value.Records()
	if !ok {
		return decision.Value{}, fmt.Errorf("value is not a constructed record list")
	}

	records := recordList.Records()
	if len(records) < schema.MinRecords() || len(records) > schema.MaxRecords() {
		return decision.Value{}, fmt.Errorf("record count is outside %d..%d", schema.MinRecords(), schema.MaxRecords())
	}

	normalizer := recordNormalizer{schema: schema}
	normalized := make([]decision.Record, 0, len(records))

	for recordIndex, record := range records {
		owned, err := normalizer.normalize(recordIndex, record)
		if err != nil {
			return decision.Value{}, err
		}

		normalized = append(normalized, owned)
	}

	owned, err := decision.NewRecordList(normalized)
	if err != nil {
		return decision.Value{}, err
	}

	return decision.NewValue(decision.ValueInput{Records: &owned})
}

// recordNormalizer owns per-collection aggregate state during canonical normalization.
type recordNormalizer struct {
	schema    registry.RecordSchema
	aggregate int
}

// normalize validates and canonicalizes one record within the collection budget.
func (n *recordNormalizer) normalize(index int, record decision.Record) (decision.Record, error) {
	fields := record.Fields()

	if len(fields) == 0 || len(fields) > n.schema.MaxFields() {
		return decision.Record{}, fmt.Errorf("record %d field count is outside the admitted bound", index)
	}

	byName, err := n.normalizeFields(index, fields)
	if err != nil {
		return decision.Record{}, err
	}

	ordered, err := n.orderFields(index, byName)
	if err != nil {
		return decision.Record{}, err
	}

	return decision.NewRecord(ordered)
}

// normalizeFields validates leaf declarations and accounts their decoded bytes.
func (n *recordNormalizer) normalizeFields(
	index int,
	fields []decision.RecordField,
) (map[string]decision.RecordFieldValue, error) {
	byName := make(map[string]decision.RecordFieldValue, len(fields))

	for _, field := range fields {
		value, err := n.normalizeField(index, field)
		if err != nil {
			return nil, err
		}

		byName[field.Name()] = value
	}

	return byName, nil
}

// normalizeField validates one exact leaf and advances the aggregate byte budget.
func (n *recordNormalizer) normalizeField(
	index int,
	field decision.RecordField,
) (decision.RecordFieldValue, error) {
	definition, exists := n.schema.LookupField(field.Name())
	if !exists {
		return decision.RecordFieldValue{}, fmt.Errorf("record %d contains unknown field %s", index, field.Name())
	}

	value := field.Value()
	if value.Kind() != definition.Kind() {
		return decision.RecordFieldValue{}, fmt.Errorf("record %d field %s has the wrong kind", index, field.Name())
	}

	if err := validateRecordFieldValue(definition, value); err != nil {
		return decision.RecordFieldValue{}, fmt.Errorf("record %d field %s: %w", index, field.Name(), err)
	}

	size := recordFieldDecodedBytes(value)
	if size > n.schema.MaxAggregateBytes()-n.aggregate {
		return decision.RecordFieldValue{}, fmt.Errorf(
			"record collection exceeds aggregate decoded-byte limit %d", n.schema.MaxAggregateBytes(),
		)
	}

	n.aggregate += size

	return value, nil
}

// orderFields emits present leaves in exact schema order and enforces required fields.
func (n *recordNormalizer) orderFields(
	index int,
	byName map[string]decision.RecordFieldValue,
) ([]decision.RecordField, error) {
	ordered := make([]decision.RecordField, 0, len(byName))

	for _, definition := range n.schema.Fields() {
		value, exists := byName[definition.Name()]
		if !exists {
			if definition.Required() {
				return nil, fmt.Errorf("record %d is missing required field %s", index, definition.Name())
			}

			continue
		}

		field, err := decision.NewRecordField(definition.Name(), value)
		if err != nil {
			return nil, err
		}

		ordered = append(ordered, field)
	}

	return ordered, nil
}

// validateRecordFieldValue applies the exact existing leaf-value bounds.
func validateRecordFieldValue(definition registry.RecordFieldSchema, value decision.RecordFieldValue) error {
	switch definition.Kind() {
	case decision.ValueKindString:
		text, _ := value.StringValue()
		if len(text) > definition.MaxLength() {
			return fmt.Errorf("string exceeds maximum length %d", definition.MaxLength())
		}
	case decision.ValueKindStrings:
		members, _ := value.Strings()
		if len(members) > definition.MaxItems() {
			return fmt.Errorf("string list exceeds maximum items %d", definition.MaxItems())
		}

		for _, member := range members {
			if len(member) > definition.MaxLength() {
				return fmt.Errorf("string list member exceeds maximum length %d", definition.MaxLength())
			}
		}
	case decision.ValueKindBytes:
		data, _ := value.Bytes()
		if len(data) > definition.MaxBytes() {
			return fmt.Errorf("bytes exceed maximum size %d", definition.MaxBytes())
		}
	}

	return nil
}

// recordFieldDecodedBytes measures detached decoded leaf payload without wire ambiguity.
func recordFieldDecodedBytes(value decision.RecordFieldValue) int {
	switch value.Kind() {
	case decision.ValueKindString:
		text, _ := value.StringValue()

		return len(text)
	case decision.ValueKindStrings:
		members, _ := value.Strings()
		total := 0

		for _, member := range members {
			if len(member) > math.MaxInt-total {
				return math.MaxInt
			}

			total += len(member)
		}

		return total
	case decision.ValueKindBytes:
		data, _ := value.Bytes()

		return len(data)
	case decision.ValueKindBoolean:
		return 1
	default:
		return 8
	}
}

// filterRecordValueForProvider preserves record order while removing fields outside exact visibility.
func filterRecordValueForProvider(
	definition registry.FactSchema,
	value decision.Value,
	providerID string,
) (decision.Value, bool) {
	schema, exists := definition.RecordSchema()
	if !exists {
		return decision.Value{}, false
	}

	recordList, exists := value.Records()
	if !exists {
		return decision.Value{}, false
	}

	filteredRecords := make([]decision.Record, 0, len(recordList.Records()))
	for _, record := range recordList.Records() {
		fields := make([]decision.RecordField, 0, len(record.Fields()))
		for _, field := range record.Fields() {
			fieldSchema, declared := schema.LookupField(field.Name())
			if declared && fieldSchema.VisibleToProvider(providerID) {
				fields = append(fields, field)
			}
		}

		if len(fields) == 0 {
			return decision.Value{}, false
		}

		owned, err := decision.NewRecord(fields)
		if err != nil {
			return decision.Value{}, false
		}

		filteredRecords = append(filteredRecords, owned)
	}

	owned, err := decision.NewRecordList(filteredRecords)
	if err != nil {
		return decision.Value{}, false
	}

	filtered, err := decision.NewValue(decision.ValueInput{Records: &owned})

	return filtered, err == nil
}
