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

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// NormalizeValue validates one fact value and returns a schema-ordered immutable snapshot.
func (s CompiledSchema) NormalizeValue(factID string, value decision.Value) (decision.Value, error) {
	normalized, _, err := s.normalizeValue(factID, value)

	return normalized, err
}

// normalizeValue validates one fact value and reports whether normalization had to rebuild it. Values are immutable,
// so an already normalized value is returned unchanged.
func (s CompiledSchema) normalizeValue(factID string, value decision.Value) (decision.Value, bool, error) {
	definition, exists := s.facts[factID]
	if !exists {
		return decision.Value{}, false, schemaFactError(
			s.identity, factID, "fact is not declared by the selected exact schema",
		)
	}

	if value.Kind() != definition.Kind() {
		return decision.Value{}, false, schemaFactError(
			s.identity, factID, "value kind does not match the selected exact schema",
		)
	}

	if definition.Kind() != decision.ValueKindRecords {
		if err := validateCompiledFactBounds(definition, value); err != nil {
			return decision.Value{}, false, schemaFactError(s.identity, factID, err.Error())
		}

		return value, false, nil
	}

	recordSchema, exists := definition.RecordSchema()
	if !exists {
		return decision.Value{}, false, schemaFactError(s.identity, factID, "records fact has no closed record schema")
	}

	normalized, changed, err := normalizeRecordValue(recordSchema, value)
	if err != nil {
		return decision.Value{}, false, schemaFactError(s.identity, factID, err.Error())
	}

	return normalized, changed, nil
}

// NormalizeFacts returns one schema-normalized fact snapshot without changing provenance. Facts are immutable, so the
// input set itself is returned when every fact is already normalized, and unchanged facts are reused.
func (s CompiledSchema) NormalizeFacts(facts decision.FactSet) (decision.FactSet, error) {
	var result []decision.Fact

	index := 0

	for fact := range facts.All() {
		definition, exists := s.facts[fact.ID()]
		if !exists {
			return decision.FactSet{}, schemaFactError(s.identity, fact.ID(), "fact is not declared by the selected exact schema")
		}

		if fact.Category() != definition.Category() || !definition.AllowsSource(fact.Provenance().Source()) {
			return decision.FactSet{}, schemaFactError(s.identity, fact.ID(), "category or source does not match the selected exact schema")
		}

		value, changed, err := s.normalizeValue(fact.ID(), fact.Value())
		if err != nil {
			return decision.FactSet{}, err
		}

		if changed {
			if result == nil {
				result = facts.Facts()[:index]
			}

			fact, err = decision.NewFact(fact.ID(), fact.Category(), value, fact.Provenance())
			if err != nil {
				return decision.FactSet{}, err
			}
		}

		if result != nil {
			result = append(result, fact)
		}

		index++
	}

	if result == nil {
		return facts, nil
	}

	return decision.NewFactSet(result)
}

// FactsForProvider returns the facts with record fields filtered by exact provider visibility. Facts are immutable,
// so the input set itself is returned when the provider sees every record field, and unchanged facts are reused.
func (s CompiledSchema) FactsForProvider(
	facts decision.FactSet,
	providerID string,
) (decision.FactSet, error) {
	var filtered []decision.Fact

	index := 0

	for fact := range facts.All() {
		definition, exists := s.facts[fact.ID()]
		if !exists {
			return decision.FactSet{}, schemaFactError(s.identity, fact.ID(), "fact is not declared by the selected exact schema")
		}

		keep, changed := true, false

		if definition.Kind() == decision.ValueKindRecords {
			var value decision.Value

			value, changed, keep = filterRecordValueForProvider(definition, fact.Value(), providerID)
			if keep && changed {
				owned, err := decision.NewFact(fact.ID(), fact.Category(), value, fact.Provenance())
				if err != nil {
					return decision.FactSet{}, err
				}

				fact = owned
			}
		}

		if (changed || !keep) && filtered == nil {
			filtered = facts.Facts()[:index]
		}

		if filtered != nil && keep {
			filtered = append(filtered, fact)
		}

		index++
	}

	if filtered == nil {
		return facts, nil
	}

	return decision.NewFactSet(filtered)
}

// normalizeRecordValue rejects unknown, missing, wrongly typed, oversized, or ambiguous fields. It reports whether a
// record had to be reordered; otherwise the immutable input value is returned unchanged.
func normalizeRecordValue(schema registry.RecordSchema, value decision.Value) (decision.Value, bool, error) {
	recordList, ok := value.Records()
	if !ok {
		return decision.Value{}, false, fmt.Errorf("value is not a constructed record list")
	}

	count := recordList.Len()
	if count < schema.MinRecords() || count > schema.MaxRecords() {
		return decision.Value{}, false, fmt.Errorf(
			"record count is outside %d..%d", schema.MinRecords(), schema.MaxRecords(),
		)
	}

	normalizer := recordNormalizer{schema: schema, fields: schema.Fields()}

	var normalized []decision.Record

	for recordIndex, record := range recordList.All() {
		owned, changed, err := normalizer.normalize(recordIndex, record)
		if err != nil {
			return decision.Value{}, false, err
		}

		if changed && normalized == nil {
			normalized = recordList.Records()[:recordIndex]
		}

		if normalized != nil {
			normalized = append(normalized, owned)
		}
	}

	if normalized == nil {
		return value, false, nil
	}

	owned, err := decision.NewRecordList(normalized)
	if err != nil {
		return decision.Value{}, false, err
	}

	result, err := decision.NewValue(decision.ValueInput{Records: &owned})

	return result, err == nil, err
}

// recordNormalizer owns per-collection aggregate state during canonical normalization.
type recordNormalizer struct {
	schema    registry.RecordSchema
	fields    []registry.RecordFieldSchema
	aggregate int
}

// normalize validates and canonicalizes one record within the collection budget. A record whose fields already
// follow the schema order is validated in place and reported as unchanged.
func (n *recordNormalizer) normalize(index int, record decision.Record) (decision.Record, bool, error) {
	if record.Len() == 0 || record.Len() > n.schema.MaxFields() {
		return decision.Record{}, false, fmt.Errorf("record %d field count is outside the admitted bound", index)
	}

	if n.inSchemaOrder(record) {
		for _, field := range record.All() {
			if _, err := n.normalizeField(index, field); err != nil {
				return decision.Record{}, false, err
			}
		}

		return record, false, nil
	}

	byName, err := n.normalizeFields(index, record.Fields())
	if err != nil {
		return decision.Record{}, false, err
	}

	ordered, err := n.orderFields(index, byName)
	if err != nil {
		return decision.Record{}, false, err
	}

	owned, err := decision.NewRecord(ordered)

	return owned, err == nil, err
}

// inSchemaOrder reports whether every field is declared, the fields follow the schema order, and no required field
// is missing. Such a record is exactly what orderFields would emit.
func (n *recordNormalizer) inSchemaOrder(record decision.Record) bool {
	next := 0

	for _, field := range record.All() {
		for next < len(n.fields) && n.fields[next].Name() != field.Name() {
			if n.fields[next].Required() {
				return false
			}

			next++
		}

		if next == len(n.fields) {
			return false
		}

		next++
	}

	for ; next < len(n.fields); next++ {
		if n.fields[next].Required() {
			return false
		}
	}

	return true
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

	for _, definition := range n.fields {
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

// filterRecordValueForProvider preserves record order while removing fields outside exact visibility. It reports
// whether a field was removed and whether the value stays visible; a fully visible value is returned unchanged.
func filterRecordValueForProvider(
	definition registry.FactSchema,
	value decision.Value,
	providerID string,
) (decision.Value, bool, bool) {
	schema, exists := definition.RecordSchema()
	if !exists {
		return decision.Value{}, false, false
	}

	recordList, exists := value.Records()
	if !exists {
		return decision.Value{}, false, false
	}

	var filteredRecords []decision.Record

	for index, record := range recordList.All() {
		owned, changed, visible := filterRecordForProvider(schema, record, providerID)
		if !visible {
			return decision.Value{}, false, false
		}

		if changed && filteredRecords == nil {
			filteredRecords = recordList.Records()[:index]
		}

		if filteredRecords != nil {
			filteredRecords = append(filteredRecords, owned)
		}
	}

	if filteredRecords == nil {
		return value, false, true
	}

	owned, err := decision.NewRecordList(filteredRecords)
	if err != nil {
		return decision.Value{}, false, false
	}

	filtered, err := decision.NewValue(decision.ValueInput{Records: &owned})

	return filtered, true, err == nil
}

// filterRecordForProvider removes the fields of one record outside exact visibility. It reports whether a field was
// removed and whether any field stays visible; a fully visible record is returned unchanged.
func filterRecordForProvider(
	schema registry.RecordSchema,
	record decision.Record,
	providerID string,
) (decision.Record, bool, bool) {
	var fields []decision.RecordField

	for index, field := range record.All() {
		fieldSchema, declared := schema.LookupField(field.Name())
		if declared && fieldSchema.VisibleToProvider(providerID) {
			if fields != nil {
				fields = append(fields, field)
			}

			continue
		}

		if fields == nil {
			fields = record.Fields()[:index]
		}
	}

	if fields == nil {
		return record, false, true
	}

	if len(fields) == 0 {
		return decision.Record{}, true, false
	}

	owned, err := decision.NewRecord(fields)

	return owned, true, err == nil
}
