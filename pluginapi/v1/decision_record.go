// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginapi

// DecisionRecordFieldValue owns one non-recursive public record-field value.
type DecisionRecordFieldValue struct {
	value DecisionValue
}

// NewDecisionRecordFieldValue narrows a public strict value to the leaf vocabulary.
func NewDecisionRecordFieldValue(value DecisionValue) (DecisionRecordFieldValue, error) {
	if !value.valid() || value.Kind() == DecisionValueKindRecords {
		return DecisionRecordFieldValue{}, invalidDecisionContract("record.field.value", "must use a non-recursive value kind")
	}

	return DecisionRecordFieldValue{value: cloneDecisionValue(value)}, nil
}

// Kind returns the exact active leaf kind.
func (v DecisionRecordFieldValue) Kind() DecisionValueKind {
	return v.value.Kind()
}

// Value returns a detached strict leaf value.
func (v DecisionRecordFieldValue) Value() DecisionValue {
	return cloneDecisionValue(v.value)
}

// Any returns one detached leaf member.
func (v DecisionRecordFieldValue) Any() (any, bool) {
	return v.value.Any()
}

// valid reports whether this is one constructed non-recursive leaf value.
func (v DecisionRecordFieldValue) valid() bool {
	return v.value.valid() && v.value.Kind() != DecisionValueKindRecords
}

// clone returns a deeply detached field value.
func (v DecisionRecordFieldValue) clone() DecisionRecordFieldValue {
	return DecisionRecordFieldValue{value: cloneDecisionValue(v.value)}
}

// DecisionRecordField binds one canonical local field name to one leaf value.
type DecisionRecordField struct {
	name  string
	value DecisionRecordFieldValue
}

// NewDecisionRecordField constructs one public record field.
func NewDecisionRecordField(name string, value DecisionRecordFieldValue) (DecisionRecordField, error) {
	if !validDecisionRecordFieldName(name) || !value.valid() {
		return DecisionRecordField{}, invalidDecisionContract("record.field", "must contain a canonical name and constructed leaf value")
	}

	return DecisionRecordField{name: name, value: value.clone()}, nil
}

// Name returns the exact local field name.
func (f DecisionRecordField) Name() string {
	return f.name
}

// Value returns a detached field value.
func (f DecisionRecordField) Value() DecisionRecordFieldValue {
	return f.value.clone()
}

// valid reports whether the field satisfies its constructor invariant.
func (f DecisionRecordField) valid() bool {
	return validDecisionRecordFieldName(f.name) && f.value.valid()
}

// clone returns a detached field.
func (f DecisionRecordField) clone() DecisionRecordField {
	return DecisionRecordField{name: f.name, value: f.value.clone()}
}

// DecisionRecord is one non-empty ordered public field collection.
type DecisionRecord struct {
	fields []DecisionRecordField
}

// NewDecisionRecord constructs one record and rejects duplicate names.
func NewDecisionRecord(fields []DecisionRecordField) (DecisionRecord, error) {
	if len(fields) == 0 {
		return DecisionRecord{}, invalidDecisionContract("record.fields", "must contain at least one field")
	}

	owned := make([]DecisionRecordField, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))

	for _, field := range fields {
		if !field.valid() {
			return DecisionRecord{}, invalidDecisionContract("record.fields", "must contain constructed fields")
		}

		if _, exists := seen[field.Name()]; exists {
			return DecisionRecord{}, invalidDecisionContract("record.fields."+field.Name(), "field name occurs more than once")
		}

		seen[field.Name()] = struct{}{}
		owned = append(owned, field.clone())
	}

	return DecisionRecord{fields: owned}, nil
}

// Fields returns detached fields in logical order.
func (r DecisionRecord) Fields() []DecisionRecordField {
	result := make([]DecisionRecordField, 0, len(r.fields))
	for _, field := range r.fields {
		result = append(result, field.clone())
	}

	return result
}

// valid reports whether this is one constructed non-empty record.
func (r DecisionRecord) valid() bool {
	if len(r.fields) == 0 {
		return false
	}

	seen := make(map[string]struct{}, len(r.fields))
	for _, field := range r.fields {
		if !field.valid() {
			return false
		}

		if _, exists := seen[field.Name()]; exists {
			return false
		}

		seen[field.Name()] = struct{}{}
	}

	return true
}

// clone returns a deeply detached record.
func (r DecisionRecord) clone() DecisionRecord {
	return DecisionRecord{fields: r.Fields()}
}

// DecisionRecordList is one ordered, possibly empty public record collection.
type DecisionRecordList struct {
	records []DecisionRecord
}

// NewDecisionRecordList constructs and deeply owns a public record collection.
func NewDecisionRecordList(records []DecisionRecord) (DecisionRecordList, error) {
	owned := make([]DecisionRecord, 0, len(records))
	for _, record := range records {
		if !record.valid() {
			return DecisionRecordList{}, invalidDecisionContract("records", "must contain constructed records")
		}

		owned = append(owned, record.clone())
	}

	return DecisionRecordList{records: owned}, nil
}

// Records returns detached records in logical order.
func (l DecisionRecordList) Records() []DecisionRecord {
	result := make([]DecisionRecord, 0, len(l.records))
	for _, record := range l.records {
		result = append(result, record.clone())
	}

	return result
}

// valid reports whether the collection was constructed and contains only valid records.
func (l DecisionRecordList) valid() bool {
	if l.records == nil {
		return false
	}

	for _, record := range l.records {
		if !record.valid() {
			return false
		}
	}

	return true
}

// clone returns a deeply detached record collection.
func (l DecisionRecordList) clone() DecisionRecordList {
	records, _ := NewDecisionRecordList(l.records)

	return records
}

// validDecisionRecordFieldName enforces one bounded lowercase local-name grammar.
func validDecisionRecordFieldName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}

	separator := false

	for index := range len(value) {
		current := value[index]

		if decisionRecordFieldWordCharacter(current) {
			separator = false

			continue
		}

		if !decisionRecordFieldSeparator(current, index, len(value), separator) {
			return false
		}

		separator = true
	}

	return true
}

// decisionRecordFieldWordCharacter reports whether one byte belongs to the local-name word set.
func decisionRecordFieldWordCharacter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// decisionRecordFieldSeparator validates one non-repeated interior name separator.
func decisionRecordFieldSeparator(value byte, index int, length int, repeated bool) bool {
	return (value == '-' || value == '_') && index > 0 && index < length-1 && !repeated
}
