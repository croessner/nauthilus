// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package decision

import (
	"time"

	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"
)

// RecordFieldValueInput carries one non-recursive record-field value.
type RecordFieldValueInput struct {
	String    *string
	Boolean   *bool
	Integer   *int64
	Double    *float64
	Timestamp *time.Time
	Strings   []string
	Bytes     []byte
}

// RecordFieldValue owns one closed scalar, string-list, bytes, or timestamp value.
type RecordFieldValue struct {
	value Value
}

// NewRecordFieldValue constructs one non-recursive field value.
func NewRecordFieldValue(input RecordFieldValueInput) (RecordFieldValue, error) {
	value, err := NewValue(ValueInput{
		String: input.String, Boolean: input.Boolean, Integer: input.Integer, Double: input.Double,
		Timestamp: input.Timestamp, Strings: input.Strings, Bytes: input.Bytes,
	})
	if err != nil {
		return RecordFieldValue{}, err
	}

	return RecordFieldValue{value: value}, nil
}

// NewRecordFieldValueFromValue narrows an existing strict value to the record-field vocabulary.
func NewRecordFieldValueFromValue(value Value) (RecordFieldValue, error) {
	if !value.valid() || value.Kind() == ValueKindRecords {
		return RecordFieldValue{}, invalidValue("record.field.value", "must use a non-recursive record-field kind")
	}

	return RecordFieldValue{value: cloneValue(value)}, nil
}

// Kind returns the active field-value kind.
func (v RecordFieldValue) Kind() ValueKind {
	return v.value.Kind()
}

// Value returns a detached strict scalar value.
func (v RecordFieldValue) Value() Value {
	return cloneValue(v.value)
}

// StringValue returns the active string member.
func (v RecordFieldValue) StringValue() (string, bool) {
	return v.value.StringValue()
}

// Boolean returns the active boolean member.
func (v RecordFieldValue) Boolean() (bool, bool) {
	return v.value.Boolean()
}

// Integer returns the active integer member.
func (v RecordFieldValue) Integer() (int64, bool) {
	return v.value.Integer()
}

// Double returns the active double member.
func (v RecordFieldValue) Double() (float64, bool) {
	return v.value.Double()
}

// Strings returns a detached ordered string list.
func (v RecordFieldValue) Strings() ([]string, bool) {
	return v.value.Strings()
}

// Bytes returns detached bytes.
func (v RecordFieldValue) Bytes() ([]byte, bool) {
	return v.value.Bytes()
}

// Timestamp returns the active normalized timestamp member.
func (v RecordFieldValue) Timestamp() (time.Time, bool) {
	return v.value.Timestamp()
}

// Any returns a detached scalar member.
func (v RecordFieldValue) Any() (any, bool) {
	return v.value.Any()
}

// valid reports whether the field value is constructed and non-recursive.
func (v RecordFieldValue) valid() bool {
	return v.value.valid() && v.value.Kind() != ValueKindRecords
}

// clone returns a detached field value.
func (v RecordFieldValue) clone() RecordFieldValue {
	return RecordFieldValue{value: cloneValue(v.value)}
}

// RecordField is one named field in a schema-bound record.
type RecordField struct {
	name  string
	value RecordFieldValue
}

// NewRecordField constructs one canonical local field.
func NewRecordField(name string, value RecordFieldValue) (RecordField, error) {
	if !identifier.Action(name) {
		return RecordField{}, invalidValue("record.field.name", "must be a canonical local field name")
	}

	if !value.valid() {
		return RecordField{}, invalidValue("record.field.value", "must be a constructed record-field value")
	}

	return RecordField{name: name, value: value.clone()}, nil
}

// Name returns the exact field name.
func (f RecordField) Name() string {
	return f.name
}

// Value returns a detached field value.
func (f RecordField) Value() RecordFieldValue {
	return f.value.clone()
}

// valid reports whether the field satisfies its constructor invariant.
func (f RecordField) valid() bool {
	return identifier.Action(f.name) && f.value.valid()
}

// clone returns a detached field.
func (f RecordField) clone() RecordField {
	return RecordField{name: f.name, value: f.value.clone()}
}

// Record is one non-empty ordered collection of uniquely named fields.
type Record struct {
	fields []RecordField
}

// NewRecord constructs and deeply owns one record without changing field order.
func NewRecord(fields []RecordField) (Record, error) {
	if len(fields) == 0 {
		return Record{}, invalidValue("record.fields", "must contain at least one field")
	}

	owned := make([]RecordField, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))

	for _, field := range fields {
		if !field.valid() {
			return Record{}, invalidValue("record.fields", "must contain constructed record fields")
		}

		if _, exists := seen[field.Name()]; exists {
			return Record{}, invalidValue("record.fields."+field.Name(), "field name occurs more than once")
		}

		seen[field.Name()] = struct{}{}
		owned = append(owned, field.clone())
	}

	return Record{fields: owned}, nil
}

// Fields returns detached fields in logical order.
func (r Record) Fields() []RecordField {
	return cloneRecordFields(r.fields)
}

// valid reports whether the record satisfies its constructor invariant.
func (r Record) valid() bool {
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
func (r Record) clone() Record {
	return Record{fields: cloneRecordFields(r.fields)}
}

// RecordList is one ordered, possibly empty correlated resource collection.
type RecordList struct {
	records []Record
}

// NewRecordList constructs and deeply owns one ordered record list.
func NewRecordList(records []Record) (RecordList, error) {
	owned := make([]Record, 0, len(records))
	for _, record := range records {
		if !record.valid() {
			return RecordList{}, invalidValue("records", "must contain constructed non-empty records")
		}

		owned = append(owned, record.clone())
	}

	return RecordList{records: owned}, nil
}

// Records returns detached records in logical order.
func (l RecordList) Records() []Record {
	result := make([]Record, 0, len(l.records))
	for _, record := range l.records {
		result = append(result, record.clone())
	}

	return result
}

// valid reports whether every record satisfies its constructor invariant.
func (l RecordList) valid() bool {
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

// clone returns a deeply detached record list.
func (l RecordList) clone() RecordList {
	records, _ := NewRecordList(l.records)

	return records
}

// cloneRecordFields deeply copies ordered record fields.
func cloneRecordFields(fields []RecordField) []RecordField {
	result := make([]RecordField, 0, len(fields))
	for _, field := range fields {
		result = append(result, field.clone())
	}

	return result
}
