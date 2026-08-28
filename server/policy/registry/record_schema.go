// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package registry

import (
	"slices"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"
)

// RecordFieldSchemaInput carries one closed record-field declaration.
type RecordFieldSchemaInput struct {
	Name               string
	ProviderVisibility []string
	Kind               decision.ValueKind
	MaxLength          int
	MaxItems           int
	MaxBytes           int
	Required           bool
	ExpressionVisible  bool
}

// RecordFieldSchema is one immutable non-recursive record-field declaration.
type RecordFieldSchema struct {
	name               string
	providerVisibility []string
	kind               decision.ValueKind
	maxLength          int
	maxItems           int
	maxBytes           int
	required           bool
	expressionVisible  bool
}

// NewRecordFieldSchema validates and owns one exact record field.
func NewRecordFieldSchema(input RecordFieldSchemaInput) (RecordFieldSchema, error) {
	if !identifier.Action(input.Name) {
		return RecordFieldSchema{}, newValidationError(
			ErrInvalidFactSchema, "record_schema.fields", input.Name, "must be a canonical local field name",
		)
	}

	if !input.Kind.IsValid() || input.Kind == decision.ValueKindRecords {
		return RecordFieldSchema{}, newValidationError(
			ErrInvalidFactSchema, "record_schema.fields."+input.Name, string(input.Kind),
			"must use a non-recursive record-field kind",
		)
	}

	if err := validateRecordFieldBounds(input); err != nil {
		return RecordFieldSchema{}, err
	}

	visibility := append([]string(nil), input.ProviderVisibility...)
	seen := make(map[string]struct{}, len(visibility))

	for _, providerID := range visibility {
		if !identifier.ProviderIdentity(providerID) {
			return RecordFieldSchema{}, newValidationError(
				ErrInvalidFactSchema, "record_schema.fields."+input.Name+".provider_visibility", providerID,
				"must contain canonical qualified provider identities",
			)
		}

		if _, exists := seen[providerID]; exists {
			return RecordFieldSchema{}, newValidationError(
				ErrDuplicateDefinition, "record_schema.fields."+input.Name+".provider_visibility", providerID,
				"provider identity occurs more than once",
			)
		}

		seen[providerID] = struct{}{}
	}

	slices.Sort(visibility)

	return RecordFieldSchema{
		name: input.Name, providerVisibility: visibility, kind: input.Kind,
		maxLength: input.MaxLength, maxItems: input.MaxItems, maxBytes: input.MaxBytes,
		required: input.Required, expressionVisible: input.ExpressionVisible,
	}, nil
}

// Name returns the exact record-local field name.
func (f RecordFieldSchema) Name() string {
	return f.name
}

// Kind returns the exact non-recursive value kind.
func (f RecordFieldSchema) Kind() decision.ValueKind {
	return f.kind
}

// MaxLength returns the text or text-member bound.
func (f RecordFieldSchema) MaxLength() int {
	return f.maxLength
}

// MaxItems returns the string-list item bound.
func (f RecordFieldSchema) MaxItems() int {
	return f.maxItems
}

// MaxBytes returns the bytes bound.
func (f RecordFieldSchema) MaxBytes() int {
	return f.maxBytes
}

// Required reports whether every record must carry this field.
func (f RecordFieldSchema) Required() bool {
	return f.required
}

// ExpressionVisible reports whether record-local predicates may access this field.
func (f RecordFieldSchema) ExpressionVisible() bool {
	return f.expressionVisible
}

// ProviderVisibility returns the exact provider allowlist.
func (f RecordFieldSchema) ProviderVisibility() []string {
	return append([]string(nil), f.providerVisibility...)
}

// VisibleToProvider applies the closed provider visibility rule.
func (f RecordFieldSchema) VisibleToProvider(providerID string) bool {
	return len(f.providerVisibility) == 0 || slices.Contains(f.providerVisibility, providerID)
}

// clone returns a detached field schema.
func (f RecordFieldSchema) clone() RecordFieldSchema {
	f.providerVisibility = append([]string(nil), f.providerVisibility...)

	return f
}

// valid reports whether the field schema satisfies its constructor invariant.
func (f RecordFieldSchema) valid() bool {
	_, err := NewRecordFieldSchema(RecordFieldSchemaInput{
		Name: f.name, ProviderVisibility: f.providerVisibility, Kind: f.kind,
		MaxLength: f.maxLength, MaxItems: f.maxItems, MaxBytes: f.maxBytes,
		Required: f.required, ExpressionVisible: f.expressionVisible,
	})

	return err == nil
}

// RecordSchemaInput carries one exact schema-owned record collection declaration.
type RecordSchemaInput struct {
	ID                string
	Version           string
	Fields            []RecordFieldSchema
	MinRecords        int
	MaxRecords        int
	MaxFields         int
	MaxAggregateBytes int
}

// RecordSchema is one immutable closed and ordered record declaration.
type RecordSchema struct {
	id                string
	version           SchemaVersion
	fields            []RecordFieldSchema
	minRecords        int
	maxRecords        int
	maxFields         int
	maxAggregateBytes int
}

// NewRecordSchema validates and deeply owns one exact record schema.
func NewRecordSchema(input RecordSchemaInput) (RecordSchema, error) {
	if !identifier.Action(input.ID) {
		return RecordSchema{}, newValidationError(
			ErrInvalidFactSchema, "record_schema.id", input.ID, "must be a canonical schema-local identity",
		)
	}

	version, err := NewSchemaVersion(input.Version)
	if err != nil {
		return RecordSchema{}, newValidationError(
			ErrInvalidFactSchema, "record_schema.version", input.Version, "must be an exact positive vN version",
		)
	}

	if !validRecordSchemaLimits(input) {
		return RecordSchema{}, newValidationError(
			ErrInvalidFactSchema, "record_schema", input.ID,
			"must declare non-empty fields and positive bounded record, field, and aggregate limits",
		)
	}

	fields, required, err := ownRecordSchemaFields(input.Fields)
	if err != nil {
		return RecordSchema{}, err
	}

	if required > input.MaxFields {
		return RecordSchema{}, newValidationError(
			ErrInvalidFactSchema, "record_schema.max_fields", input.ID, "must admit every required field",
		)
	}

	return RecordSchema{
		id: input.ID, version: version, fields: fields,
		minRecords: input.MinRecords, maxRecords: input.MaxRecords, maxFields: input.MaxFields,
		maxAggregateBytes: input.MaxAggregateBytes,
	}, nil
}

// validRecordSchemaLimits checks collection-wide bounds against the declared field set.
func validRecordSchemaLimits(input RecordSchemaInput) bool {
	return len(input.Fields) > 0 && input.MinRecords >= 0 && input.MaxRecords > 0 &&
		input.MinRecords <= input.MaxRecords && input.MaxFields > 0 &&
		input.MaxFields <= len(input.Fields) && input.MaxAggregateBytes > 0
}

// ownRecordSchemaFields validates uniqueness and returns detached fields plus the required count.
func ownRecordSchemaFields(input []RecordFieldSchema) ([]RecordFieldSchema, int, error) {
	fields := make([]RecordFieldSchema, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	required := 0

	for _, field := range input {
		if !field.valid() {
			return nil, 0, newValidationError(
				ErrInvalidFactSchema, "record_schema.fields", field.Name(), "must be constructor validated",
			)
		}

		if _, exists := seen[field.Name()]; exists {
			return nil, 0, newValidationError(
				ErrDuplicateDefinition, "record_schema.fields", field.Name(), "field occurs more than once",
			)
		}

		if field.Required() {
			required++
		}

		seen[field.Name()] = struct{}{}
		fields = append(fields, field.clone())
	}

	return fields, required, nil
}

// ID returns the stable record-schema identity.
func (s RecordSchema) ID() string {
	return s.id
}

// Version returns the exact record-schema version.
func (s RecordSchema) Version() string {
	return s.version.String()
}

// Fields returns detached fields in canonical schema order.
func (s RecordSchema) Fields() []RecordFieldSchema {
	result := make([]RecordFieldSchema, 0, len(s.fields))
	for _, field := range s.fields {
		result = append(result, field.clone())
	}

	return result
}

// LookupField resolves one exact local field.
func (s RecordSchema) LookupField(name string) (RecordFieldSchema, bool) {
	for _, field := range s.fields {
		if field.Name() == name {
			return field.clone(), true
		}
	}

	return RecordFieldSchema{}, false
}

// MinRecords returns the admitted collection minimum.
func (s RecordSchema) MinRecords() int {
	return s.minRecords
}

// MaxRecords returns the admitted collection maximum.
func (s RecordSchema) MaxRecords() int {
	return s.maxRecords
}

// MaxFields returns the admitted per-record field maximum.
func (s RecordSchema) MaxFields() int {
	return s.maxFields
}

// MaxAggregateBytes returns the aggregate decoded-value bound.
func (s RecordSchema) MaxAggregateBytes() int {
	return s.maxAggregateBytes
}

// Equivalent reports whether two uses of one schema identity have the same ordered closed contract.
func (s RecordSchema) Equivalent(other RecordSchema) bool {
	if s.id != other.id || s.version != other.version || s.minRecords != other.minRecords ||
		s.maxRecords != other.maxRecords || s.maxFields != other.maxFields ||
		s.maxAggregateBytes != other.maxAggregateBytes || len(s.fields) != len(other.fields) {
		return false
	}

	for index := range s.fields {
		if !s.fields[index].equivalent(other.fields[index]) {
			return false
		}
	}

	return true
}

// equivalent compares one ordered field contract including visibility and all value bounds.
func (f RecordFieldSchema) equivalent(other RecordFieldSchema) bool {
	return f.name == other.name && f.kind == other.kind && f.maxLength == other.maxLength &&
		f.maxItems == other.maxItems && f.maxBytes == other.maxBytes && f.required == other.required &&
		f.expressionVisible == other.expressionVisible && slices.Equal(f.providerVisibility, other.providerVisibility)
}

// ValidateRecordSchemaIdentities rejects incompatible shapes for one stable schema ID and version.
func ValidateRecordSchemaIdentities(definitions []SchemaDefinition) error {
	type ownedSchema struct {
		definition string
		schema     RecordSchema
	}

	seen := make(map[string]ownedSchema)

	for _, definition := range definitions {
		for _, fact := range definition.Facts() {
			recordSchema, exists := fact.RecordSchema()
			if !exists {
				continue
			}

			identity := recordSchema.ID() + "@" + recordSchema.Version()

			previous, exists := seen[identity]
			if exists && !previous.schema.Equivalent(recordSchema) {
				return newValidationError(
					ErrInvalidFactSchema, "record_schema.identity", identity,
					"must have one compatible definition across "+previous.definition+" and "+definition.Identity().String(),
				)
			}

			seen[identity] = ownedSchema{definition: definition.Identity().String(), schema: recordSchema}
		}
	}

	return nil
}

// clone returns a deeply detached record schema.
func (s RecordSchema) clone() RecordSchema {
	s.fields = s.Fields()

	return s
}

// valid reports whether the record schema satisfies its constructor invariant.
func (s RecordSchema) valid() bool {
	_, err := NewRecordSchema(RecordSchemaInput{
		ID: s.id, Version: s.Version(), Fields: s.fields, MinRecords: s.minRecords,
		MaxRecords: s.maxRecords, MaxFields: s.maxFields, MaxAggregateBytes: s.maxAggregateBytes,
	})

	return err == nil
}

// validateRecordFieldBounds enforces the existing scalar and leaf-value bounds.
func validateRecordFieldBounds(input RecordFieldSchemaInput) error {
	if nonNegativeRecordFieldBounds(input) && recordFieldBoundsMatchKind(input) {
		return nil
	}

	return newValidationError(
		ErrInvalidFactSchema, "record_schema.fields."+input.Name, input.Name,
		"bounds must match the exact non-recursive value kind",
	)
}

// nonNegativeRecordFieldBounds rejects negative leaf limits before kind matching.
func nonNegativeRecordFieldBounds(input RecordFieldSchemaInput) bool {
	return input.MaxLength >= 0 && input.MaxItems >= 0 && input.MaxBytes >= 0
}

// recordFieldBoundsMatchKind applies the exact leaf-kind limit shape.
func recordFieldBoundsMatchKind(input RecordFieldSchemaInput) bool {
	switch input.Kind {
	case decision.ValueKindString:
		return recordFieldUsesOnlyLength(input)
	case decision.ValueKindStrings:
		return input.MaxLength > 0 && input.MaxItems > 0 && input.MaxBytes == 0
	case decision.ValueKindBytes:
		return recordFieldUsesOnlyBytes(input)
	default:
		return recordFieldHasNoBounds(input)
	}
}

// recordFieldUsesOnlyLength reports whether only a positive text limit is configured.
func recordFieldUsesOnlyLength(input RecordFieldSchemaInput) bool {
	return input.MaxLength > 0 && input.MaxItems == 0 && input.MaxBytes == 0
}

// recordFieldUsesOnlyBytes reports whether only a positive byte limit is configured.
func recordFieldUsesOnlyBytes(input RecordFieldSchemaInput) bool {
	return input.MaxLength == 0 && input.MaxItems == 0 && input.MaxBytes > 0
}

// recordFieldHasNoBounds reports whether scalar fixed-width kinds carry no extra limit.
func recordFieldHasNoBounds(input RecordFieldSchemaInput) bool {
	return input.MaxLength == 0 && input.MaxItems == 0 && input.MaxBytes == 0
}
