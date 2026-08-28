// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"fmt"
	"sort"
)

const (
	staticValueKindString  = "string"
	staticValueKindStrings = "strings"
	staticValueKindBytes   = "bytes"
	staticValueKindRecords = "records"
)

// StaticTargetSchemaConfig owns exact schema versions for one namespace-local target action.
type StaticTargetSchemaConfig struct {
	Versions map[string]StaticSchemaVersionConfig `mapstructure:"versions"`
}

// StaticSchemaVersionConfig declares the complete fact vocabulary of one exact version.
type StaticSchemaVersionConfig struct {
	Facts []StaticFactSchemaConfig `mapstructure:"facts"`
}

// StaticFactSchemaConfig declares one typed and source-bounded schema fact.
type StaticFactSchemaConfig struct {
	RecordSchema   *StaticRecordSchemaConfig `mapstructure:"record_schema"`
	Attribute      string                    `mapstructure:"attribute"`
	Category       string                    `mapstructure:"category"`
	Type           string                    `mapstructure:"type"`
	AllowedSources []string                  `mapstructure:"allowed_sources"`
	MaxLength      int                       `mapstructure:"max_length"`
	MaxItems       int                       `mapstructure:"max_items"`
	MaxBytes       int                       `mapstructure:"max_bytes"`
	Required       bool                      `mapstructure:"required"`
}

// StaticRecordSchemaConfig declares one closed ordered schema-owned record collection.
type StaticRecordSchemaConfig struct {
	ID                string                          `mapstructure:"id"`
	Version           string                          `mapstructure:"version"`
	Fields            []StaticRecordFieldSchemaConfig `mapstructure:"fields"`
	MinRecords        int                             `mapstructure:"min_records"`
	MaxRecords        int                             `mapstructure:"max_records"`
	MaxFields         int                             `mapstructure:"max_fields"`
	MaxAggregateBytes int                             `mapstructure:"max_aggregate_bytes"`
}

// StaticRecordFieldSchemaConfig declares one non-recursive record field.
type StaticRecordFieldSchemaConfig struct {
	Name               string   `mapstructure:"name"`
	Type               string   `mapstructure:"type"`
	ProviderVisibility []string `mapstructure:"provider_visibility"`
	MaxLength          int      `mapstructure:"max_length"`
	MaxItems           int      `mapstructure:"max_items"`
	MaxBytes           int      `mapstructure:"max_bytes"`
	Required           bool     `mapstructure:"required"`
	ExpressionVisible  bool     `mapstructure:"expression_visible"`
}

// validateStaticSchemas enforces exact version, fact, source, and builtin ownership contracts.
func validateStaticSchemas(
	namespace string,
	configured map[string]StaticTargetSchemaConfig,
	path string,
) error {
	if namespace == authnNamespace && len(configured) > 0 {
		return invalid(path, "authn schemas are supplied only by the builtin contributor")
	}

	for _, action := range sortedStaticActions(configured) {
		actionPath := path + "." + action
		if !validAction(action) {
			return invalid(actionPath, "must be a canonical target action")
		}

		versions := configured[action].Versions
		if len(versions) == 0 {
			return invalid(actionPath+".versions", "must contain at least one exact schema version")
		}

		for _, version := range sortedStaticVersions(versions) {
			versionPath := actionPath + ".versions." + version
			if !validExactVersion(version) {
				return invalid(versionPath, "must be an exact positive vN version")
			}

			if err := validateStaticFacts(versions[version].Facts, versionPath+".facts"); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateStaticFacts enforces one collision-free exact fact vocabulary.
func validateStaticFacts(facts []StaticFactSchemaConfig, path string) error {
	seen := make(map[string]struct{}, len(facts))

	for index, fact := range facts {
		factPath := fmt.Sprintf("%s[%d]", path, index)
		if !validFact(fact.Attribute) {
			return invalid(factPath+".attribute", "must be a canonical fact identity")
		}

		if _, exists := seen[fact.Attribute]; exists {
			return invalid(factPath+".attribute", "must be unique within the exact schema")
		}

		seen[fact.Attribute] = struct{}{}

		if !validStaticCategory(fact.Category) {
			return invalid(factPath+".category", "must be subject, resource, or environment")
		}

		if !validValueKind(fact.Type) {
			return invalid(factPath+".type", "must be an exact value kind")
		}

		if err := validateStaticSources(fact.AllowedSources, factPath+".allowed_sources"); err != nil {
			return err
		}

		if !validStaticBounds(fact) {
			return invalid(factPath, "bounds must match the exact value kind")
		}

		if err := validateStaticRecordSchema(fact, factPath); err != nil {
			return err
		}
	}

	return nil
}

// validateStaticRecordSchema binds records to one closed schema and forbids it on all other kinds.
func validateStaticRecordSchema(fact StaticFactSchemaConfig, path string) error {
	if fact.Type != staticValueKindRecords {
		if fact.RecordSchema != nil {
			return invalid(path+".record_schema", "is legal only for records facts")
		}

		return nil
	}

	if fact.RecordSchema == nil {
		return invalid(path+".record_schema", "records facts must own one closed record schema")
	}

	schema := fact.RecordSchema

	if err := validateStaticRecordSchemaBounds(schema, path); err != nil {
		return err
	}

	return validateStaticRecordFields(schema, path)
}

// validateStaticRecordSchemaBounds checks schema identity and collection-wide limits.
func validateStaticRecordSchemaBounds(schema *StaticRecordSchemaConfig, path string) error {
	if !validAction(schema.ID) || !validExactVersion(schema.Version) {
		return invalid(path+".record_schema", "id and version must be exact canonical values")
	}

	if len(schema.Fields) == 0 || schema.MinRecords < 0 || schema.MaxRecords <= 0 ||
		schema.MinRecords > schema.MaxRecords || schema.MaxFields <= 0 ||
		schema.MaxFields > len(schema.Fields) || schema.MaxAggregateBytes <= 0 {
		return invalid(path+".record_schema", "must declare positive bounded record, field, and aggregate limits")
	}

	return nil
}

// validateStaticRecordFields checks exact ordered fields and the required-field budget.
func validateStaticRecordFields(schema *StaticRecordSchemaConfig, path string) error {
	seen := make(map[string]struct{}, len(schema.Fields))
	required := 0

	for index, field := range schema.Fields {
		fieldPath := fmt.Sprintf("%s.record_schema.fields[%d]", path, index)

		if err := validateStaticRecordField(field, fieldPath, seen); err != nil {
			return err
		}

		seen[field.Name] = struct{}{}

		if field.Required {
			required++
		}
	}

	if required > schema.MaxFields {
		return invalid(path+".record_schema.max_fields", "must admit every required field")
	}

	return nil
}

// validateStaticRecordField checks one non-recursive field declaration.
func validateStaticRecordField(
	field StaticRecordFieldSchemaConfig,
	path string,
	seen map[string]struct{},
) error {
	if !validAction(field.Name) {
		return invalid(path+".name", "must be a canonical local field name")
	}

	if _, exists := seen[field.Name]; exists {
		return invalid(path+".name", "must be unique within the record schema")
	}

	if !validValueKind(field.Type) || field.Type == staticValueKindRecords {
		return invalid(path+".type", "must be a non-recursive record-field value kind")
	}

	if !validStaticRecordFieldBounds(field) {
		return invalid(path, "bounds must match the exact record-field value kind")
	}

	return validateStaticProviderVisibility(field.ProviderVisibility, path+".provider_visibility")
}

// validateStaticProviderVisibility checks one duplicate-free exact provider allowlist.
func validateStaticProviderVisibility(providerIDs []string, path string) error {
	seen := make(map[string]struct{}, len(providerIDs))

	for index, providerID := range providerIDs {
		providerPath := fmt.Sprintf("%s[%d]", path, index)

		if !validProviderUse(providerID) {
			return invalid(providerPath, "must be an exact provider identity")
		}

		if _, exists := seen[providerID]; exists {
			return invalid(providerPath, "must be unique")
		}

		seen[providerID] = struct{}{}
	}

	return nil
}

// validStaticRecordFieldBounds mirrors the registry's existing leaf-value bounds.
func validStaticRecordFieldBounds(field StaticRecordFieldSchemaConfig) bool {
	fact := StaticFactSchemaConfig{
		Type: field.Type, MaxLength: field.MaxLength, MaxItems: field.MaxItems, MaxBytes: field.MaxBytes,
	}

	return validStaticBounds(fact)
}

// validateStaticSources enforces the closed collision-free source vocabulary.
func validateStaticSources(sources []string, path string) error {
	if len(sources) == 0 {
		return invalid(path, "must contain at least one exact source")
	}

	seen := make(map[string]struct{}, len(sources))
	for index, source := range sources {
		if !validStaticSource(source) {
			return invalid(fmt.Sprintf("%s[%d]", path, index), "must be a registered fact source")
		}

		if _, exists := seen[source]; exists {
			return invalid(fmt.Sprintf("%s[%d]", path, index), "must be unique")
		}

		seen[source] = struct{}{}
	}

	return nil
}

// validStaticBounds mirrors the transport-neutral registry's kind-specific bounds.
func validStaticBounds(fact StaticFactSchemaConfig) bool {
	if fact.MaxLength < 0 || fact.MaxItems < 0 || fact.MaxBytes < 0 {
		return false
	}

	switch fact.Type {
	case staticValueKindString:
		return validStaticStringBounds(fact)
	case staticValueKindStrings:
		return validStaticStringListBounds(fact)
	case staticValueKindBytes:
		return validStaticByteBounds(fact)
	case staticValueKindRecords:
		return validStaticScalarBounds(fact)
	default:
		return validStaticScalarBounds(fact)
	}
}

// validStaticStringBounds requires one positive text length and no other bounds.
func validStaticStringBounds(fact StaticFactSchemaConfig) bool {
	return fact.MaxLength > 0 && fact.MaxItems == 0 && fact.MaxBytes == 0
}

// validStaticStringListBounds requires bounded list cardinality and member length.
func validStaticStringListBounds(fact StaticFactSchemaConfig) bool {
	return fact.MaxLength > 0 && fact.MaxItems > 0 && fact.MaxBytes == 0
}

// validStaticByteBounds requires one positive byte length and no other bounds.
func validStaticByteBounds(fact StaticFactSchemaConfig) bool {
	return fact.MaxLength == 0 && fact.MaxItems == 0 && fact.MaxBytes > 0
}

// validStaticScalarBounds rejects size bounds on scalar values.
func validStaticScalarBounds(fact StaticFactSchemaConfig) bool {
	return fact.MaxLength == 0 && fact.MaxItems == 0 && fact.MaxBytes == 0
}

// validExactVersion rejects aliases, ranges, leading zeroes, and replacement spelling.
func validExactVersion(version string) bool {
	if len(version) < 2 || version[0] != 'v' || version[1] == '0' {
		return false
	}

	for index := 1; index < len(version); index++ {
		if version[index] < '0' || version[index] > '9' {
			return false
		}
	}

	return true
}

// validStaticCategory reports whether a fact belongs to one closed policy category.
func validStaticCategory(category string) bool {
	return category == "subject" || category == "resource" || category == "environment"
}

// validStaticSource reports whether a fact source belongs to the registry vocabulary.
func validStaticSource(source string) bool {
	switch source {
	case "caller", "token", "transport", "nauthilus", "backend", "lua", keywordPlugin:
		return true
	default:
		return false
	}
}

// sortedStaticActions returns deterministic action keys.
func sortedStaticActions(values map[string]StaticTargetSchemaConfig) []string {
	result := make([]string, 0, len(values))
	for action := range values {
		result = append(result, action)
	}

	sort.Strings(result)

	return result
}

// sortedStaticVersions returns deterministic exact version keys.
func sortedStaticVersions(values map[string]StaticSchemaVersionConfig) []string {
	result := make([]string, 0, len(values))
	for version := range values {
		result = append(result, version)
	}

	sort.Strings(result)

	return result
}
