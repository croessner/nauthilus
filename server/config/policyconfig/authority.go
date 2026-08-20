// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// FieldPaths returns the canonical leaf paths derived from mapstructure tags.
func FieldPaths() []string {
	paths := make([]string, 0, 128)
	collectFieldPaths(reflect.TypeOf(Document{}), "", nil, &paths)
	sort.Strings(paths)

	return paths
}

// rejectUnknownFields compares decoded keys with the model's mapstructure authority.
func rejectUnknownFields(value any, model reflect.Type, path string) error {
	model = indirectType(model)
	if model == durationType || model == secretType || model.Kind() == reflect.Interface {
		return nil
	}

	switch model.Kind() {
	case reflect.Struct:
		return rejectUnknownStruct(value, model, path)
	case reflect.Map:
		return rejectUnknownMap(value, model, path)
	case reflect.Slice, reflect.Array:
		return rejectUnknownSlice(value, model, path)
	default:
		return nil
	}
}

// rejectUnknownStruct validates one object against its exact tagged fields.
func rejectUnknownStruct(value any, model reflect.Type, path string) error {
	object, ok := stringMap(value)
	if !ok {
		if value == nil {
			return nil
		}

		return newPathError(nonEmptyPath(path), ErrDecode, "must be an object")
	}

	fields := taggedFields(model)
	keys := sortedKeys(object)

	for _, key := range keys {
		field, exists := fields[key]

		fieldPath := joinPath(path, key)
		if !exists {
			return newPathError(fieldPath, ErrUnknownField, "unknown configuration field")
		}

		if err := rejectUnknownFields(object[key], field.Type, fieldPath); err != nil {
			return err
		}
	}

	return nil
}

// rejectUnknownMap validates dynamic map values against their declared element type.
func rejectUnknownMap(value any, model reflect.Type, path string) error {
	object, ok := stringMap(value)
	if !ok {
		if value == nil {
			return nil
		}

		return newPathError(nonEmptyPath(path), ErrDecode, "must be an object")
	}

	for _, key := range sortedKeys(object) {
		if err := rejectUnknownFields(object[key], model.Elem(), joinPath(path, key)); err != nil {
			return err
		}
	}

	return nil
}

// rejectUnknownSlice validates every indexed element against its declared type.
func rejectUnknownSlice(value any, model reflect.Type, path string) error {
	values, ok := value.([]any)
	if !ok {
		if value == nil {
			return nil
		}

		return newPathError(nonEmptyPath(path), ErrDecode, "must be an array")
	}

	for index, item := range values {
		itemPath := fmt.Sprintf("%s[%d]", path, index)
		if err := rejectUnknownFields(item, model.Elem(), itemPath); err != nil {
			return err
		}
	}

	return nil
}

// collectFieldPaths traverses the same tagged model used by strict decoding.
func collectFieldPaths(model reflect.Type, path string, stack map[reflect.Type]bool, result *[]string) {
	model = indirectType(model)

	if stack == nil {
		stack = make(map[reflect.Type]bool)
	}

	if model == durationType || model == secretType || model.Kind() == reflect.Interface {
		*result = append(*result, path)

		return
	}

	switch model.Kind() {
	case reflect.Struct:
		if stack[model] {
			*result = append(*result, path)

			return
		}

		nextStack := cloneTypeStack(stack)
		nextStack[model] = true

		for _, field := range sortedTaggedFields(model) {
			collectFieldPaths(field.Type, joinPath(path, field.Tag.Get("mapstructure")), nextStack, result)
		}
	case reflect.Map:
		collectFieldPaths(model.Elem(), joinPath(path, "<name>"), stack, result)
	case reflect.Slice, reflect.Array:
		collectFieldPaths(model.Elem(), path+"[]", stack, result)
	default:
		*result = append(*result, path)
	}
}

// taggedFields indexes one struct's declared mapstructure fields.
func taggedFields(model reflect.Type) map[string]reflect.StructField {
	result := make(map[string]reflect.StructField, model.NumField())

	for index := range model.NumField() {
		field := model.Field(index)

		name := field.Tag.Get("mapstructure")
		if name == "" || name == "-" {
			continue
		}

		result[name] = field
	}

	return result
}

// sortedTaggedFields returns tagged fields in canonical key order.
func sortedTaggedFields(model reflect.Type) []reflect.StructField {
	fields := taggedFields(model)
	keys := make([]string, 0, len(fields))

	for key := range fields {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	result := make([]reflect.StructField, 0, len(keys))

	for _, key := range keys {
		result = append(result, fields[key])
	}

	return result
}

// stringMap normalizes string-keyed decoder objects for strict traversal.
func stringMap(value any) (map[string]any, bool) {
	if value == nil {
		return nil, true
	}

	if object, ok := value.(map[string]any); ok {
		return object, true
	}

	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Map || reflected.Type().Key().Kind() != reflect.String {
		return nil, false
	}

	result := make(map[string]any, reflected.Len())

	iterator := reflected.MapRange()
	for iterator.Next() {
		result[iterator.Key().String()] = iterator.Value().Interface()
	}

	return result, true
}

// sortedKeys returns deterministic map keys.
func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

// cloneTypeStack detaches one recursion guard for sibling model branches.
func cloneTypeStack(source map[reflect.Type]bool) map[reflect.Type]bool {
	result := make(map[reflect.Type]bool, len(source))
	for key, value := range source {
		result[key] = value
	}

	return result
}

// indirectType unwraps pointers while retaining scalar aliases.
func indirectType(model reflect.Type) reflect.Type {
	for model.Kind() == reflect.Pointer {
		model = model.Elem()
	}

	return model
}

// joinPath joins one canonical field component.
func joinPath(path string, component string) string {
	if path == "" {
		return component
	}

	if component == "" {
		return path
	}

	return path + "." + component
}

// nonEmptyPath supplies a stable root path for malformed documents.
func nonEmptyPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return "policy"
	}

	return path
}
