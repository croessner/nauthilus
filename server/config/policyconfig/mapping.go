// Copyright (C) 2026 Christian Rößner
// SPDX-License-Identifier: GPL-3.0-or-later

package policyconfig

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
)

// DecodeMapping strictly decodes detached settings while retaining authored integer and double kinds.
func DecodeMapping(settings map[string]any) (Document, error) {
	prepared, err := preserveMappingNumbers(settings, reflect.TypeFor[Document](), 0)
	if err != nil {
		return Document{}, newPathError("policy", ErrDecode, err.Error())
	}

	encoded, err := json.Marshal(prepared)
	if err != nil {
		return Document{}, newPathError("policy", ErrDecode, "cannot encode policy settings")
	}

	return Decode(formatJSON, bytes.NewReader(encoded))
}

// preserveMappingNumbers detaches bounded containers and preserves integral floating-point spelling.
func preserveMappingNumbers(value any, model reflect.Type, depth int) (any, error) {
	if err := validateNestingDepth(depth); err != nil {
		return nil, err
	}

	switch typed := value.(type) {
	case map[string]any:
		return preserveMappingObject(typed, model, depth)
	case []any:
		return preserveMappingList(typed, model, depth)
	case float64:
		if indirectType(model).Kind() == reflect.Interface {
			return mappingDouble(typed, 64), nil
		}
	case float32:
		if indirectType(model).Kind() == reflect.Interface {
			return mappingDouble(float64(typed), 32), nil
		}
	}

	return value, nil
}

// mappingDouble ensures the strict JSON decoder can distinguish doubles from integers.
func mappingDouble(value float64, bits int) json.Number {
	spelling := strconv.FormatFloat(value, 'g', -1, bits)
	if !strings.ContainsAny(spelling, ".eE") {
		spelling += ".0"
	}

	return json.Number(spelling)
}

// mappingValueModel follows the shared schema authority while leaving expression values dynamically typed.
func mappingValueModel(model reflect.Type, key string) reflect.Type {
	model = indirectType(model)
	switch model.Kind() {
	case reflect.Struct:
		if field, ok := taggedFields(model)[key]; ok {
			return field.Type
		}
	case reflect.Map, reflect.Slice, reflect.Array:
		return model.Elem()
	}

	return reflect.TypeFor[any]()
}

// preserveMappingObject detaches one object while resolving each value through the shared schema.
func preserveMappingObject(typed map[string]any, model reflect.Type, depth int) (any, error) {
	if typed == nil {
		return typed, nil
	}

	result := make(map[string]any, len(typed))
	for key, item := range typed {
		prepared, err := preserveMappingNumbers(item, mappingValueModel(model, key), depth+1)
		if err != nil {
			return nil, err
		}

		result[key] = prepared
	}

	return result, nil
}

// preserveMappingList detaches one list without changing the kind of its authored scalar values.
func preserveMappingList(typed []any, model reflect.Type, depth int) (any, error) {
	if typed == nil {
		return typed, nil
	}

	result := make([]any, len(typed))
	for index, item := range typed {
		prepared, err := preserveMappingNumbers(item, mappingValueModel(model, ""), depth+1)
		if err != nil {
			return nil, err
		}

		result[index] = prepared
	}

	return result, nil
}
