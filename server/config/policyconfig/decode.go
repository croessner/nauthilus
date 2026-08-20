// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/mitchellh/mapstructure"
	"github.com/pelletier/go-toml/v2"
	"go.yaml.in/yaml/v3"
)

var (
	// ErrDecode identifies invalid standalone policy syntax or types.
	ErrDecode = errors.New("invalid standalone policy configuration")

	// ErrUnknownField identifies a field outside the unified contract.
	ErrUnknownField = errors.New("unknown standalone policy configuration field")
)

const (
	formatJSON                          = "json"
	formatTOML                          = "toml"
	formatYAML                          = "yaml"
	formatYML                           = "yml"
	formatProperties                    = "properties"
	formatProps                         = "props"
	formatProp                          = "prop"
	formatHCL                           = "hcl"
	formatTFVars                        = "tfvars"
	formatDotenv                        = "dotenv"
	formatEnv                           = "env"
	formatINI                           = "ini"
	maximumInputSize                    = 4 * 1024 * 1024
	maximumFlatCollectionItems          = 4096
	maximumFlatAggregateCollectionItems = 16 * 1024
	maximumFlatPathTokens               = 64
	maximumFlatAssignments              = 4096
	maximumNestingDepth                 = 64
)

var supportedFormats = []string{
	formatJSON,
	formatTOML,
	formatYAML,
	formatYML,
	formatProperties,
	formatProps,
	formatProp,
	formatHCL,
	formatTFVars,
	formatDotenv,
	formatEnv,
	formatINI,
}

var (
	durationType = reflect.TypeOf(time.Duration(0))
	secretType   = reflect.TypeOf(secret.Value{})
)

// SupportedFormats returns the isolated decoder's Viper format aliases.
func SupportedFormats() []string {
	return append([]string(nil), supportedFormats...)
}

// Decode strictly decodes one standalone unified policy document.
func Decode(format string, reader io.Reader) (Document, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if !slices.Contains(supportedFormats, format) {
		return Document{}, newPathError("policy", ErrDecode, fmt.Sprintf("unsupported format %q", format))
	}

	settings, err := decodeSettings(format, reader)
	if err != nil {
		var pathError *PathError
		if errors.As(err, &pathError) {
			return Document{}, pathError
		}

		return Document{}, newPathError("policy", ErrDecode, err.Error())
	}

	if err := rejectUnknownFields(settings, reflect.TypeOf(Document{}), ""); err != nil {
		return Document{}, err
	}

	var document Document

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.ComposeDecodeHookFunc(secretDecodeHook, mapstructure.StringToTimeDurationHookFunc()),
		ErrorUnused:      false,
		Metadata:         nil,
		Result:           &document,
		TagName:          "mapstructure",
		WeaklyTypedInput: true,
	})
	if err != nil {
		return Document{}, newPathError("policy", ErrDecode, err.Error())
	}

	if err := decoder.Decode(settings); err != nil {
		return Document{}, newPathError("policy", ErrDecode, err.Error())
	}

	return document, nil
}

// decodeSettings uses an isolated Viper instance without production defaults or keys.
func decodeSettings(format string, reader io.Reader) (map[string]any, error) {
	switch format {
	case formatJSON:
		return decodeJSONSettings(reader)
	case formatTOML:
		return decodeTOMLSettings(reader)
	case formatYAML, formatYML:
		return decodeYAMLSettings(reader)
	case formatProperties, formatProps, formatProp, formatDotenv, formatEnv, formatINI:
		return decodeFlatSettings(format, reader)
	case formatHCL, formatTFVars:
		return decodeHCLSettings(reader)
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
}

// readBoundedSettings reads one complete document and rejects data beyond the shared byte limit.
func readBoundedSettings(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximumInputSize+1))
	if err != nil {
		return nil, err
	}

	if len(data) > maximumInputSize {
		return nil, fmt.Errorf("configuration exceeds maximum input size of %d bytes", maximumInputSize)
	}

	return data, nil
}

// validateNestingDepth rejects recursive codec input before entering an excessive container.
func validateNestingDepth(depth int) error {
	if depth >= maximumNestingDepth {
		return fmt.Errorf("nesting depth exceeds maximum of %d", maximumNestingDepth)
	}

	return nil
}

// decodeJSONSettings preserves empty and unknown objects for strict traversal.
func decodeJSONSettings(reader io.Reader) (map[string]any, error) {
	data, err := readBoundedSettings(reader)
	if err != nil {
		return nil, fmt.Errorf("read json: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	value, err := decodeJSONValue(decoder, "", 0)
	if err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}

	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("decode json trailing data: %w", err)
		}

		return nil, fmt.Errorf("decode json: multiple top-level values")
	}

	result, ok := value.(map[string]any)
	if !ok {
		return nil, newPathError("policy", ErrDecode, "top-level JSON value must be an object")
	}

	return result, nil
}

// decodeJSONValue recursively owns bounded JSON objects while rejecting duplicate keys.
func decodeJSONValue(decoder *json.Decoder, path string, depth int) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}

	if err := validateNestingDepth(depth); err != nil {
		return nil, err
	}

	switch delimiter {
	case '{':
		return decodeJSONObject(decoder, path, depth+1)
	case '[':
		return decodeJSONArray(decoder, path, depth+1)
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

// decodeJSONObject preserves empty objects and rejects duplicate keys at exact nested paths.
func decodeJSONObject(decoder *json.Decoder, path string, depth int) (map[string]any, error) {
	result := make(map[string]any)

	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}

		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("JSON object key must be a string")
		}

		fieldPath := joinPath(path, key)
		if _, exists := result[key]; exists {
			return nil, newPathError(fieldPath, ErrDecode, "duplicate JSON field")
		}

		value, err := decodeJSONValue(decoder, fieldPath, depth)
		if err != nil {
			return nil, err
		}

		result[key] = value
	}

	if _, err := decoder.Token(); err != nil {
		return nil, err
	}

	return result, nil
}

// decodeJSONArray preserves source order and supplies indexed paths to nested objects.
func decodeJSONArray(decoder *json.Decoder, path string, depth int) ([]any, error) {
	result := make([]any, 0)

	for decoder.More() {
		itemPath := fmt.Sprintf("%s[%d]", path, len(result))

		value, err := decodeJSONValue(decoder, itemPath, depth)
		if err != nil {
			return nil, err
		}

		result = append(result, value)
	}

	if _, err := decoder.Token(); err != nil {
		return nil, err
	}

	return result, nil
}

// decodeTOMLSettings preserves the raw object tree before strict traversal.
func decodeTOMLSettings(reader io.Reader) (map[string]any, error) {
	return decodeStructuredSettings(formatTOML, reader, toml.Unmarshal)
}

// decodeYAMLSettings preserves empty and unknown objects before strict traversal.
func decodeYAMLSettings(reader io.Reader) (map[string]any, error) {
	return decodeStructuredSettings(formatYAML, reader, yaml.Unmarshal)
}

// decodeStructuredSettings shares bounded reading and raw-map ownership across structured codecs.
func decodeStructuredSettings(
	format string,
	reader io.Reader,
	unmarshal func([]byte, any) error,
) (map[string]any, error) {
	data, err := readBoundedSettings(reader)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", format, err)
	}

	result := map[string]any{}
	if err := unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode %s: %w", format, err)
	}

	return result, nil
}

// secretDecodeHook converts configured strings directly into the repository secret type.
func secretDecodeHook(from reflect.Type, to reflect.Type, value any) (any, error) {
	if to != secretType {
		return value, nil
	}

	if from.Kind() != reflect.String {
		return nil, fmt.Errorf("secret must be a string")
	}

	return secret.New(value.(string)), nil
}
