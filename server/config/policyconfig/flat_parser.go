// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type pathToken struct {
	key   string
	index int
	isKey bool
}

// flatSettingsDecoder accumulates one flat-format document and its current INI section.
type flatSettingsDecoder struct {
	root        map[string]any
	format      string
	section     string
	assignments int
	sliceItems  int
}

// flatQuoteState tracks whether punctuation is currently quoted or escaped.
type flatQuoteState struct {
	quote   byte
	escaped bool
}

// decodeFlatSettings parses bounded dotted properties, dotenv, and INI representations.
func decodeFlatSettings(format string, reader io.Reader) (map[string]any, error) {
	data, err := readBoundedSettings(reader)
	if err != nil {
		return nil, fmt.Errorf("read flat configuration: %w", err)
	}

	decoder := &flatSettingsDecoder{
		root:   map[string]any{},
		format: format,
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))

	scanner.Buffer(make([]byte, 4096), maximumInputSize+1)

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		if err := decoder.decodeLine(scanner.Text()); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read flat configuration: %w", err)
	}

	return decoder.root, nil
}

// decodeLine merges one flat-format assignment into the decoder tree.
func (decoder *flatSettingsDecoder) decodeLine(rawLine string) error {
	line := strings.TrimSpace(rawLine)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return nil
	}

	section, err := decoder.readINISection(line)
	if err != nil || section {
		return err
	}

	key, rawValue, err := splitFlatAssignment(line)
	if err != nil {
		return err
	}

	if decoder.assignments >= maximumFlatAssignments {
		return fmt.Errorf("assignment count exceeds maximum of %d", maximumFlatAssignments)
	}

	decoder.assignments++

	if decoder.section != "" {
		key = decoder.section + "." + key
	}

	value, err := parseFlatValue(rawValue)
	if err != nil {
		return err
	}

	tokens, err := parseDottedPath(key)
	if err != nil {
		return err
	}

	updated, err := decoder.assignPath(decoder.root, tokens, value)
	if err != nil {
		return err
	}

	decoder.root = updated.(map[string]any)

	return nil
}

// readINISection consumes an INI section header when the selected format supports it.
func (decoder *flatSettingsDecoder) readINISection(line string) (bool, error) {
	if decoder.format != formatINI || !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
		return false, nil
	}

	decoder.section = strings.TrimSpace(line[1 : len(line)-1])
	if decoder.section == "" {
		return true, fmt.Errorf("empty INI section")
	}

	return true, nil
}

// splitFlatAssignment separates one bounded key/value line outside quotes.
func splitFlatAssignment(line string) (string, string, error) {
	line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
	state := flatQuoteState{}

	for index := range len(line) {
		current := line[index]

		if state.isSyntax(current) && (current == '=' || current == ':') {
			key := strings.TrimSpace(line[:index])

			if key == "" {
				return "", "", fmt.Errorf("empty key")
			}

			return key, strings.TrimSpace(line[index+1:]), nil
		}
	}

	return "", "", fmt.Errorf("missing assignment delimiter")
}

// parseFlatValue decodes JSON-like scalars and arrays while retaining durations as strings.
func parseFlatValue(raw string) (any, error) {
	raw = stripFlatComment(strings.TrimSpace(raw))
	if raw == "" {
		return "", nil
	}

	if strings.HasPrefix(raw, "'") && strings.HasSuffix(raw, "'") && len(raw) >= 2 {
		return raw[1 : len(raw)-1], nil
	}

	if strings.HasPrefix(raw, "\"") || strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, "{") {
		var value any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return nil, fmt.Errorf("invalid JSON-like value: %w", err)
		}

		return value, nil
	}

	if value, err := strconv.ParseBool(raw); err == nil {
		return value, nil
	}

	if value, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return value, nil
	}

	if value, err := strconv.ParseFloat(raw, 64); err == nil {
		return value, nil
	}

	return raw, nil
}

// stripFlatComment removes trailing unquoted flat-format comments.
func stripFlatComment(value string) string {
	state := flatQuoteState{}

	for index := range len(value) {
		current := value[index]

		if state.isSyntax(current) && (current == '#' || current == ';') {
			return strings.TrimSpace(value[:index])
		}
	}

	return value
}

// isSyntax updates quote state and reports whether the byte has unquoted syntax meaning.
func (state *flatQuoteState) isSyntax(current byte) bool {
	if state.escaped {
		state.escaped = false

		return false
	}

	if current == '\\' && state.quote != 0 {
		state.escaped = true

		return false
	}

	if current != '\'' && current != '"' {
		return state.quote == 0
	}

	switch state.quote {
	case 0:
		state.quote = current
	case current:
		state.quote = 0
	}

	return false
}

// parseDottedPath parses escaped map keys and numeric array indices from a flat key.
func parseDottedPath(value string) ([]pathToken, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty path")
	}

	parts, err := splitFlatPathComponents(value)
	if err != nil {
		return nil, err
	}

	tokens := make([]pathToken, 0, len(parts))

	for _, part := range parts {
		partTokens, err := parsePathPart(part)
		if err != nil {
			return nil, err
		}

		if len(tokens)+len(partTokens) > maximumFlatPathTokens {
			return nil, fmt.Errorf("path exceeds maximum token count of %d", maximumFlatPathTokens)
		}

		tokens = append(tokens, partTokens...)
	}

	if len(tokens) == 0 || !tokens[0].isKey {
		return nil, fmt.Errorf("path must start with a field name")
	}

	return tokens, nil
}

// splitFlatPathComponents splits unescaped dots and decodes escaped dots and backslashes.
func splitFlatPathComponents(value string) ([]string, error) {
	var (
		component strings.Builder
		parts     = make([]string, 0, maximumFlatPathTokens)
		escaped   bool
	)

	for index := range len(value) {
		current := value[index]

		if escaped {
			if current != '.' && current != '\\' {
				return nil, fmt.Errorf("unsupported path escape \\%c", current)
			}

			component.WriteByte(current)

			escaped = false

			continue
		}

		if current == '\\' {
			escaped = true

			continue
		}

		if current == '.' {
			if component.Len() == 0 {
				return nil, fmt.Errorf("empty path component")
			}

			var err error

			parts, err = appendFlatPathComponent(parts, component.String())
			if err != nil {
				return nil, err
			}

			component.Reset()

			continue
		}

		component.WriteByte(current)
	}

	if escaped {
		return nil, fmt.Errorf("unterminated path escape")
	}

	if component.Len() == 0 {
		return nil, fmt.Errorf("empty path component")
	}

	return appendFlatPathComponent(parts, component.String())
}

// appendFlatPathComponent adds one decoded component without exceeding the token-depth bound.
func appendFlatPathComponent(parts []string, component string) ([]string, error) {
	if len(parts) >= maximumFlatPathTokens {
		return nil, fmt.Errorf("path exceeds maximum token count of %d", maximumFlatPathTokens)
	}

	return append(parts, component), nil
}

// parsePathPart splits one dotted component into a key and bracket indices.
func parsePathPart(part string) ([]pathToken, error) {
	part = strings.TrimSpace(part)
	if part == "" {
		return nil, fmt.Errorf("empty path component")
	}

	if index, err := strconv.Atoi(part); err == nil {
		if err := validateFlatArrayIndex(index); err != nil {
			return nil, err
		}

		return []pathToken{{index: index}}, nil
	}

	var (
		bracket = strings.IndexByte(part, '[')
		name    = part
	)

	if bracket >= 0 {
		name = part[:bracket]
	}

	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("empty field name")
	}

	result := []pathToken{{key: strings.ToLower(name), isKey: true}}
	remainder := part[len(name):]

	return appendFlatPathIndices(part, remainder, result)
}

// appendFlatPathIndices parses bounded bracket indices after one field name.
func appendFlatPathIndices(part string, remainder string, result []pathToken) ([]pathToken, error) {
	for remainder != "" {
		if remainder[0] != '[' {
			return nil, fmt.Errorf("invalid array path %q", part)
		}

		end := strings.IndexByte(remainder, ']')
		if end < 0 {
			return nil, fmt.Errorf("unterminated array path %q", part)
		}

		index, err := strconv.Atoi(remainder[1:end])
		if err != nil || index < 0 {
			return nil, fmt.Errorf("invalid array index in %q", part)
		}

		if err := validateFlatArrayIndex(index); err != nil {
			return nil, err
		}

		if len(result) >= maximumFlatPathTokens {
			return nil, fmt.Errorf("path exceeds maximum token count of %d", maximumFlatPathTokens)
		}

		result = append(result, pathToken{index: index})
		remainder = remainder[end+1:]
	}

	return result, nil
}

// validateFlatArrayIndex rejects negative and sparse indices before any slice growth.
func validateFlatArrayIndex(index int) error {
	if index < 0 {
		return fmt.Errorf("negative path index")
	}

	if index >= maximumFlatCollectionItems {
		return fmt.Errorf("array index exceeds maximum collection size of %d", maximumFlatCollectionItems)
	}

	return nil
}

// assignPath immutably grows maps and bounded slices along one parsed flat path.
func (decoder *flatSettingsDecoder) assignPath(node any, tokens []pathToken, value any) (any, error) {
	if len(tokens) == 0 {
		if node != nil {
			return nil, fmt.Errorf("duplicate configuration path")
		}

		return value, nil
	}

	token := tokens[0]
	if token.isKey {
		return decoder.assignObjectPath(node, token, tokens[1:], value)
	}

	return decoder.assignArrayPath(node, token, tokens[1:], value)
}

// assignObjectPath grows one object field before descending into the remaining path.
func (decoder *flatSettingsDecoder) assignObjectPath(
	node any,
	token pathToken,
	remainder []pathToken,
	value any,
) (any, error) {
	object, ok := node.(map[string]any)
	if node == nil {
		object = map[string]any{}
		ok = true
	}

	if !ok {
		return nil, fmt.Errorf("field conflicts with a scalar value")
	}

	child, err := decoder.assignPath(object[token.key], remainder, value)
	if err != nil {
		return nil, err
	}

	object[token.key] = child

	return object, nil
}

// assignArrayPath reserves bounded aggregate slice growth before descending into one index.
func (decoder *flatSettingsDecoder) assignArrayPath(
	node any,
	token pathToken,
	remainder []pathToken,
	value any,
) (any, error) {
	if err := validateFlatArrayIndex(token.index); err != nil {
		return nil, err
	}

	values, ok := node.([]any)
	if node == nil {
		values = []any{}
		ok = true
	}

	if !ok {
		return nil, fmt.Errorf("array index conflicts with an object or scalar")
	}

	growth := token.index + 1 - len(values)
	if growth > 0 {
		if decoder.sliceItems+growth > maximumFlatAggregateCollectionItems {
			return nil, fmt.Errorf(
				"aggregate collection growth exceeds maximum of %d elements",
				maximumFlatAggregateCollectionItems,
			)
		}

		decoder.sliceItems += growth
	}

	for len(values) <= token.index {
		values = append(values, nil)
	}

	child, err := decoder.assignPath(values[token.index], remainder, value)
	if err != nil {
		return nil, err
	}

	values[token.index] = child

	return values, nil
}
