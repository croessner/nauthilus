// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"fmt"
	"strings"
	"testing"
)

func TestPolicyCodecsRejectOversizedInput(t *testing.T) {
	oversized := strings.Repeat(" ", maximumInputSize+1)

	for _, format := range SupportedFormats() {
		t.Run(format, func(t *testing.T) {
			_, err := Decode(format, strings.NewReader(oversized))
			requireLimitError(t, err, "maximum input size")
		})
	}
}

func TestPolicyRecursiveCodecsCapNestingDepth(t *testing.T) {
	levels := maximumNestingDepth + 1
	jsonInput := strings.Repeat(`{"field":`, levels) + `true` + strings.Repeat("}", levels)
	hclInput := strings.Repeat("field { ", levels) + "value = true " + strings.Repeat("} ", levels)
	formats := map[string]string{
		formatJSON:   jsonInput,
		formatHCL:    hclInput,
		formatTFVars: hclInput,
	}

	for format, input := range formats {
		t.Run(format, func(t *testing.T) {
			_, err := Decode(format, strings.NewReader(input))
			requireLimitError(t, err, "nesting depth exceeds maximum")
		})
	}
}

func TestPolicyFlatFormatsRejectSparseArrayIndices(t *testing.T) {
	input := fmt.Sprintf("policy.targets[%d].namespace=dkim2\n", maximumFlatCollectionItems)

	for _, format := range flatFormatAliases() {
		t.Run(format, func(t *testing.T) {
			_, err := Decode(format, strings.NewReader(input))
			requireLimitError(t, err, "array index exceeds maximum collection size")
		})
	}
}

func TestPolicyFlatFormatsCapPathTokens(t *testing.T) {
	components := make([]string, maximumFlatPathTokens+1)
	for index := range components {
		components[index] = fmt.Sprintf("field%d", index)
	}

	input := strings.Join(components, ".") + "=true\n"

	for _, format := range flatFormatAliases() {
		t.Run(format, func(t *testing.T) {
			_, err := Decode(format, strings.NewReader(input))
			requireLimitError(t, err, "path exceeds maximum token count")
		})
	}
}

func TestPolicyFlatFormatsCapAssignments(t *testing.T) {
	var input strings.Builder

	for index := 0; index <= maximumFlatAssignments; index++ {
		fmt.Fprintf(&input, "field%d=true\n", index)
	}

	for _, format := range flatFormatAliases() {
		t.Run(format, func(t *testing.T) {
			_, err := Decode(format, strings.NewReader(input.String()))
			requireLimitError(t, err, "assignment count exceeds maximum")
		})
	}
}

func TestPolicyFlatFormatsCapAggregateSliceGrowth(t *testing.T) {
	const boundedIndex = 4

	var input strings.Builder

	assignments := maximumFlatAggregateCollectionItems/(boundedIndex+1) + 1

	for index := range assignments {
		fmt.Fprintf(&input, "field%d.items[%d]=true\n", index, boundedIndex)
	}

	if input.Len() >= maximumInputSize {
		t.Fatal("aggregate-growth fixture exceeds the input-size bound")
	}

	for _, format := range flatFormatAliases() {
		t.Run(format, func(t *testing.T) {
			_, err := Decode(format, strings.NewReader(input.String()))
			requireLimitError(t, err, "aggregate collection growth exceeds maximum")
		})
	}
}

// flatFormatAliases returns every alias owned by the bounded flat decoder.
func flatFormatAliases() []string {
	return []string{formatProperties, formatProps, formatProp, formatDotenv, formatEnv, formatINI}
}

// requireLimitError verifies one decoder rejected input for the expected bound.
func requireLimitError(t *testing.T, err error, message string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected limit error containing %q", message)
	}

	if !strings.Contains(err.Error(), message) {
		t.Fatalf("expected limit error containing %q, got %v", message, err)
	}
}
