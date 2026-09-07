// Copyright (C) 2026 Christian Rößner
// SPDX-License-Identifier: GPL-3.0-or-later

package policyconfig

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

// TestDecodeMappingRetainsStrictBoundary rejects malformed settings before they reach runtime preparation.
func TestDecodeMappingRetainsStrictBoundary(t *testing.T) {
	cycle := map[string]any{}
	cycle["policy"] = cycle

	for _, test := range []struct {
		name     string
		settings map[string]any
	}{
		{"unknown field", map[string]any{"policy": map[string]any{"unknown": true}}},
		{"cycle", cycle},
		{"oversized", map[string]any{"policy": strings.Repeat("x", maximumInputSize+1)}},
		{"nonfinite", map[string]any{"policy": math.Inf(1)}},
		{"unsupported", map[string]any{"policy": make(chan bool)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeMapping(test.settings); err == nil {
				t.Fatal("invalid mapping was accepted")
			}
		})
	}
}

// TestPreserveMappingNumbersOwnsContainers prevents encoding from rewriting operator-owned input.
func TestPreserveMappingNumbersOwnsContainers(t *testing.T) {
	input := map[string]any{"values": []any{float64(20), float32(20), 20}}
	if _, err := preserveMappingNumbers(input, reflect.TypeFor[any](), 0); err != nil {
		t.Fatal(err)
	}

	values := input["values"].([]any)
	if _, ok := values[0].(float64); !ok {
		t.Fatal("input float64 was mutated")
	}

	if _, ok := values[1].(float32); !ok {
		t.Fatal("input float32 was mutated")
	}

	if _, ok := values[2].(int); !ok {
		t.Fatal("input integer was mutated")
	}
}
