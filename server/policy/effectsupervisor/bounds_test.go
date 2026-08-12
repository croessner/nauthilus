// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package effectsupervisor

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateBoundedValueRejectsBytesElementsAndDepth(t *testing.T) {
	tests := []struct {
		name  string
		value any
	}{
		{name: "bytes", value: strings.Repeat("x", 9)},
		{name: "elements", value: []int{1, 2, 3, 4}},
		{name: "depth", value: map[string]any{"one": map[string]any{"two": "value"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateBoundedValue(test.value, WorkBounds{
				MaxBytes:    8,
				MaxElements: 3,
				MaxDepth:    1,
			}); !errors.Is(err, ErrWorkBounds) {
				t.Fatalf("ValidateBoundedValue() error = %v, want ErrWorkBounds", err)
			}
		})
	}
}
