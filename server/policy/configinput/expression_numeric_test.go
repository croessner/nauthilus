// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

// TestNormalizeValuePreservesExplicitWholeFloatKind proves typed number thresholds remain doubles.
func TestNormalizeValuePreservesExplicitWholeFloatKind(t *testing.T) {
	tests := []struct {
		configured any
		want       decision.ValueKind
		name       string
	}{
		{name: "integer", configured: 10, want: decision.ValueKindInteger},
		{name: "explicit whole float", configured: 10.0, want: decision.ValueKindDouble},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := normalizeValue(test.configured)
			if err != nil {
				t.Fatalf("normalizeValue() error = %v", err)
			}

			if value.Kind() != test.want {
				t.Fatalf("normalizeValue() kind = %s, want %s", value.Kind(), test.want)
			}
		})
	}
}
