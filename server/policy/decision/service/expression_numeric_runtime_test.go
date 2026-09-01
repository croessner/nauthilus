// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

func TestRuntimeComparesIntegerThresholdWithDoubleFact(t *testing.T) {
	integer := int64(10)
	double := 10.0

	integerValue, err := decision.NewValue(decision.ValueInput{Integer: &integer})
	if err != nil {
		t.Fatalf("NewValue(integer) error = %v", err)
	}

	doubleValue, err := decision.NewValue(decision.ValueInput{Double: &double})
	if err != nil {
		t.Fatalf("NewValue(double) error = %v", err)
	}

	comparison, ok := compareRuntimeValue(doubleValue, integerValue)
	if !ok || comparison != 0 {
		t.Fatalf("compareRuntimeValue(double, integer) = (%d, %t), want (0, true)", comparison, ok)
	}

	if !equalRuntimeValue(doubleValue, integerValue) {
		t.Fatal("equalRuntimeValue(double, integer) = false, want numeric equality")
	}

	largeInteger := int64(9_007_199_254_740_993)
	roundedDouble := float64(9_007_199_254_740_992)

	largeIntegerValue, err := decision.NewValue(decision.ValueInput{Integer: &largeInteger})
	if err != nil {
		t.Fatalf("NewValue(large integer) error = %v", err)
	}

	roundedDoubleValue, err := decision.NewValue(decision.ValueInput{Double: &roundedDouble})
	if err != nil {
		t.Fatalf("NewValue(rounded double) error = %v", err)
	}

	comparison, ok = compareRuntimeValue(roundedDoubleValue, largeIntegerValue)
	if !ok || comparison >= 0 {
		t.Fatalf("compareRuntimeValue(rounded double, large integer) = (%d, %t), want exact less-than", comparison, ok)
	}
}
