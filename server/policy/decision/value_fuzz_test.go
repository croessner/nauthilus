// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package decision

import (
	"math"
	"testing"
	"time"
)

func FuzzTypedValueConstruction(f *testing.F) {
	f.Add(uint8(0), "value", []byte("bytes"), uint64(0x3ff0000000000000), false)
	f.Add(uint8(3), "", []byte{}, uint64(0x7ff8000000000001), false)
	f.Add(uint8(4), "", []byte{}, uint64(0), false)
	f.Add(uint8(5), "", []byte{}, uint64(0), false)
	f.Add(uint8(2), "ambiguous", []byte("owned"), uint64(42), true)

	f.Fuzz(func(t *testing.T, kind uint8, text string, payload []byte, bits uint64, ambiguous bool) {
		if len(text) > 4096 || len(payload) > 64*1024 {
			t.Skip()
		}

		input := fuzzTypedValueInput(kind, text, payload, bits)
		if ambiguous {
			makeTypedValueInputAmbiguous(&input)
		}

		value, err := NewValue(input)
		if ambiguous {
			if err == nil {
				t.Fatal("NewValue() accepted more than one active kind")
			}

			return
		}

		if err != nil {
			return
		}

		if !value.Kind().IsValid() {
			t.Fatalf("NewValue() produced invalid kind %q", value.Kind())
		}

		assertTypedValueOwnsCollections(t, value, input)
	})
}

// fuzzTypedValueInput constructs one bounded closed-kind constructor input.
func fuzzTypedValueInput(kind uint8, text string, payload []byte, bits uint64) ValueInput {
	boolean := bits&1 == 1
	integer := int64(bits)
	double := math.Float64frombits(bits)
	timestamp := time.Unix(0, int64(bits)).UTC()

	switch kind % 7 {
	case 0:
		return ValueInput{String: &text}
	case 1:
		return ValueInput{Boolean: &boolean}
	case 2:
		return ValueInput{Integer: &integer}
	case 3:
		return ValueInput{Double: &double}
	case 4:
		if len(payload) == 0 {
			return ValueInput{Strings: []string{}}
		}

		return ValueInput{Strings: []string{text}}
	case 5:
		return ValueInput{Bytes: append([]byte{}, payload...)}
	default:
		return ValueInput{Timestamp: &timestamp}
	}
}

// makeTypedValueInputAmbiguous activates a second distinct constructor member.
func makeTypedValueInputAmbiguous(input *ValueInput) {
	if input.String != nil {
		boolean := false
		input.Boolean = &boolean

		return
	}

	text := "second-kind"
	input.String = &text
}

// assertTypedValueOwnsCollections verifies empty presence and defensive copying.
func assertTypedValueOwnsCollections(t *testing.T, value Value, input ValueInput) {
	t.Helper()

	if stringsValue, ok := value.Strings(); ok {
		if stringsValue == nil {
			t.Fatal("Strings() lost an active empty collection")
		}

		if len(input.Strings) > 0 {
			input.Strings[0] = "mutated"
			if owned, _ := value.Strings(); len(owned) != 1 || owned[0] == "mutated" {
				t.Fatalf("Strings() did not preserve ownership: %v", owned)
			}
		}
	}

	if bytesValue, ok := value.Bytes(); ok {
		if bytesValue == nil {
			t.Fatal("Bytes() lost an active empty collection")
		}

		if len(input.Bytes) > 0 {
			input.Bytes[0] ^= 0xff
			if owned, _ := value.Bytes(); len(owned) > 0 && owned[0] == input.Bytes[0] {
				t.Fatalf("Bytes() did not preserve ownership: %v", owned)
			}
		}
	}
}
