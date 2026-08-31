// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package decision_test

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

func TestValueRequiresExactlyOneKind(t *testing.T) {
	text := "mail"
	boolean := true

	tests := []struct {
		name  string
		input decision.ValueInput
	}{
		{name: "missing kind", input: decision.ValueInput{}},
		{name: "multiple kinds", input: decision.ValueInput{String: &text, Boolean: &boolean}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decision.NewValue(test.input)
			if !errors.Is(err, decision.ErrInvalidValue) {
				t.Fatalf("NewValue() error = %v, want ErrInvalidValue", err)
			}
		})
	}
}

func TestValueAcceptsStrictScalarKinds(t *testing.T) {
	text := "mail"
	boolean := true
	integer := int64(math.MinInt64)
	double := 0.5
	timestamp := time.Date(2026, time.August, 12, 8, 30, 0, 123, time.FixedZone("test", 3600))

	tests := []struct {
		name string
		kind decision.ValueKind
		in   decision.ValueInput
	}{
		{name: "string", kind: decision.ValueKindString, in: decision.ValueInput{String: &text}},
		{name: "boolean", kind: decision.ValueKindBoolean, in: decision.ValueInput{Boolean: &boolean}},
		{name: "integer", kind: decision.ValueKindInteger, in: decision.ValueInput{Integer: &integer}},
		{name: "double", kind: decision.ValueKindDouble, in: decision.ValueInput{Double: &double}},
		{name: "timestamp", kind: decision.ValueKindTimestamp, in: decision.ValueInput{Timestamp: &timestamp}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := decision.NewValue(test.in)
			if err != nil {
				t.Fatalf("NewValue() error = %v", err)
			}

			if value.Kind() != test.kind {
				t.Fatalf("Value.Kind() = %q, want %q", value.Kind(), test.kind)
			}
		})
	}
}

func TestIntegerValueRejectsOutOfRangeInput(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int64
		ok   bool
	}{
		{name: "minimum", raw: "-9223372036854775808", want: math.MinInt64, ok: true},
		{name: "maximum", raw: "9223372036854775807", want: math.MaxInt64, ok: true},
		{name: "below minimum", raw: "-9223372036854775809"},
		{name: "above maximum", raw: "9223372036854775808"},
		{name: "fraction", raw: "1.25"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := decision.ParseIntegerValue(test.raw)
			if !test.ok {
				if !errors.Is(err, decision.ErrInvalidValue) {
					t.Fatalf("ParseIntegerValue() error = %v, want ErrInvalidValue", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("ParseIntegerValue() error = %v", err)
			}

			got, ok := value.Integer()
			if !ok || got != test.want {
				t.Fatalf("Value.Integer() = (%d, %t), want (%d, true)", got, ok, test.want)
			}
		})
	}
}

func TestValueRejectsNonFiniteDouble(t *testing.T) {
	for _, input := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		input := input

		_, err := decision.NewValue(decision.ValueInput{Double: &input})
		if !errors.Is(err, decision.ErrInvalidValue) {
			t.Fatalf("NewValue(%v) error = %v, want ErrInvalidValue", input, err)
		}
	}
}

func TestValueDeeplyOwnsBytesAndStringLists(t *testing.T) {
	bytesInput := []byte("abc")
	listInput := []string{"one", "two"}

	bytesValue, err := decision.NewValue(decision.ValueInput{Bytes: bytesInput})
	if err != nil {
		t.Fatalf("NewValue(bytes) error = %v", err)
	}

	listValue, err := decision.NewValue(decision.ValueInput{Strings: listInput})
	if err != nil {
		t.Fatalf("NewValue(strings) error = %v", err)
	}

	bytesInput[0] = 'z'
	listInput[0] = "changed"

	gotBytes, ok := bytesValue.Bytes()
	if !ok || string(gotBytes) != "abc" {
		t.Fatalf("Value.Bytes() = (%q, %t), want (abc, true)", gotBytes, ok)
	}

	gotList, ok := listValue.Strings()
	if !ok || gotList[0] != "one" {
		t.Fatalf("Value.Strings() = (%v, %t), want immutable original", gotList, ok)
	}

	gotBytes[0] = 'x'
	gotList[0] = "mutated"

	againBytes, _ := bytesValue.Bytes()

	againList, _ := listValue.Strings()
	if string(againBytes) != "abc" || againList[0] != "one" {
		t.Fatal("Value accessors exposed mutable backing storage")
	}
}

func TestValuePreservesPresentEmptyStrings(t *testing.T) {
	assertPresentEmptyCollection(t, decision.ValueInput{Strings: []string{}}, func(value decision.Value) (any, bool) {
		return value.Strings()
	}, func(value any) bool {
		member, ok := value.([]string)

		return ok && member != nil && len(member) == 0
	})
}

func TestValuePreservesPresentEmptyBytes(t *testing.T) {
	assertPresentEmptyCollection(t, decision.ValueInput{Bytes: []byte{}}, func(value decision.Value) (any, bool) {
		return value.Bytes()
	}, func(value any) bool {
		member, ok := value.([]byte)

		return ok && member != nil && len(member) == 0
	})
}

// assertPresentEmptyCollection verifies constructor, typed accessor, and generic accessor presence.
func assertPresentEmptyCollection(
	t *testing.T,
	input decision.ValueInput,
	accessor func(decision.Value) (any, bool),
	valid func(any) bool,
) {
	t.Helper()

	value, err := decision.NewValue(input)
	if err != nil {
		t.Fatalf("NewValue(present empty collection) error = %v", err)
	}

	direct, ok := accessor(value)
	if !ok || !valid(direct) {
		t.Fatalf("typed accessor = %#v/%t, want present non-nil empty collection", direct, ok)
	}

	generic, ok := value.Any()
	if !ok || !valid(generic) {
		t.Fatalf("Any() = %#v/%t, want present non-nil empty collection", generic, ok)
	}
}

func TestValueMapDeeplyOwnsInputAndAccessorCopies(t *testing.T) {
	stringsValue, err := decision.NewValue(decision.ValueInput{Strings: []string{"mx01", "mx02"}})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	source := map[string]decision.Value{"hosts": stringsValue}

	values, err := decision.NewValueMap(source)
	if err != nil {
		t.Fatalf("NewValueMap() error = %v", err)
	}

	delete(source, "hosts")

	copyOne := values.Values()
	copyOne["extra"] = stringsValue

	if values.Len() != 1 {
		t.Fatalf("ValueMap.Len() = %d, want 1", values.Len())
	}

	if _, ok := values.Get("extra"); ok {
		t.Fatal("ValueMap accessor exposed mutable map storage")
	}
}
