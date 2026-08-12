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

package decision

import (
	"math"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"
)

const maximumValueMapKeyLength = 128

// ValueKind identifies one exact strict value member.
type ValueKind string

const (
	// ValueKindString identifies a UTF-8 string.
	ValueKindString ValueKind = "string"

	// ValueKindBoolean identifies a boolean.
	ValueKindBoolean ValueKind = "boolean"

	// ValueKindInteger identifies a signed 64-bit integer.
	ValueKindInteger ValueKind = "integer"

	// ValueKindDouble identifies a finite IEEE-754 double.
	ValueKindDouble ValueKind = "double"

	// ValueKindStrings identifies an ordered UTF-8 string list.
	ValueKindStrings ValueKind = "strings"

	// ValueKindBytes identifies an owned byte sequence.
	ValueKindBytes ValueKind = "bytes"

	// ValueKindTimestamp identifies an instant normalized to UTC.
	ValueKindTimestamp ValueKind = "timestamp"
)

// IsValid reports whether the kind is a closed contract member.
func (k ValueKind) IsValid() bool {
	switch k {
	case ValueKindString,
		ValueKindBoolean,
		ValueKindInteger,
		ValueKindDouble,
		ValueKindStrings,
		ValueKindBytes,
		ValueKindTimestamp:
		return true
	default:
		return false
	}
}

// ValueInput is the constructor input for one strict value.
type ValueInput struct {
	String    *string
	Boolean   *bool
	Integer   *int64
	Double    *float64
	Timestamp *time.Time
	Strings   []string
	Bytes     []byte
}

// Value is a deeply owned strict one-of policy value.
type Value struct {
	stringValue string
	strings     []string
	bytes       []byte
	timestamp   time.Time
	kind        ValueKind
	integer     int64
	double      float64
	boolean     bool
}

// NewValue requires exactly one valid member and takes ownership by copying it.
func NewValue(input ValueInput) (Value, error) {
	if activeValueMembers(input) != 1 {
		return Value{}, invalidValue("value", "must contain exactly one active kind")
	}

	switch {
	case input.String != nil:
		return newStringValue(*input.String)
	case input.Boolean != nil:
		return Value{kind: ValueKindBoolean, boolean: *input.Boolean}, nil
	case input.Integer != nil:
		return Value{kind: ValueKindInteger, integer: *input.Integer}, nil
	case input.Double != nil:
		return newDoubleValue(*input.Double)
	case input.Strings != nil:
		return newStringsValue(input.Strings)
	case input.Bytes != nil:
		return Value{kind: ValueKindBytes, bytes: append([]byte(nil), input.Bytes...)}, nil
	case input.Timestamp != nil:
		return Value{kind: ValueKindTimestamp, timestamp: input.Timestamp.Round(0).UTC()}, nil
	default:
		return Value{}, invalidValue("value", "must contain exactly one active kind")
	}
}

// ParseIntegerValue range-checks a base-10 signed 64-bit integer.
func ParseIntegerValue(input string) (Value, error) {
	parsed, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return Value{}, invalidValue("value.integer", "must be a signed 64-bit base-10 integer")
	}

	return Value{kind: ValueKindInteger, integer: parsed}, nil
}

// Kind returns the active value kind.
func (v Value) Kind() ValueKind {
	return v.kind
}

// StringValue returns the string member when active.
func (v Value) StringValue() (string, bool) {
	return v.stringValue, v.kind == ValueKindString
}

// Boolean returns the boolean member when active.
func (v Value) Boolean() (bool, bool) {
	return v.boolean, v.kind == ValueKindBoolean
}

// Integer returns the signed integer member when active.
func (v Value) Integer() (int64, bool) {
	return v.integer, v.kind == ValueKindInteger
}

// Double returns the finite double member when active.
func (v Value) Double() (float64, bool) {
	return v.double, v.kind == ValueKindDouble
}

// Strings returns an owned copy of the string-list member when active.
func (v Value) Strings() ([]string, bool) {
	if v.kind != ValueKindStrings {
		return nil, false
	}

	return append([]string(nil), v.strings...), true
}

// Bytes returns an owned copy of the bytes member when active.
func (v Value) Bytes() ([]byte, bool) {
	if v.kind != ValueKindBytes {
		return nil, false
	}

	return append([]byte(nil), v.bytes...), true
}

// Timestamp returns the UTC-normalized timestamp member when active.
func (v Value) Timestamp() (time.Time, bool) {
	return v.timestamp, v.kind == ValueKindTimestamp
}

// valid reports whether a value satisfies its constructor invariant.
func (v Value) valid() bool {
	switch v.kind {
	case ValueKindString:
		return utf8.ValidString(v.stringValue)
	case ValueKindBoolean, ValueKindInteger:
		return true
	case ValueKindDouble:
		return !math.IsNaN(v.double) && !math.IsInf(v.double, 0)
	case ValueKindStrings:
		return validUTF8Strings(v.strings)
	case ValueKindBytes, ValueKindTimestamp:
		return true
	default:
		return false
	}
}

// ValueMap is an immutable map of strict values.
type ValueMap struct {
	values map[string]Value
}

// NewValueMap validates keys and deeply owns the map structure.
func NewValueMap(input map[string]Value) (ValueMap, error) {
	values := make(map[string]Value, len(input))
	keys := make([]string, 0, len(input))

	for key := range input {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		value := input[key]
		if !validValueMapKey(key) {
			return ValueMap{}, invalidValue(key, "map key must be non-empty valid UTF-8")
		}

		if !value.valid() {
			return ValueMap{}, invalidValue(key, "map member is not a constructed strict value")
		}

		values[key] = value
	}

	return ValueMap{values: values}, nil
}

// Len returns the number of map entries.
func (m ValueMap) Len() int {
	return len(m.values)
}

// Get returns one immutable value by key.
func (m ValueMap) Get(key string) (Value, bool) {
	value, ok := m.values[key]

	return value, ok
}

// Values returns a detached map copy.
func (m ValueMap) Values() map[string]Value {
	values := make(map[string]Value, len(m.values))
	for key, value := range m.values {
		values[key] = value
	}

	return values
}

// activeValueMembers counts populated one-of members without conflating empty and absent lists.
func activeValueMembers(input ValueInput) int {
	count := 0

	for _, active := range []bool{
		input.String != nil,
		input.Boolean != nil,
		input.Integer != nil,
		input.Double != nil,
		input.Strings != nil,
		input.Bytes != nil,
		input.Timestamp != nil,
	} {
		if active {
			count++
		}
	}

	return count
}

// newStringValue validates UTF-8 text before construction.
func newStringValue(input string) (Value, error) {
	if !utf8.ValidString(input) {
		return Value{}, invalidValue("value.string", "must contain valid UTF-8")
	}

	return Value{kind: ValueKindString, stringValue: input}, nil
}

// newDoubleValue rejects non-finite numeric values.
func newDoubleValue(input float64) (Value, error) {
	if math.IsNaN(input) || math.IsInf(input, 0) {
		return Value{}, invalidValue("value.double", "must be finite")
	}

	return Value{kind: ValueKindDouble, double: input}, nil
}

// newStringsValue validates and copies an ordered string list.
func newStringsValue(input []string) (Value, error) {
	if !validUTF8Strings(input) {
		return Value{}, invalidValue("value.strings", "all members must contain valid UTF-8")
	}

	return Value{kind: ValueKindStrings, strings: append([]string(nil), input...)}, nil
}

// validUTF8Strings validates every string-list member.
func validUTF8Strings(input []string) bool {
	for _, value := range input {
		if !utf8.ValidString(value) {
			return false
		}
	}

	return true
}

// validValueMapKey validates bounded map keys without assigning domain schema semantics.
func validValueMapKey(input string) bool {
	return input != "" && len(input) <= maximumValueMapKeyLength && utf8.ValidString(input)
}

// invalidValue constructs a strict-value taxonomy error.
func invalidValue(field string, reason string) error {
	return newContractError(ErrInvalidValue, ErrorCodeInvalidValue, field, reason)
}
