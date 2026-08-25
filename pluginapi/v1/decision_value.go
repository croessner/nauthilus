// Copyright (C) 2026 Christian Roessner
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

package pluginapi

import (
	"fmt"
	"math"
	"time"
	"unicode/utf8"
)

// DecisionValueKind identifies one member of the closed generic policy vocabulary.
type DecisionValueKind string

const (
	// DecisionValueKindString identifies a UTF-8 string.
	DecisionValueKindString DecisionValueKind = "string"

	// DecisionValueKindBoolean identifies a boolean.
	DecisionValueKindBoolean DecisionValueKind = "boolean"

	// DecisionValueKindInteger identifies a signed 64-bit integer.
	DecisionValueKindInteger DecisionValueKind = "integer"

	// DecisionValueKindDouble identifies a finite IEEE-754 double.
	DecisionValueKindDouble DecisionValueKind = "double"

	// DecisionValueKindStrings identifies an ordered UTF-8 string list.
	DecisionValueKindStrings DecisionValueKind = "strings"

	// DecisionValueKindBytes identifies an owned byte sequence.
	DecisionValueKindBytes DecisionValueKind = "bytes"

	// DecisionValueKindTimestamp identifies an instant normalized to UTC.
	DecisionValueKindTimestamp DecisionValueKind = "timestamp"
)

// IsValid reports whether the kind belongs to the closed value vocabulary.
func (k DecisionValueKind) IsValid() bool {
	switch k {
	case DecisionValueKindString,
		DecisionValueKindBoolean,
		DecisionValueKindInteger,
		DecisionValueKindDouble,
		DecisionValueKindStrings,
		DecisionValueKindBytes,
		DecisionValueKindTimestamp:
		return true
	default:
		return false
	}
}

// DecisionValueInput carries exactly one strict value member into its constructor.
type DecisionValueInput struct {
	String    *string
	Boolean   *bool
	Integer   *int64
	Double    *float64
	Timestamp *time.Time
	Strings   []string
	Bytes     []byte
}

// DecisionValue is a deeply owned strict one-of value.
type DecisionValue struct {
	stringValue string
	strings     []string
	bytes       []byte
	timestamp   time.Time
	kind        DecisionValueKind
	integer     int64
	double      float64
	boolean     bool
}

// NewDecisionValue requires exactly one valid member and copies mutable input.
func NewDecisionValue(input DecisionValueInput) (DecisionValue, error) {
	if activeDecisionValueMembers(input) != 1 {
		return DecisionValue{}, invalidDecisionContract("value", "must contain exactly one active kind")
	}

	switch {
	case input.String != nil:
		return newDecisionStringValue(*input.String)
	case input.Boolean != nil:
		return DecisionValue{kind: DecisionValueKindBoolean, boolean: *input.Boolean}, nil
	case input.Integer != nil:
		return DecisionValue{kind: DecisionValueKindInteger, integer: *input.Integer}, nil
	case input.Double != nil:
		return newDecisionDoubleValue(*input.Double)
	case input.Strings != nil:
		return newDecisionStringsValue(input.Strings)
	case input.Bytes != nil:
		return DecisionValue{kind: DecisionValueKindBytes, bytes: append([]byte(nil), input.Bytes...)}, nil
	case input.Timestamp != nil:
		return DecisionValue{kind: DecisionValueKindTimestamp, timestamp: input.Timestamp.Round(0).UTC()}, nil
	default:
		return DecisionValue{}, invalidDecisionContract("value", "must contain exactly one active kind")
	}
}

// Kind returns the active strict value kind.
func (v DecisionValue) Kind() DecisionValueKind {
	return v.kind
}

// StringValue returns the string member when active.
func (v DecisionValue) StringValue() (string, bool) {
	return v.stringValue, v.kind == DecisionValueKindString
}

// Boolean returns the boolean member when active.
func (v DecisionValue) Boolean() (bool, bool) {
	return v.boolean, v.kind == DecisionValueKindBoolean
}

// Integer returns the signed integer member when active.
func (v DecisionValue) Integer() (int64, bool) {
	return v.integer, v.kind == DecisionValueKindInteger
}

// Double returns the finite double member when active.
func (v DecisionValue) Double() (float64, bool) {
	return v.double, v.kind == DecisionValueKindDouble
}

// Strings returns an owned copy of the string-list member when active.
func (v DecisionValue) Strings() ([]string, bool) {
	if v.kind != DecisionValueKindStrings {
		return nil, false
	}

	return append([]string(nil), v.strings...), true
}

// Bytes returns an owned copy of the bytes member when active.
func (v DecisionValue) Bytes() ([]byte, bool) {
	if v.kind != DecisionValueKindBytes {
		return nil, false
	}

	return append([]byte(nil), v.bytes...), true
}

// Timestamp returns the UTC-normalized timestamp member when active.
func (v DecisionValue) Timestamp() (time.Time, bool) {
	return v.timestamp, v.kind == DecisionValueKindTimestamp
}

// Any returns one detached member in the closed policy-value vocabulary.
func (v DecisionValue) Any() (any, bool) {
	switch v.kind {
	case DecisionValueKindString:
		return v.stringValue, true
	case DecisionValueKindBoolean:
		return v.boolean, true
	case DecisionValueKindInteger:
		return v.integer, true
	case DecisionValueKindDouble:
		return v.double, true
	case DecisionValueKindStrings:
		return append([]string(nil), v.strings...), true
	case DecisionValueKindBytes:
		return append([]byte(nil), v.bytes...), true
	case DecisionValueKindTimestamp:
		return v.timestamp, true
	default:
		return nil, false
	}
}

// valid reports whether the value satisfies its constructor invariant.
func (v DecisionValue) valid() bool {
	switch v.kind {
	case DecisionValueKindString:
		return utf8.ValidString(v.stringValue)
	case DecisionValueKindBoolean, DecisionValueKindInteger:
		return true
	case DecisionValueKindDouble:
		return !math.IsNaN(v.double) && !math.IsInf(v.double, 0)
	case DecisionValueKindStrings:
		return validDecisionUTF8Strings(v.strings)
	case DecisionValueKindBytes, DecisionValueKindTimestamp:
		return true
	default:
		return false
	}
}

// activeDecisionValueMembers counts present one-of members without conflating empty and absent slices.
func activeDecisionValueMembers(input DecisionValueInput) int {
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

// newDecisionStringValue validates UTF-8 text before construction.
func newDecisionStringValue(input string) (DecisionValue, error) {
	if !utf8.ValidString(input) {
		return DecisionValue{}, invalidDecisionContract("value.string", "must contain valid UTF-8")
	}

	return DecisionValue{kind: DecisionValueKindString, stringValue: input}, nil
}

// newDecisionDoubleValue rejects non-finite numeric values.
func newDecisionDoubleValue(input float64) (DecisionValue, error) {
	if math.IsNaN(input) || math.IsInf(input, 0) {
		return DecisionValue{}, invalidDecisionContract("value.double", "must be finite")
	}

	return DecisionValue{kind: DecisionValueKindDouble, double: input}, nil
}

// newDecisionStringsValue validates and copies an ordered string list.
func newDecisionStringsValue(input []string) (DecisionValue, error) {
	if !validDecisionUTF8Strings(input) {
		return DecisionValue{}, invalidDecisionContract("value.strings", "all members must contain valid UTF-8")
	}

	return DecisionValue{kind: DecisionValueKindStrings, strings: append([]string(nil), input...)}, nil
}

// validDecisionUTF8Strings validates every string-list member.
func validDecisionUTF8Strings(input []string) bool {
	for _, value := range input {
		if !utf8.ValidString(value) {
			return false
		}
	}

	return true
}

// invalidDecisionContract wraps one field-specific public contract failure.
func invalidDecisionContract(field string, reason string) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidDecisionContract, field, reason)
}
