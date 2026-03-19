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

package dbmock

import (
	"fmt"
	"reflect"
)

// ArgMatcher defines argument matching behavior for expectations.
type ArgMatcher interface {
	Match(value any) bool
	Describe() string
}

type anyArgMatcher struct{}

func (m anyArgMatcher) Match(_ any) bool {
	return true
}

func (m anyArgMatcher) Describe() string {
	return "any"
}

type eqArgMatcher struct {
	expected any
}

func (m eqArgMatcher) Match(value any) bool {
	return reflect.DeepEqual(m.expected, value)
}

func (m eqArgMatcher) Describe() string {
	return fmt.Sprintf("eq(%#v)", m.expected)
}

type typeOfArgMatcher struct {
	expectedType reflect.Type
}

func (m typeOfArgMatcher) Match(value any) bool {
	if value == nil {
		return false
	}

	return reflect.TypeOf(value) == m.expectedType
}

func (m typeOfArgMatcher) Describe() string {
	return fmt.Sprintf("type_of(%s)", m.expectedType.String())
}

type predicateArgMatcher struct {
	name      string
	predicate func(any) bool
}

func (m predicateArgMatcher) Match(value any) bool {
	return m.predicate(value)
}

func (m predicateArgMatcher) Describe() string {
	if m.name != "" {
		return fmt.Sprintf("predicate(%s)", m.name)
	}

	return "predicate(<anonymous>)"
}

// AnyArg matches any value at the corresponding argument position.
func AnyArg() ArgMatcher {
	return anyArgMatcher{}
}

// Eq matches exactly one expected value.
func Eq(expected any) ArgMatcher {
	return eqArgMatcher{expected: expected}
}

// TypeOf matches arguments of the same dynamic type as sample.
func TypeOf(sample any) ArgMatcher {
	return typeOfArgMatcher{
		expectedType: reflect.TypeOf(sample),
	}
}

// Predicate matches arguments for which predicate(value) returns true.
func Predicate(name string, predicate func(any) bool) ArgMatcher {
	if predicate == nil {
		panic("dbmock: predicate matcher requires a non-nil function")
	}

	return predicateArgMatcher{
		name:      name,
		predicate: predicate,
	}
}
