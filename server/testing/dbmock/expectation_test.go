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
	"errors"
	"testing"
)

func TestExecExpectationMatchSuccess(t *testing.T) {
	exp := NewExecExpectation("SELECT id FROM users WHERE email = ?", "a@example.org")
	call := NewCall(CallExec, " select   id  from USERS where email = ? ", "a@example.org")

	if err := exp.Match(call); err != nil {
		t.Fatalf("expected match success, got error: %v", err)
	}
}

func TestExecExpectationKindMismatch(t *testing.T) {
	exp := NewExecExpectation("SELECT 1")
	call := NewCall(CallQuery, "SELECT 1")

	err := exp.Match(call)
	if !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("expected ErrKindMismatch, got: %v", err)
	}
}

func TestExecExpectationSQLMismatch(t *testing.T) {
	exp := NewExecExpectation("SELECT 1")
	call := NewCall(CallExec, "SELECT 2")

	err := exp.Match(call)
	if !errors.Is(err, ErrSQLMismatch) {
		t.Fatalf("expected ErrSQLMismatch, got: %v", err)
	}
}

func TestExecExpectationArgCountMismatch(t *testing.T) {
	exp := NewExecExpectation("SELECT 1", 1, 2)
	call := NewCall(CallExec, "SELECT 1", 1)

	err := exp.Match(call)
	if !errors.Is(err, ErrArgCountMismatch) {
		t.Fatalf("expected ErrArgCountMismatch, got: %v", err)
	}
}

func TestExecExpectationArgMismatch(t *testing.T) {
	exp := NewExecExpectation("SELECT 1", 1)
	call := NewCall(CallExec, "SELECT 1", 2)

	err := exp.Match(call)
	if !errors.Is(err, ErrArgMismatch) {
		t.Fatalf("expected ErrArgMismatch, got: %v", err)
	}
}

func TestExecExpectationArgMatcher(t *testing.T) {
	exp := NewExecExpectation("SELECT 1", AnyArg(), Eq("expected"))
	call := NewCall(CallExec, "SELECT 1", 42, "expected")

	if err := exp.Match(call); err != nil {
		t.Fatalf("expected arg matcher success, got error: %v", err)
	}
}

func TestExecExpectationTypeOfMatcher(t *testing.T) {
	exp := NewExecExpectation("SELECT 1", TypeOf(int64(0)))
	call := NewCall(CallExec, "SELECT 1", int64(7))

	if err := exp.Match(call); err != nil {
		t.Fatalf("expected TypeOf matcher success, got error: %v", err)
	}
}

func TestExecExpectationPredicateMatcher(t *testing.T) {
	exp := NewExecExpectation("SELECT 1", Predicate("positive-number", func(v any) bool {
		number, ok := v.(float64)
		if !ok {
			return false
		}

		return number > 0
	}))
	call := NewCall(CallExec, "SELECT 1", float64(1))

	if err := exp.Match(call); err != nil {
		t.Fatalf("expected Predicate matcher success, got error: %v", err)
	}
}

func TestExpectationConsumeTwice(t *testing.T) {
	exp := NewQueryExpectation("SELECT 1")

	if err := exp.Consume(); err != nil {
		t.Fatalf("first consume must succeed, got: %v", err)
	}

	err := exp.Consume()
	if !errors.Is(err, ErrExpectationAlreadyConsumed) {
		t.Fatalf("expected ErrExpectationAlreadyConsumed, got: %v", err)
	}
}

func TestTxExpectation(t *testing.T) {
	exp := NewTxExpectation(CallBegin)
	call := NewCall(CallBegin, "")

	if err := exp.Match(call); err != nil {
		t.Fatalf("expected tx match success, got error: %v", err)
	}
}

func TestPreparedModeMismatch(t *testing.T) {
	exp := newExecExpectation("SELECT 1", true)
	call := NewCall(CallExec, "SELECT 1")

	err := exp.Match(call)
	if !errors.Is(err, ErrPreparedModeMismatch) {
		t.Fatalf("expected ErrPreparedModeMismatch, got: %v", err)
	}
}
