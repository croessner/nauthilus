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
	"strings"
	"sync"
)

// Expectation defines matching and lifecycle behavior for one expected DB call.
type Expectation interface {
	Kind() CallKind
	Match(call Call) error
	Consume() error
	IsSatisfied() bool
	DescribeMismatch(call Call) string
}

type baseExpectation struct {
	mu       sync.Mutex
	kind     CallKind
	query    string
	args     []any
	prepared bool
	consumed bool
	err      error
}

func (b *baseExpectation) Kind() CallKind {
	return b.kind
}

func (b *baseExpectation) Match(call Call) error {
	if call.Kind != b.kind {
		return fmt.Errorf("%w: expected %q, got %q", ErrKindMismatch, b.kind, call.Kind)
	}

	if b.prepared != call.Prepared {
		return fmt.Errorf("%w: expected %t, got %t", ErrPreparedModeMismatch, b.prepared, call.Prepared)
	}

	if b.requiresQueryMatch() {
		expected := normalizeSQL(b.query)
		actual := normalizeSQL(call.Query)
		if actual != expected {
			return fmt.Errorf("%w: expected %q, got %q", ErrSQLMismatch, expected, actual)
		}
	}

	if len(call.Args) != len(b.args) {
		return fmt.Errorf("%w: expected %d, got %d", ErrArgCountMismatch, len(b.args), len(call.Args))
	}

	for i := range b.args {
		if matcher, ok := b.args[i].(ArgMatcher); ok {
			if !matcher.Match(call.Args[i]) {
				return fmt.Errorf("%w at index %d: matcher %s did not match value %#v", ErrArgMismatch, i, matcher.Describe(), call.Args[i])
			}
			continue
		}

		if !reflect.DeepEqual(call.Args[i], b.args[i]) {
			return fmt.Errorf("%w at index %d: expected %#v, got %#v", ErrArgMismatch, i, b.args[i], call.Args[i])
		}
	}

	return nil
}

func (b *baseExpectation) Consume() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.consumed {
		return ErrExpectationAlreadyConsumed
	}

	b.consumed = true

	return nil
}

func (b *baseExpectation) IsSatisfied() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.consumed
}

func (b *baseExpectation) DescribeMismatch(call Call) string {
	if err := b.Match(call); err != nil {
		return err.Error()
	}

	return ""
}

func (b *baseExpectation) requiresQueryMatch() bool {
	switch b.kind {
	case CallExec, CallQuery, CallPrepare:
		return true
	default:
		return false
	}
}

// ExecExpectation matches an exec call.
type ExecExpectation struct {
	baseExpectation
	result ExecResult
}

// NewExecExpectation creates an exec expectation.
func NewExecExpectation(query string, args ...any) *ExecExpectation {
	return newExecExpectation(query, false, args...)
}

func newExecExpectation(query string, prepared bool, args ...any) *ExecExpectation {
	return &ExecExpectation{
		baseExpectation: newBaseExpectation(CallExec, query, prepared, args...),
	}
}

// WillReturnResult configures the result returned by a matched exec call.
func (e *ExecExpectation) WillReturnResult(rowsAffected, lastInsertID int64) *ExecExpectation {
	e.result = ExecResult{
		RowsAffected: rowsAffected,
		LastInsertID: lastInsertID,
	}

	return e
}

// WillReturnError configures the error returned by a matched exec call.
func (e *ExecExpectation) WillReturnError(err error) *ExecExpectation {
	e.err = err

	return e
}

func (e *ExecExpectation) resultOrZero() (ExecResult, error) {
	return e.result, e.err
}

// QueryExpectation matches a query call.
type QueryExpectation struct {
	baseExpectation
	rows Rows
}

// NewQueryExpectation creates a query expectation.
func NewQueryExpectation(query string, args ...any) *QueryExpectation {
	return newQueryExpectation(query, false, args...)
}

func newQueryExpectation(query string, prepared bool, args ...any) *QueryExpectation {
	return &QueryExpectation{
		baseExpectation: newBaseExpectation(CallQuery, query, prepared, args...),
	}
}

// WillReturnRows configures rows returned by a matched query call.
func (e *QueryExpectation) WillReturnRows(rows Rows) *QueryExpectation {
	e.rows = rows.Clone()

	return e
}

// WillReturnError configures the error returned by a matched query call.
func (e *QueryExpectation) WillReturnError(err error) *QueryExpectation {
	e.err = err

	return e
}

func (e *QueryExpectation) rowsOrZero() (Rows, error) {
	return e.rows.Clone(), e.err
}

// PrepareExpectation matches a prepare call.
type PrepareExpectation struct {
	baseExpectation
	queue                    *ExpectationQueue
	validatePlaceholderCount bool
}

// NewPrepareExpectation creates a prepare expectation.
func NewPrepareExpectation(query string, args ...any) *PrepareExpectation {
	return &PrepareExpectation{
		baseExpectation:          newBaseExpectation(CallPrepare, query, false, args...),
		validatePlaceholderCount: false,
	}
}

func (e *PrepareExpectation) withQueue(queue *ExpectationQueue) *PrepareExpectation {
	e.queue = queue

	return e
}

// ValidatePlaceholderCount enables placeholder-count checks for prepared stmt exec/query calls.
func (e *PrepareExpectation) ValidatePlaceholderCount() *PrepareExpectation {
	e.validatePlaceholderCount = true

	return e
}

// ExpectExec chains an expected prepared statement exec call.
func (e *PrepareExpectation) ExpectExec(args ...any) *ExecExpectation {
	exp := newExecExpectation(e.query, true, args...)
	e.enqueueChained(exp)

	return exp
}

// ExpectQuery chains an expected prepared statement query call.
func (e *PrepareExpectation) ExpectQuery(args ...any) *QueryExpectation {
	exp := newQueryExpectation(e.query, true, args...)
	e.enqueueChained(exp)

	return exp
}

func (e *PrepareExpectation) enqueueChained(exp Expectation) {
	if e.queue == nil {
		panic("dbmock: chained expectations require PrepareExpectation from Mock.ExpectPrepare")
	}

	e.queue.Enqueue(exp)
}

// WillReturnError configures the error returned by a matched prepare call.
func (e *PrepareExpectation) WillReturnError(err error) *PrepareExpectation {
	e.err = err

	return e
}

func (e *PrepareExpectation) queryText() string {
	return e.query
}

func (e *PrepareExpectation) placeholderValidationEnabled() bool {
	return e.validatePlaceholderCount
}

// TxExpectation matches a transaction lifecycle call.
type TxExpectation struct {
	baseExpectation
}

// NewTxExpectation creates a transaction expectation (begin, commit, rollback).
func NewTxExpectation(kind CallKind) *TxExpectation {
	return &TxExpectation{
		baseExpectation: newBaseExpectation(kind, "", false),
	}
}

// WillReturnError configures the error returned by a matched tx call.
func (e *TxExpectation) WillReturnError(err error) *TxExpectation {
	e.err = err

	return e
}

func newBaseExpectation(kind CallKind, query string, prepared bool, args ...any) baseExpectation {
	copiedArgs := make([]any, len(args))
	copy(copiedArgs, args)

	return baseExpectation{
		kind:     kind,
		query:    query,
		args:     copiedArgs,
		prepared: prepared,
	}
}

func normalizeSQL(in string) string {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(in)))
	return strings.Join(fields, " ")
}
