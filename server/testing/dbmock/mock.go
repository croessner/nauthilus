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
	"strings"
	"sync"
)

// Mock coordinates expectations and captured calls.
type Mock struct {
	mu      sync.Mutex
	queue   *ExpectationQueue
	history []Call
}

type options struct {
	ordered bool
}

// Option configures mock behavior.
type Option func(*options)

// Conn executes DB operations against mock expectations.
type Conn struct {
	mock *Mock
}

// Tx executes transaction lifecycle operations against mock expectations.
type Tx struct {
	mu   sync.Mutex
	mock *Mock
	done bool
}

// Stmt executes prepared statement operations against mock expectations.
type Stmt struct {
	mu                       sync.Mutex
	mock                     *Mock
	query                    string
	closed                   bool
	validatePlaceholderCount bool
	expectedPlaceholderCount int
}

// WithUnorderedExpectations enables matching calls in any order.
func WithUnorderedExpectations() Option {
	return func(cfg *options) {
		cfg.ordered = false
	}
}

// New creates a fresh mock instance.
func New(opts ...Option) *Mock {
	config := options{
		ordered: true,
	}

	for _, opt := range opts {
		opt(&config)
	}

	return &Mock{
		queue:   NewExpectationQueueWithOrdering(config.ordered),
		history: make([]Call, 0),
	}
}

// Conn returns a connection handle bound to the mock.
func (m *Mock) Conn() *Conn {
	return &Conn{mock: m}
}

// ExpectExec appends an exec expectation.
func (m *Mock) ExpectExec(query string, args ...any) *ExecExpectation {
	exp := NewExecExpectation(query, args...)
	m.queue.Enqueue(exp)

	return exp
}

// ExpectQuery appends a query expectation.
func (m *Mock) ExpectQuery(query string, args ...any) *QueryExpectation {
	exp := NewQueryExpectation(query, args...)
	m.queue.Enqueue(exp)

	return exp
}

// ExpectPrepare appends a prepare expectation.
func (m *Mock) ExpectPrepare(query string, args ...any) *PrepareExpectation {
	exp := NewPrepareExpectation(query, args...).withQueue(m.queue)
	m.queue.Enqueue(exp)

	return exp
}

// ExpectBegin appends a begin expectation.
func (m *Mock) ExpectBegin() *TxExpectation {
	exp := NewTxExpectation(CallBegin)
	m.queue.Enqueue(exp)

	return exp
}

// ExpectCommit appends a commit expectation.
func (m *Mock) ExpectCommit() *TxExpectation {
	exp := NewTxExpectation(CallCommit)
	m.queue.Enqueue(exp)

	return exp
}

// ExpectRollback appends a rollback expectation.
func (m *Mock) ExpectRollback() *TxExpectation {
	exp := NewTxExpectation(CallRollback)
	m.queue.Enqueue(exp)

	return exp
}

// ExpectationsWereMet fails if queued expectations remain unmatched.
func (m *Mock) ExpectationsWereMet() error {
	remaining := m.queue.Snapshot()
	if len(remaining) == 0 {
		return nil
	}

	calls := m.Calls()
	descriptions := make([]string, 0, len(remaining))
	for i, exp := range remaining {
		descriptions = append(descriptions, fmt.Sprintf("#%d %s", i+1, describeExpectation(exp)))
	}

	lastCall := "<none>"
	if len(calls) > 0 {
		lastCall = describeCall(calls[len(calls)-1])
	}

	return fmt.Errorf(
		"%d expectation(s) not met after %d matched call(s); pending=[%s]; last_call=%s",
		len(remaining),
		len(calls),
		strings.Join(descriptions, "; "),
		lastCall,
	)
}

// Calls returns a copied history of successfully matched calls.
func (m *Mock) Calls() []Call {
	m.mu.Lock()
	defer m.mu.Unlock()

	calls := make([]Call, len(m.history))
	copy(calls, m.history)

	return calls
}

// Exec matches and executes the next expected exec call.
func (c *Conn) Exec(query string, args ...any) (ExecResult, error) {
	return c.mock.execCall(NewCall(CallExec, query, args...))
}

// Query matches and executes the next expected query call.
func (c *Conn) Query(query string, args ...any) (Rows, error) {
	return c.mock.queryCall(NewCall(CallQuery, query, args...))
}

// Prepare matches the next prepare expectation and returns a statement handle.
func (c *Conn) Prepare(query string, args ...any) (*Stmt, error) {
	call := NewCall(CallPrepare, query, args...)
	exp, err := c.mock.matchAndRecord(call)
	if err != nil {
		return nil, err
	}

	prepareExp, ok := exp.(*PrepareExpectation)
	if !ok {
		return nil, fmt.Errorf("%w: expected prepare expectation", ErrUnexpectedCall)
	}

	if prepareExp.err != nil {
		return nil, prepareExp.err
	}

	stmt := &Stmt{
		mock:                     c.mock,
		query:                    prepareExp.queryText(),
		closed:                   false,
		validatePlaceholderCount: prepareExp.placeholderValidationEnabled(),
		expectedPlaceholderCount: countPlaceholders(prepareExp.queryText()),
	}

	return stmt, nil
}

// Begin matches the next begin expectation and returns a transaction handle.
func (c *Conn) Begin() (*Tx, error) {
	exp, err := c.mock.matchAndRecord(NewCall(CallBegin, ""))
	if err != nil {
		return nil, err
	}

	txExp, ok := exp.(*TxExpectation)
	if !ok {
		return nil, fmt.Errorf("%w: expected begin expectation", ErrUnexpectedCall)
	}

	if txExp.err != nil {
		return nil, txExp.err
	}

	return &Tx{
		mock: c.mock,
		done: false,
	}, nil
}

// Exec matches and executes a prepared statement exec call.
func (s *Stmt) Exec(args ...any) (ExecResult, error) {
	if err := s.ensureOpen(); err != nil {
		return ExecResult{}, err
	}

	if err := s.validateArgCount(args); err != nil {
		return ExecResult{}, err
	}

	return s.mock.execCall(NewPreparedCall(CallExec, s.query, args...))
}

// Query matches and executes a prepared statement query call.
func (s *Stmt) Query(args ...any) (Rows, error) {
	if err := s.ensureOpen(); err != nil {
		return Rows{}, err
	}

	if err := s.validateArgCount(args); err != nil {
		return Rows{}, err
	}

	return s.mock.queryCall(NewPreparedCall(CallQuery, s.query, args...))
}

// Close marks the statement as unusable.
func (s *Stmt) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
}

// Commit matches and executes a commit call for the active transaction.
func (tx *Tx) Commit() error {
	if err := tx.ensureActive(); err != nil {
		return err
	}

	exp, err := tx.mock.matchAndRecord(NewCall(CallCommit, ""))
	if err != nil {
		return err
	}

	txExp, ok := exp.(*TxExpectation)
	if !ok {
		return fmt.Errorf("%w: expected commit expectation", ErrUnexpectedCall)
	}

	tx.markDone()

	return txExp.err
}

// Rollback matches and executes a rollback call for the active transaction.
func (tx *Tx) Rollback() error {
	if err := tx.ensureActive(); err != nil {
		return err
	}

	exp, err := tx.mock.matchAndRecord(NewCall(CallRollback, ""))
	if err != nil {
		return err
	}

	txExp, ok := exp.(*TxExpectation)
	if !ok {
		return fmt.Errorf("%w: expected rollback expectation", ErrUnexpectedCall)
	}

	tx.markDone()

	return txExp.err
}

// Exec matches and executes an exec call inside the active transaction.
func (tx *Tx) Exec(query string, args ...any) (ExecResult, error) {
	if err := tx.ensureActive(); err != nil {
		return ExecResult{}, err
	}

	return tx.mock.execCall(NewCall(CallExec, query, args...))
}

// Query matches and executes a query call inside the active transaction.
func (tx *Tx) Query(query string, args ...any) (Rows, error) {
	if err := tx.ensureActive(); err != nil {
		return Rows{}, err
	}

	return tx.mock.queryCall(NewCall(CallQuery, query, args...))
}

func (s *Stmt) ensureOpen() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStatementClosed
	}

	return nil
}

func (s *Stmt) validateArgCount(args []any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.validatePlaceholderCount {
		return nil
	}

	actualCount := len(args)
	if actualCount != s.expectedPlaceholderCount {
		return fmt.Errorf("%w: expected %d, got %d", ErrPlaceholderCountMismatch, s.expectedPlaceholderCount, actualCount)
	}

	return nil
}

func (tx *Tx) ensureActive() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.done {
		return ErrTransactionDone
	}

	return nil
}

func (tx *Tx) markDone() {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	tx.done = true
}

func (m *Mock) execCall(call Call) (ExecResult, error) {
	exp, err := m.matchAndRecord(call)
	if err != nil {
		return ExecResult{}, err
	}

	execExp, ok := exp.(*ExecExpectation)
	if !ok {
		return ExecResult{}, fmt.Errorf("%w: expected exec expectation", ErrUnexpectedCall)
	}

	return execExp.resultOrZero()
}

func (m *Mock) queryCall(call Call) (Rows, error) {
	exp, err := m.matchAndRecord(call)
	if err != nil {
		return Rows{}, err
	}

	queryExp, ok := exp.(*QueryExpectation)
	if !ok {
		return Rows{}, fmt.Errorf("%w: expected query expectation", ErrUnexpectedCall)
	}

	return queryExp.rowsOrZero()
}

func (m *Mock) matchAndRecord(call Call) (Expectation, error) {
	exp, err := m.queue.MatchNext(call)
	if err != nil {
		return nil, err
	}

	m.recordCall(call)

	return exp, nil
}

func (m *Mock) recordCall(call Call) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.history = append(m.history, call)
}
