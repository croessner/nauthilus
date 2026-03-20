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
	"sync"
)

// ExpectationQueue provides synchronized expectation ordering and consumption.
type ExpectationQueue struct {
	mu      sync.Mutex
	ordered bool
	items   []Expectation
}

// NewExpectationQueue creates an empty expectation queue.
func NewExpectationQueue() *ExpectationQueue {
	return NewExpectationQueueWithOrdering(true)
}

// NewExpectationQueueWithOrdering creates an empty expectation queue with configured ordering mode.
func NewExpectationQueueWithOrdering(ordered bool) *ExpectationQueue {
	return &ExpectationQueue{
		ordered: ordered,
		items:   make([]Expectation, 0),
	}
}

// Enqueue appends an expectation at the tail.
func (q *ExpectationQueue) Enqueue(exp Expectation) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.items = append(q.items, exp)
}

// Len returns the number of queued expectations.
func (q *ExpectationQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	return len(q.items)
}

// Peek returns the first expectation without consuming it.
func (q *ExpectationQueue) Peek() (Expectation, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return nil, ErrEmptyExpectationQueue
	}

	return q.items[0], nil
}

// Dequeue removes and returns the first expectation.
func (q *ExpectationQueue) Dequeue() (Expectation, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return nil, ErrEmptyExpectationQueue
	}

	exp := q.items[0]
	q.items = q.items[1:]

	return exp, nil
}

// MatchNext validates and consumes the next expected call.
func (q *ExpectationQueue) MatchNext(call Call) (Expectation, error) {
	q.mu.Lock()
	if len(q.items) == 0 {
		q.mu.Unlock()
		return nil, fmt.Errorf("%w: queue is empty; actual=%s", ErrUnexpectedCall, describeCall(call))
	}

	if !q.ordered {
		for index := range q.items {
			exp := q.items[index]
			if err := exp.Match(call); err != nil {
				continue
			}

			q.items = append(q.items[:index], q.items[index+1:]...)
			q.mu.Unlock()

			if err := exp.Consume(); err != nil {
				return nil, err
			}

			return exp, nil
		}

		expected := describeExpectation(q.items[0])
		q.mu.Unlock()
		return nil, fmt.Errorf("%w: expected=%s actual=%s reason=no unordered expectation matched", ErrUnexpectedCall, expected, describeCall(call))
	}

	exp := q.items[0]
	if err := exp.Match(call); err != nil {
		q.mu.Unlock()
		return nil, fmt.Errorf(
			"%w: expected=%s actual=%s reason=%s",
			ErrUnexpectedCall,
			describeExpectation(exp),
			describeCall(call),
			exp.DescribeMismatch(call),
		)
	}

	q.items = q.items[1:]
	q.mu.Unlock()

	if err := exp.Consume(); err != nil {
		return nil, err
	}

	return exp, nil
}

// Snapshot returns a shallow copy of currently queued expectations.
func (q *ExpectationQueue) Snapshot() []Expectation {
	q.mu.Lock()
	defer q.mu.Unlock()

	out := make([]Expectation, len(q.items))
	copy(out, q.items)

	return out
}
