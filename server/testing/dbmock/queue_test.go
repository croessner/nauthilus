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
	"strings"
	"testing"
)

func TestExpectationQueueEnqueuePeekDequeue(t *testing.T) {
	queue := NewExpectationQueue()
	exp := NewExecExpectation("SELECT 1")
	queue.Enqueue(exp)

	if queue.Len() != 1 {
		t.Fatalf("expected len=1, got %d", queue.Len())
	}

	peeked, err := queue.Peek()
	if err != nil {
		t.Fatalf("peek returned error: %v", err)
	}
	if peeked != exp {
		t.Fatalf("peeked expectation mismatch")
	}

	dequeued, err := queue.Dequeue()
	if err != nil {
		t.Fatalf("dequeue returned error: %v", err)
	}
	if dequeued != exp {
		t.Fatalf("dequeued expectation mismatch")
	}

	if queue.Len() != 0 {
		t.Fatalf("expected len=0, got %d", queue.Len())
	}
}

func TestExpectationQueueEmpty(t *testing.T) {
	queue := NewExpectationQueue()

	_, err := queue.Peek()
	if !errors.Is(err, ErrEmptyExpectationQueue) {
		t.Fatalf("expected ErrEmptyExpectationQueue from Peek, got: %v", err)
	}

	_, err = queue.Dequeue()
	if !errors.Is(err, ErrEmptyExpectationQueue) {
		t.Fatalf("expected ErrEmptyExpectationQueue from Dequeue, got: %v", err)
	}
}

func TestExpectationQueueMatchNextSuccess(t *testing.T) {
	queue := NewExpectationQueue()
	exp := NewExecExpectation("UPDATE users SET enabled = ? WHERE id = ?", true, "u-1")
	queue.Enqueue(exp)

	call := NewCall(CallExec, "update users set enabled = ? where id = ?", true, "u-1")
	matched, err := queue.MatchNext(call)
	if err != nil {
		t.Fatalf("expected match success, got error: %v", err)
	}
	if matched != exp {
		t.Fatalf("matched expectation mismatch")
	}
	if !exp.IsSatisfied() {
		t.Fatalf("expected expectation to be satisfied")
	}
	if queue.Len() != 0 {
		t.Fatalf("expected len=0 after consume, got %d", queue.Len())
	}
}

func TestExpectationQueueMatchNextMismatchKeepsQueue(t *testing.T) {
	queue := NewExpectationQueue()
	exp := NewExecExpectation("SELECT 1")
	queue.Enqueue(exp)

	_, err := queue.MatchNext(NewCall(CallExec, "SELECT 2"))
	if !errors.Is(err, ErrUnexpectedCall) {
		t.Fatalf("expected ErrUnexpectedCall, got: %v", err)
	}
	if !strings.Contains(err.Error(), "expected=") || !strings.Contains(err.Error(), "actual=") {
		t.Fatalf("expected mismatch details in error, got: %v", err)
	}
	if queue.Len() != 1 {
		t.Fatalf("queue should keep expectation on mismatch")
	}
	if exp.IsSatisfied() {
		t.Fatalf("expectation must not be satisfied on mismatch")
	}
}
