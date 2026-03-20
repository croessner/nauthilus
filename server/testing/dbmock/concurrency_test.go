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
	"sync"
	"testing"
)

func TestConcurrentExecUnordered(t *testing.T) {
	t.Parallel()

	mock := New(WithUnorderedExpectations())
	conn := mock.Conn()

	const calls = 16

	for i := range calls {
		mock.ExpectExec("UPDATE users SET enabled = ? WHERE id = ?", true, i).WillReturnResult(1, 0)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, calls)

	for i := range calls {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, err := conn.Exec("UPDATE users SET enabled = ? WHERE id = ?", true, id)
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent exec returned error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expected all concurrent expectations met, got: %v", err)
	}
}

func TestConcurrentQueueEnqueue(t *testing.T) {
	t.Parallel()

	queue := NewExpectationQueueWithOrdering(true)
	const total = 32

	var wg sync.WaitGroup
	for i := range total {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			queue.Enqueue(NewExecExpectation("SELECT ?", id))
		}(i)
	}

	wg.Wait()

	if queue.Len() != total {
		t.Fatalf("expected queue length %d, got %d", total, queue.Len())
	}
}
