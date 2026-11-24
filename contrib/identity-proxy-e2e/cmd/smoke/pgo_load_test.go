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

package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPGOLoadEndsCleanlyAtTheDeadline pins that a request cut short by the workload deadline is no failure, that every
// worker rotates through all operations, and that completed requests are counted.
func TestPGOLoadEndsCleanlyAtTheDeadline(t *testing.T) {
	load := &pgoLoad{runner: &runner{opts: options{loadWorkers: 4}}}
	seen := make(map[string]struct{})

	var mu sync.Mutex

	operation := func(name string) pgoLoadOperation {
		return func(ctx context.Context, account string) error {
			if !strings.HasSuffix(account, "@example.test") {
				return errors.New("unexpected account " + account)
			}

			mu.Lock()
			seen[name] = struct{}{}
			mu.Unlock()

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Millisecond):
				return nil
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := load.run(ctx, []pgoLoadOperation{operation("edge"), operation("authenticate"), operation("lookup")}); err != nil {
		t.Fatalf("deadline reported as failure: %v", err)
	}

	if load.requests.Load() == 0 || len(seen) != 3 {
		t.Fatalf("requests=%d operations=%v", load.requests.Load(), seen)
	}
}

// TestPGOLoadReportsTheFirstFailure pins that a failing request ends the workload with its error, so a profile of an
// error path is never published.
func TestPGOLoadReportsTheFirstFailure(t *testing.T) {
	load := &pgoLoad{runner: &runner{opts: options{loadWorkers: 4}}}
	refused := errors.New("edge JSON authentication: status=401")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := load.run(ctx, []pgoLoadOperation{func(context.Context, string) error { return refused }})
	if !errors.Is(err, refused) {
		t.Fatalf("error=%v, want %v", err, refused)
	}
}

// lateTimerContext models a context whose deadline has passed while its timer has not fired yet: Deadline is in the
// past, but Err is still nil and Done is still open. On a loaded host a gRPC status can arrive in that window.
type lateTimerContext struct {
	context.Context
	deadline time.Time
}

// Deadline reports the passed workload deadline.
func (c lateTimerContext) Deadline() (time.Time, bool) {
	return c.deadline, true
}

// TestPGOLoadTreatsAnErrorAfterTheDeadlineAsTheEnd pins that a request failing after the workload deadline passed is
// the end of the workload, even before the context's timer has set Err. The release PGO refresh for v4.1.3 and v4.2.0
// failed on such a DeadlineExceeded status that arrived 35 s after the profiles started, exactly at the workload end.
func TestPGOLoadTreatsAnErrorAfterTheDeadlineAsTheEnd(t *testing.T) {
	load := &pgoLoad{runner: &runner{opts: options{loadWorkers: 1}}}
	ctx := lateTimerContext{Context: context.Background(), deadline: time.Now().Add(-time.Millisecond)}
	deadlineStatus := errors.New("authenticate RPC failed: rpc error: code = DeadlineExceeded")

	done := make(chan error, 1)

	go func() {
		done <- load.work(ctx, 0, []pgoLoadOperation{func(context.Context, string) error { return deadlineStatus }})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("error after the workload deadline reported as failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop after the workload deadline")
	}
}

// TestPGOLoadStillReportsAFailureBeforeTheDeadline pins that the deadline check does not hide a real failure: an error
// while the workload still has time left ends the workload with that error.
func TestPGOLoadStillReportsAFailureBeforeTheDeadline(t *testing.T) {
	load := &pgoLoad{runner: &runner{opts: options{loadWorkers: 1}}}
	ctx := lateTimerContext{Context: context.Background(), deadline: time.Now().Add(time.Hour)}
	stalled := errors.New("lookup identity RPC failed: rpc error: code = DeadlineExceeded")

	if err := load.work(ctx, 0, []pgoLoadOperation{func(context.Context, string) error { return stalled }}); !errors.Is(err, stalled) {
		t.Fatalf("error=%v, want %v", err, stalled)
	}
}
