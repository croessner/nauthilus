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
