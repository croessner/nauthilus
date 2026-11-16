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

package runtime

import (
	"context"
	"errors"
	"testing"
	"time"
)

// errWorkerStillInCleanup reports that disposal ran while the releasing worker was still inside its cleanup.
var errWorkerStillInCleanup = errors.New("disposal waited for the worker that released the last lease")

// workerOwnedResource models the effect supervisor: disposing it waits until the worker that runs post-action
// cleanup has returned from that cleanup.
type workerOwnedResource struct {
	countingCandidateResource
	cleanupReturned chan struct{}
}

// Dispose waits for the cleanup worker like Supervisor.Shutdown waits for its workers.
func (r *workerOwnedResource) Dispose(ctx context.Context) error {
	defer r.disposals.Add(1)

	select {
	case <-r.cleanupReturned:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
		return errWorkerStillInCleanup
	}
}

// TestGenerationPostActionCleanupDoesNotRetireOnItsWorker reproduces the effect supervisor self-deadlock: when the
// cleanup of a post action releases the last lease of a retired generation, the final retirement disposes the
// supervisor that owns the cleaning worker, and the supervisor waits for that same worker.
func TestGenerationPostActionCleanupDoesNotRetireOnItsWorker(t *testing.T) {
	resource := &workerOwnedResource{cleanupReturned: make(chan struct{})}
	work := &testGenerationExecutableWork{}
	executable := prepareRetiredGenerationPostAction(t, work, resource)

	returned := make(chan time.Duration, 1)

	go func() {
		started := time.Now()

		executable.Cleanup()

		returned <- time.Since(started)

		close(resource.cleanupReturned)
	}()

	select {
	case elapsed := <-returned:
		if elapsed > time.Second {
			t.Fatalf("post-action cleanup blocked for %s on the final generation retirement", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("post-action cleanup did not return")
	}

	waitResourceDisposals(t, &resource.countingCandidateResource, 1)

	if got := work.cleanups.Load(); got != 1 {
		t.Fatalf("underlying work cleanup count = %d, want 1", got)
	}
}
