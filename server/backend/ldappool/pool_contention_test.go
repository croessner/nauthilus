package ldappool

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

// TestBorrowSkipsLockedConnection reproduces pool-wide blocking behind one occupied slot.
func TestBorrowSkipsLockedConnection(t *testing.T) {
	setupLDAPPoolTestConfig()

	for _, available := range []bool{true, false} {
		name := "deadline_with_locked_slot"
		if available {
			name = "later_free_slot"
		}

		t.Run(name, func(t *testing.T) {
			locked := &mockLDAPConnection{state: int32(definitions.LDAPStateFree)}
			connections := []LDAPConnection{locked}

			if available {
				connections = append(connections, &mockLDAPConnection{state: int32(definitions.LDAPStateFree)})
			}

			pool := newLookupTestPool(t.Context(), definitions.LDAPPoolLookup, connections)

			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()

			locked.mutex.Lock()
			done := make(chan struct{})

			var (
				index int
				err   error
			)

			go func() {
				index, err = pool.getConnection(ctx, "contention-test")

				close(done)
			}()

			select {
			case <-done:
				locked.mutex.Unlock()
			case <-time.After(500 * time.Millisecond):
				locked.mutex.Unlock()
				<-done
				t.Fatal("borrowing blocked behind a locked slot instead of scanning or honoring cancellation")
			}

			if available {
				if err != nil || index != 1 {
					t.Fatalf("expected later free slot, got index=%d error=%v", index, err)
				}

				pool.releaseToken()
			} else if err == nil {
				t.Fatal("expected the request deadline to abort borrowing")
			}

			if len(pool.tokens) != len(connections) {
				t.Fatal("borrowing leaked a pool capacity token")
			}
		})
	}
}
