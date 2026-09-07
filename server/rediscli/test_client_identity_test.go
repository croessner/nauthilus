package rediscli

import (
	"sync"
	"testing"

	"github.com/redis/go-redis/v9"
)

// TestConcurrentTestClientConstructionPreservesIdentity verifies that publication cannot replace a constructor's result.
func TestConcurrentTestClientConstructionPreservesIdentity(t *testing.T) {
	const (
		workers  = 32
		attempts = 128
	)

	start := make(chan struct{})

	var group sync.WaitGroup

	for range workers {
		group.Go(func() {
			db := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
			defer func() { _ = db.Close() }()

			<-start

			for range attempts {
				if actual := NewTestClient(db); actual.GetWriteHandle() != db {
					t.Error("constructor returned another caller's Redis handle")

					return
				}
			}
		})
	}

	close(start)
	group.Wait()
}
