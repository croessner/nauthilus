package opsfx

import (
	"context"
	"testing"
	"time"
)

func TestGate_WithLockSerializes(t *testing.T) {
	gate := NewGate()

	enteredFirst := make(chan struct{})
	releaseFirst := make(chan struct{})
	enteredSecond := make(chan struct{})

	go func() {
		_ = gate.WithLock(func() error {
			close(enteredFirst)
			<-releaseFirst
			return nil
		})
	}()

	select {
	case <-enteredFirst:
	case <-time.After(2 * time.Second):
		t.Fatal("first lock did not enter")
	}

	go func() {
		_ = gate.WithLock(func() error {
			close(enteredSecond)
			return nil
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	select {
	case <-enteredSecond:
		t.Fatal("second lock entered while first lock was held")
	case <-ctx.Done():
		// ok
	}

	close(releaseFirst)

	select {
	case <-enteredSecond:
	case <-time.After(2 * time.Second):
		t.Fatal("second lock did not enter after first lock was released")
	}
}
