package tolerate

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestCustomTolerationUpsert retains existing addresses when adding or replacing an entry.
func TestCustomTolerationUpsert(t *testing.T) {
	tol := &tolerateImpl{}
	tol.SetCustomToleration("192.0.2.1", 10, time.Minute)
	tol.SetCustomToleration("192.0.2.2", 20, time.Minute)
	tol.SetCustomToleration("192.0.2.1", 30, time.Hour)

	entries := tol.GetCustomTolerations()
	if len(entries) != 2 || entries[0].ToleratePercent != 30 || entries[1].IPAddress != "192.0.2.2" {
		t.Fatalf("custom tolerations lost an insertion or replacement: %+v", entries)
	}
}

// TestCustomTolerationConcurrentInserts preserves every distinct concurrent insertion.
func TestCustomTolerationConcurrentInserts(t *testing.T) {
	tol := &tolerateImpl{}

	var wg sync.WaitGroup
	for index := range 32 {
		wg.Go(func() { tol.SetCustomToleration(fmt.Sprintf("192.0.2.%d", index), 10, time.Minute) })
	}

	wg.Wait()

	if got := len(tol.GetCustomTolerations()); got != 32 {
		t.Fatalf("stored %d concurrent entries, want 32", got)
	}
}

// TestCustomTolerationReadSnapshotDoesNotChange keeps caller-owned snapshots independent of later writes.
func TestCustomTolerationReadSnapshotDoesNotChange(t *testing.T) {
	tol := &tolerateImpl{}
	tol.SetCustomToleration("192.0.2.1", 10, time.Minute)
	snapshot := tol.GetCustomTolerations()
	tol.SetCustomToleration("192.0.2.1", 20, time.Minute)

	if snapshot[0].ToleratePercent != 10 {
		t.Fatal("an unlocked snapshot shares mutable manager storage")
	}
}
