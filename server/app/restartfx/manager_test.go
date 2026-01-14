package restartfx

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/app/opsfx"
)

type restartRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *restartRecorder) add(name string) {
	r.mu.Lock()
	r.calls = append(r.calls, name)
	r.mu.Unlock()
}

func (r *restartRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]string, len(r.calls))
	copy(out, r.calls)

	return out
}

type fakeRestartable struct {
	name  string
	order int

	rec *restartRecorder

	enter   chan struct{}
	release chan struct{}
}

func (r *fakeRestartable) Name() string { return r.name }
func (r *fakeRestartable) Order() int   { return r.order }

func (r *fakeRestartable) Restart(_ context.Context) error {
	if r.enter != nil {
		select {
		case r.enter <- struct{}{}:
		default:
		}
	}

	if r.release != nil {
		<-r.release
	}

	if r.rec != nil {
		r.rec.add(r.name)
	}

	return nil
}

func TestRestartManager_SerializesConcurrentRestarts(t *testing.T) {
	r1 := &fakeRestartable{enter: make(chan struct{}, 1), release: make(chan struct{}), name: "r1", order: 1}
	r2 := &fakeRestartable{name: "r2", order: 2}

	manager := NewManager(managerIn{
		Gate:         opsfx.NewGate(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restartables: []Restartable{r1, r2},
	})

	ctx := context.Background()

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- manager.Restart(ctx)
	}()

	select {
	case <-r1.enter:
	case <-time.After(2 * time.Second):
		t.Fatal("first restart did not enter")
	}

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- manager.Restart(ctx)
	}()

	close(r1.release)

	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("unexpected first restart error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first restart did not complete")
	}

	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("unexpected second restart error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second restart did not complete")
	}
}

func TestRestartManager_CallsRestartInOrder(t *testing.T) {
	rec := &restartRecorder{calls: make([]string, 0, 3)}

	r2 := &fakeRestartable{name: "b", order: 20, rec: rec}
	r1 := &fakeRestartable{name: "a", order: 10, rec: rec}
	r3 := &fakeRestartable{name: "c", order: 20, rec: rec}

	manager := NewManager(managerIn{
		Gate:         opsfx.NewGate(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Restartables: []Restartable{r2, r3, r1},
	})

	if err := manager.Restart(context.Background()); err != nil {
		t.Fatalf("unexpected restart error: %v", err)
	}

	got := rec.snapshot()
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("unexpected call count: got %v, want %v", got, want)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected call order: got %v, want %v", got, want)
		}
	}
}
