package reloadfx

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/app/opsfx"
)

type fakeReloader struct {
	enter   chan struct{}
	release chan struct{}
	calls   atomic.Int64
	snap    configfx.Snapshot
	err     error
}

func (r *fakeReloader) Current() configfx.Snapshot {
	return r.snap
}

func (r *fakeReloader) Reload() (configfx.Snapshot, error) {
	r.calls.Add(1)
	if r.enter != nil {
		select {
		case r.enter <- struct{}{}:
		default:
		}
	}

	if r.release != nil {
		<-r.release
	}

	return r.snap, r.err
}

type callRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *callRecorder) add(name string) {
	r.mu.Lock()
	r.calls = append(r.calls, name)
	r.mu.Unlock()
}

func (r *callRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]string, len(r.calls))
	copy(out, r.calls)

	return out
}

type recordingReloadable struct {
	name  string
	order int

	rec *callRecorder
	err error
}

func (r *recordingReloadable) Name() string { return r.name }
func (r *recordingReloadable) Order() int   { return r.order }

func (r *recordingReloadable) ApplyConfig(_ context.Context, _ configfx.Snapshot) error {
	if r.rec != nil {
		r.rec.add(r.name)
	}

	return r.err
}

func TestReloadManager_SerializesConcurrentReloads(t *testing.T) {
	reloader := &fakeReloader{
		enter:   make(chan struct{}, 1),
		release: make(chan struct{}),
		snap:    configfx.Snapshot{Version: 2},
	}

	manager := NewManager(managerIn{
		Gate:     opsfx.NewGate(),
		Reloader: reloader,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ctx := context.Background()

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- manager.Reload(ctx)
	}()

	select {
	case <-reloader.enter:
	case <-time.After(2 * time.Second):
		t.Fatal("first reload did not enter")
	}

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- manager.Reload(ctx)
	}()

	if got := reloader.calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 Reload() call while first reload is blocked, got %d", got)
	}

	close(reloader.release)

	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("unexpected first reload error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first reload did not complete")
	}

	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("unexpected second reload error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second reload did not complete")
	}

	if got := reloader.calls.Load(); got != 2 {
		t.Fatalf("expected 2 Reload() calls, got %d", got)
	}
}

func TestReloadManager_CallsApplyConfigInOrder(t *testing.T) {
	reloader := &fakeReloader{snap: configfx.Snapshot{Version: 3}}

	rec := &callRecorder{calls: make([]string, 0, 3)}

	r2 := &recordingReloadable{name: "b", order: 20, rec: rec}
	r1 := &recordingReloadable{name: "a", order: 10, rec: rec}
	r3 := &recordingReloadable{name: "c", order: 20, rec: rec}

	manager := NewManager(managerIn{
		Gate:        opsfx.NewGate(),
		Reloader:    reloader,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Reloadables: []Reloadable{r2, r3, r1},
	})

	if err := manager.Reload(context.Background()); err != nil {
		t.Fatalf("unexpected reload error: %v", err)
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

func TestReloadManager_ContinuesOnComponentError(t *testing.T) {
	reloader := &fakeReloader{snap: configfx.Snapshot{Version: 4}}

	errBoom := errors.New("boom")
	rec := &callRecorder{calls: make([]string, 0, 2)}
	r1 := &recordingReloadable{name: "first", order: 1, rec: rec, err: errBoom}
	r2 := &recordingReloadable{name: "second", order: 2, rec: rec}

	manager := NewManager(managerIn{
		Gate:        opsfx.NewGate(),
		Reloader:    reloader,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Reloadables: []Reloadable{r1, r2},
	})

	err := manager.Reload(context.Background())
	if err == nil {
		t.Fatal("expected aggregated error")
	}

	if !errors.Is(err, errBoom) {
		t.Fatalf("expected error to wrap boom, got: %v", err)
	}

	got := rec.snapshot()
	if len(got) != 2 {
		t.Fatalf("expected both components to be called despite error, got: %v", got)
	}
}
