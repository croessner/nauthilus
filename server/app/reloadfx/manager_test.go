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

	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/app/opsfx"
)

type fakeReloader struct {
	enter   chan struct{}
	release chan struct{}
	calls   atomic.Int64
	snap    configfx.Snapshot
	err     error
}

type fakeGenerationCoordinator struct {
	calls atomic.Int64
	snap  configfx.Snapshot
	err   error
}

type committedGenerationTestError struct {
	err error
}

// Error returns the injected post-commit failure.
func (e committedGenerationTestError) Error() string {
	return e.err.Error()
}

// Unwrap exposes the injected post-commit failure.
func (e committedGenerationTestError) Unwrap() error {
	return e.err
}

// GenerationCommitted reports that publication completed before this error.
func (committedGenerationTestError) GenerationCommitted() bool {
	return true
}

// Current returns the fake's active configuration snapshot.
func (r *fakeReloader) Current() configfx.Snapshot {
	return r.snap
}

// Prepare records and optionally blocks one candidate preparation.
func (r *fakeReloader) Prepare() (configfx.Snapshot, error) {
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

// Apply records one atomic generation publication attempt.
func (c *fakeGenerationCoordinator) Apply(_ context.Context, snap configfx.Snapshot) error {
	c.calls.Add(1)
	c.snap = snap

	return c.err
}

type callRecorder struct {
	mu    sync.Mutex
	calls []string
}

// add appends one observed component call safely.
func (r *callRecorder) add(name string) {
	r.mu.Lock()
	r.calls = append(r.calls, name)
	r.mu.Unlock()
}

// snapshot returns a detached copy of observed component calls.
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

// Name returns the fake reloadable identity.
func (r *recordingReloadable) Name() string { return r.name }

// Order returns the fake reloadable ordering key.
func (r *recordingReloadable) Order() int { return r.order }

// ApplyConfig records one post-commit invocation.
func (r *recordingReloadable) ApplyConfig(_ context.Context, _ configfx.Snapshot) error {
	if r.rec != nil {
		r.rec.add(r.name)
	}

	return r.err
}

// TestReloadManager_SerializesConcurrentReloads proves candidate preparation cannot overlap.
func TestReloadManager_SerializesConcurrentReloads(t *testing.T) {
	reloader := &fakeReloader{
		enter:   make(chan struct{}, 1),
		release: make(chan struct{}),
		snap:    configfx.Snapshot{Version: 2},
	}

	manager := NewManager(managerIn{
		Gate:        opsfx.NewGate(),
		Reloader:    reloader,
		Coordinator: &fakeGenerationCoordinator{},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
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
		t.Fatalf("expected exactly 1 Prepare() call while first reload is blocked, got %d", got)
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
		t.Fatalf("expected 2 Prepare() calls, got %d", got)
	}
}

// TestReloadManager_CallsApplyConfigInOrder proves deterministic post-commit ordering.
func TestReloadManager_CallsApplyConfigInOrder(t *testing.T) {
	reloader := &fakeReloader{snap: configfx.Snapshot{Version: 3}}

	rec := &callRecorder{calls: make([]string, 0, 3)}

	r2 := &recordingReloadable{name: "b", order: 20, rec: rec}
	r1 := &recordingReloadable{name: "a", order: 10, rec: rec}
	r3 := &recordingReloadable{name: "c", order: 20, rec: rec}

	manager := NewManager(managerIn{
		Gate:        opsfx.NewGate(),
		Reloader:    reloader,
		Coordinator: &fakeGenerationCoordinator{},
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

// TestReloadManagerContinuesAfterCommittedGenerationRetirementFailure keeps post-commit state aligned.
func TestReloadManagerContinuesAfterCommittedGenerationRetirementFailure(t *testing.T) {
	retirementFailure := errors.New("generation retirement failed")
	recorder := &callRecorder{}
	manager := NewManager(managerIn{
		Gate:        opsfx.NewGate(),
		Reloader:    &fakeReloader{snap: configfx.Snapshot{Version: 4}},
		Coordinator: &fakeGenerationCoordinator{err: committedGenerationTestError{err: retirementFailure}},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Reloadables: []Reloadable{&recordingReloadable{name: "post_commit", rec: recorder}},
	})

	err := manager.Reload(context.Background())
	if !errors.Is(err, retirementFailure) {
		t.Fatalf("Reload() error = %v, want committed retirement failure", err)
	}

	if got := recorder.snapshot(); len(got) != 1 || got[0] != "post_commit" {
		t.Fatalf("post-commit calls = %v, want post_commit", got)
	}
}

// TestReloadManager_ContinuesOnComponentError proves non-policy reload remains best effort.
func TestReloadManager_ContinuesOnComponentError(t *testing.T) {
	reloader := &fakeReloader{snap: configfx.Snapshot{Version: 4}}

	errBoom := errors.New("boom")
	rec := &callRecorder{calls: make([]string, 0, 2)}
	r1 := &recordingReloadable{name: "first", order: 1, rec: rec, err: errBoom}
	r2 := &recordingReloadable{name: "second", order: 2, rec: rec}

	manager := NewManager(managerIn{
		Gate:        opsfx.NewGate(),
		Reloader:    reloader,
		Coordinator: &fakeGenerationCoordinator{},
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

// TestReloadManager_PreparationFailureSkipsGenerationAndReloadables proves fail-closed ordering.
func TestReloadManager_PreparationFailureSkipsGenerationAndReloadables(t *testing.T) {
	errPreparation := errors.New("candidate rejected")
	reloader := &fakeReloader{err: errPreparation}
	coordinator := &fakeGenerationCoordinator{}
	recorder := &callRecorder{}

	manager := NewManager(managerIn{
		Gate:        opsfx.NewGate(),
		Reloader:    reloader,
		Coordinator: coordinator,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Reloadables: []Reloadable{&recordingReloadable{name: "later", rec: recorder}},
	})

	err := manager.Reload(context.Background())
	if !errors.Is(err, errPreparation) {
		t.Fatalf("Reload() error = %v, want preparation failure", err)
	}

	if got := coordinator.calls.Load(); got != 0 {
		t.Fatalf("generation Apply() calls = %d, want 0", got)
	}

	if got := recorder.snapshot(); len(got) != 0 {
		t.Fatalf("reloadables ran after rejected preparation: %v", got)
	}
}

// TestReloadManager_GenerationFailureSkipsIndependentReloadables proves commit failure is terminal.
func TestReloadManager_GenerationFailureSkipsIndependentReloadables(t *testing.T) {
	errGeneration := errors.New("generation rejected")
	reloader := &fakeReloader{snap: configfx.Snapshot{Version: 5}}
	coordinator := &fakeGenerationCoordinator{err: errGeneration}
	recorder := &callRecorder{}

	manager := NewManager(managerIn{
		Gate:        opsfx.NewGate(),
		Reloader:    reloader,
		Coordinator: coordinator,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Reloadables: []Reloadable{&recordingReloadable{name: "later", rec: recorder}},
	})

	err := manager.Reload(context.Background())
	if !errors.Is(err, errGeneration) {
		t.Fatalf("Reload() error = %v, want generation failure", err)
	}

	if got := coordinator.calls.Load(); got != 1 {
		t.Fatalf("generation Apply() calls = %d, want 1", got)
	}

	if got := recorder.snapshot(); len(got) != 0 {
		t.Fatalf("post-commit reloadables ran before a successful generation commit: %v", got)
	}
}
