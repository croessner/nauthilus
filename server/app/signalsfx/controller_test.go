package signalsfx

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type fakeNotifier struct {
	mu      sync.Mutex
	ch      chan<- os.Signal
	stopped bool
}

func (n *fakeNotifier) Notify(ch chan<- os.Signal, _ ...os.Signal) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.ch = ch
}

func (n *fakeNotifier) Stop(_ chan<- os.Signal) {
	n.mu.Lock()
	n.stopped = true
	n.mu.Unlock()
}

func (n *fakeNotifier) Send(sig os.Signal) {
	n.mu.Lock()
	ch := n.ch
	n.mu.Unlock()

	ch <- sig
}

type fakeReloadManager struct{ calls atomic.Int64 }

func (m *fakeReloadManager) Reload(context.Context) error {
	m.calls.Add(1)

	return nil
}

type fakeRestartManager struct{ calls atomic.Int64 }

func (m *fakeRestartManager) Restart(context.Context) error {
	m.calls.Add(1)

	return nil
}

func TestController_RoutesSignals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notifier := &fakeNotifier{}
	reloadMgr := &fakeReloadManager{}
	restartMgr := &fakeRestartManager{}

	controller := NewController(controllerIn{
		Ctx:            ctx,
		Cancel:         cancel,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Notifier:       notifier,
		ReloadManager:  reloadMgr,
		RestartManager: restartMgr,
	})

	if err := controller.Start(context.Background()); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	notifier.Send(syscall.SIGHUP)
	notifier.Send(syscall.SIGUSR1)

	notifier.Send(syscall.SIGTERM)

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("expected termination to cancel context")
	}

	if got := reloadMgr.calls.Load(); got != 1 {
		t.Fatalf("expected reload to be called once, got %d", got)
	}

	if got := restartMgr.calls.Load(); got != 1 {
		t.Fatalf("expected restart to be called once, got %d", got)
	}

	if err := controller.Stop(context.Background()); err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	notifier.mu.Lock()
	stopped := notifier.stopped
	notifier.mu.Unlock()

	if !stopped {
		t.Fatal("expected notifier to be stopped")
	}
}
