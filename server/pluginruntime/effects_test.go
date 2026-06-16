package pluginruntime

import (
	"context"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/policy/report"
)

const (
	effectObligationName      = "sync_obligation"
	effectPostActionName      = "post_action"
	effectObligationQualified = testRuntimeModuleName + "." + effectObligationName
	effectPostActionQualified = testRuntimeModuleName + "." + effectPostActionName
	effectMessageArg          = "message"
	effectMessageValue        = "hello"
)

func TestEffectBridgeExecutesObligationSynchronously(t *testing.T) {
	target := &fakeObligationTarget{}
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterObligationTarget(target)
	})
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{
		ID:   effectObligationQualified,
		Args: map[string]any{effectMessageArg: effectMessageValue},
	})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	if !target.called {
		t.Fatal("obligation returned before Execute was called")
	}

	if value, _ := target.args.Get(effectMessageArg); value != effectMessageValue {
		t.Fatalf("message arg = %#v, want hello", value)
	}
}

func TestEffectBridgeMapsObligationErrorToFailure(t *testing.T) {
	target := &fakeObligationTarget{err: context.Canceled}
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterObligationTarget(target)
	})
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectObligationQualified})
	if !handled {
		t.Fatal("ExecutePolicyEffect() handled = false, want true")
	}

	if ok {
		t.Fatal("ExecutePolicyEffect() ok = true, want false")
	}
}

func TestEffectBridgeEnqueuesPostActionUnderHostSupervision(t *testing.T) {
	target := &fakePostActionTarget{called: make(chan struct{})}
	host := NewHost()
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterPostActionTarget(target)
	}, WithHost(host))
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectPostActionQualified})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	select {
	case <-target.called:
	case <-time.After(time.Second):
		t.Fatal("post-action target was not invoked")
	}

	host.WaitWorkers()
}

func TestEffectBridgeRecoversPostActionPanic(t *testing.T) {
	observer := &recordingObserver{}
	target := &fakePostActionTarget{called: make(chan struct{}), panicEnqueue: true}
	host := NewHost()
	bridge := newEffectTestBridge(t, func(registrar pluginapi.Registrar) error {
		return registrar.RegisterPostActionTarget(target)
	}, WithHost(host), WithObserver(observer))
	auth := newSubjectTestAuth(t)

	handled, ok := bridge.ExecutePolicyEffect(auth.Request.HTTPClientContext, auth.View(), report.EffectRequest{ID: effectPostActionQualified})
	if !handled || !ok {
		t.Fatalf("ExecutePolicyEffect() handled=%t ok=%t, want true/true", handled, ok)
	}

	select {
	case <-target.called:
	case <-time.After(time.Second):
		t.Fatal("post-action target was not invoked")
	}

	host.WaitWorkers()

	if !observer.sawPanic(effectPostActionName, "Enqueue") {
		t.Fatalf("observer records = %#v, want post-action panic", observer.records)
	}
}

func newEffectTestBridge(t *testing.T, register func(pluginapi.Registrar) error, options ...Option) *EffectBridge {
	t.Helper()

	runner := newTestRunner(t, &runtimePlugin{}, register, options...)
	if err := runner.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	return NewEffectBridge(runner)
}

type fakeObligationTarget struct {
	args   pluginapi.ArgsView
	err    error
	called bool
}

func (t *fakeObligationTarget) Name() string {
	return effectObligationName
}

func (t *fakeObligationTarget) Execute(_ context.Context, request pluginapi.ObligationRequest) (pluginapi.ObligationResult, error) {
	t.called = true
	t.args = request.Args

	return pluginapi.ObligationResult{Applied: t.err == nil}, t.err
}

type fakePostActionTarget struct {
	called       chan struct{}
	panicEnqueue bool
}

func (t *fakePostActionTarget) Name() string {
	return effectPostActionName
}

func (t *fakePostActionTarget) Enqueue(context.Context, pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error) {
	close(t.called)

	if t.panicEnqueue {
		panic("post-action panic")
	}

	return pluginapi.PostActionEnqueueResult{Enqueued: true}, nil
}
