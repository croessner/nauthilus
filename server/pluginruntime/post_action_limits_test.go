package pluginruntime

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

type limitedPostActionFixture struct {
	started     chan struct{}
	release     chan struct{}
	calls       atomic.Int32
	rate        int
	concurrency int
}

// Name returns the arbitrary component identity used to prove generic host ownership.
func (*limitedPostActionFixture) Name() string { return "limited" }

// AdmissionLimits declares immutable per-component host bounds.
func (p *limitedPostActionFixture) AdmissionLimits() (int, int) { return p.rate, p.concurrency }

// Enqueue blocks only the first callback so a missing concurrency gate fails without deadlocking.
func (p *limitedPostActionFixture) Enqueue(context.Context, pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error) {
	if p.calls.Add(1) == 1 && p.started != nil {
		close(p.started)
		<-p.release
	}

	return pluginapi.PostActionEnqueueResult{Enqueued: true}, nil
}

// limitedPostActionOwner captures limits through the real registrar and authentication binding path.
func limitedPostActionOwner(t *testing.T, fixture *limitedPostActionFixture) *nativeAuthnPostActionProvider {
	t.Helper()

	registrar := pluginregistry.NewRegistry().NewRegistrar(config.PluginModule{Name: "example"})
	if err := registrar.RegisterPostActionTarget(fixture); err != nil {
		t.Fatal(err)
	}

	bindings := &GenerationBindings{modules: []GenerationModuleBinding{{moduleName: "example", components: registrar.Components()}}}

	prepared, err := bindings.PrepareAuthenticationBindings(t.Context(), AuthenticationBindingInput{PostActionAcceptance: acceptingAuthnEffectAcceptor{}})
	if err != nil {
		t.Fatal(err)
	}

	return prepared.PostActions()["authn/plugin.example.limited"].(*nativeAuthnPostActionProvider)
}

// limitedPostActionCall binds one immutable request to the captured host callback.
func limitedPostActionCall(t *testing.T, fixture *limitedPostActionFixture) func() (pluginapi.PostActionEnqueueResult, error) {
	t.Helper()
	owner := limitedPostActionOwner(t, fixture)
	request := forgedPostActionRequest(t)
	target := authenticationEffectTestTarget(t)

	return func() (pluginapi.PostActionEnqueueResult, error) {
		return owner.EnqueuePostAction(t.Context(), request, target)
	}
}

// assertPostActionLimitRejected checks both temporary backpressure and absence of a second callback.
func assertPostActionLimitRejected(t *testing.T, fixture *limitedPostActionFixture, invoke func() (pluginapi.PostActionEnqueueResult, error)) {
	t.Helper()

	result, err := invoke()
	if err == nil || !result.Temporary || fixture.calls.Load() != 1 {
		t.Fatalf("host limits bypassed: calls=%d temporary=%t error=%v", fixture.calls.Load(), result.Temporary, err)
	}
}

// TestNativePostActionLimitsApplyBeforeCallback reproduces independent rate and concurrency bounds.
func TestNativePostActionLimitsApplyBeforeCallback(t *testing.T) {
	t.Run("rate", testPostActionRateBound)
	t.Run("concurrency", testPostActionConcurrencyBound)
}

// testPostActionRateBound denies a sequential burst after the component's single token is spent.
func testPostActionRateBound(t *testing.T) {
	fixture := &limitedPostActionFixture{rate: 1, concurrency: 2}

	invoke := limitedPostActionCall(t, fixture)
	if _, err := invoke(); err != nil {
		t.Fatal(err)
	}

	assertPostActionLimitRejected(t, fixture, invoke)
}

// testPostActionConcurrencyBound rejects overlapping work and returns capacity after completion.
func testPostActionConcurrencyBound(t *testing.T) {
	fixture := &limitedPostActionFixture{rate: 100, concurrency: 1, started: make(chan struct{}), release: make(chan struct{})}

	releaseFirst := sync.OnceFunc(func() { close(fixture.release) })
	defer releaseFirst()

	invoke := limitedPostActionCall(t, fixture)

	finished := make(chan struct{})
	go func() { defer close(finished); _, _ = invoke() }()

	select {
	case <-fixture.started:
	case <-time.After(time.Second):
		t.Fatal("first callback never started")
	}

	assertPostActionLimitRejected(t, fixture, invoke)
	releaseFirst()

	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("first callback failed to return capacity")
	}

	if _, err := invoke(); err != nil || fixture.calls.Load() != 2 {
		t.Fatal("host did not return released callback capacity")
	}
}
