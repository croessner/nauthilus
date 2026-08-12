// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package effectsupervisor

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testDecisionID = "decision-supervisor-01"
	testProviderID = "authn/post_action"
)

func TestSupervisorRejectsInvalidUnknownSaturatedShutdownAndCanceledAcceptance(t *testing.T) {
	provider := &recordingProvider{}
	supervisor := newTestSupervisor(t, 1, 1, provider, nil)

	if _, err := supervisor.Accept(context.Background(), Plan{}); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("Accept(zero plan) error = %v, want ErrInvalidPlan", err)
	}

	unknown := newTestPlan(t, "missing/provider", newTestWork("unknown"), completedTestGate(t))
	if _, err := supervisor.Accept(context.Background(), unknown); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("Accept(unknown provider) error = %v, want ErrUnknownProvider", err)
	}

	blocking := newTestWork("blocking")
	blocking.started = make(chan struct{})
	blocking.release = make(chan struct{})

	first := newTestPlan(t, testProviderID, blocking, completedTestGate(t))
	if _, err := supervisor.Accept(context.Background(), first); err != nil {
		t.Fatalf("Accept(first) error = %v", err)
	}

	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("accepted work did not start")
	}

	saturated := newTestPlan(t, testProviderID, newTestWork("saturated"), completedTestGate(t))
	if _, err := supervisor.Accept(context.Background(), saturated); !errors.Is(err, ErrSaturated) {
		t.Fatalf("Accept(saturated) error = %v, want ErrSaturated", err)
	}

	close(blocking.release)
	waitForIdle(t, supervisor)

	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()

	canceled := newTestPlan(t, testProviderID, newTestWork("canceled"), completedTestGate(t))
	if _, err := supervisor.Accept(canceledContext, canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept(canceled) error = %v, want context.Canceled", err)
	}

	shutdownSupervisor(t, supervisor)

	afterShutdown := newTestPlan(t, testProviderID, newTestWork("shutdown"), completedTestGate(t))
	if _, err := supervisor.Accept(context.Background(), afterShutdown); !errors.Is(err, ErrShutdown) {
		t.Fatalf("Accept(after shutdown) error = %v, want ErrShutdown", err)
	}
}

func TestSupervisorAcceptanceTransfersImmutableOwnershipAndReturnsStableReceipt(t *testing.T) {
	observer := &recordingEffectObserver{}
	provider := &recordingProvider{}
	supervisor := newTestSupervisor(t, 1, 1, provider, observer)
	gate := newTestGate(t, BoundaryHTTPCommit)
	work := newTestWork("captured")
	plan := newTestPlan(t, testProviderID, work, gate)

	receipt, err := supervisor.Accept(context.Background(), plan)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}

	work.value = "mutated-after-acceptance"

	if got, want := receipt.ID(), testDecisionID+":1"; got != want {
		t.Fatalf("receipt ID = %q, want %q", got, want)
	}

	if receipt.DecisionID() != testDecisionID || receipt.Ordinal() != 1 {
		t.Fatalf("receipt correlation = %q/%d, want %q/1", receipt.DecisionID(), receipt.Ordinal(), testDecisionID)
	}

	select {
	case <-provider.invoked:
		t.Fatal("provider ran before the finalization gate opened")
	default:
	}

	gate.Complete()
	waitForIdle(t, supervisor)

	if got := provider.values(); !slices.Equal(got, []string{"captured"}) {
		t.Fatalf("executed values = %#v, want immutable captured value", got)
	}

	if got := work.cleaned.Load(); got != 1 {
		t.Fatalf("cleanup count = %d, want 1", got)
	}

	if got := observer.states(); !slices.Equal(got, []State{
		StateNotStarted,
		StateAccepted,
		StateAttempted,
		StateSucceeded,
	}) {
		t.Fatalf("state order = %#v, want deterministic acceptance before execution", got)
	}
}

func TestSupervisorBoundsConcurrencyAndReleasesCapacityExactlyOnce(t *testing.T) {
	provider := &recordingProvider{}
	supervisor := newTestSupervisor(t, 3, 1, provider, nil)
	release := make(chan struct{})
	works := []*testWork{newTestWork("one"), newTestWork("two"), newTestWork("three")}

	for _, work := range works {
		work.release = release
		plan := newTestPlan(t, testProviderID, work, completedTestGate(t))

		if _, err := supervisor.Accept(context.Background(), plan); err != nil {
			t.Fatalf("Accept(%s) error = %v", work.value, err)
		}
	}

	waitForCondition(t, func() bool { return provider.maxConcurrent.Load() == 1 }, "worker did not begin")

	if got := supervisor.InFlight(); got != 3 {
		t.Fatalf("in-flight work = %d, want 3", got)
	}

	close(release)
	waitForIdle(t, supervisor)

	if got := provider.maxConcurrent.Load(); got != 1 {
		t.Fatalf("maximum concurrency = %d, want 1", got)
	}

	for _, work := range works {
		if got := work.cleaned.Load(); got != 1 {
			t.Fatalf("work %q cleanup count = %d, want 1", work.value, got)
		}
	}

	reuse := newTestPlan(t, testProviderID, newTestWork("reuse"), completedTestGate(t))
	if _, err := supervisor.Accept(context.Background(), reuse); err != nil {
		t.Fatalf("capacity was not reusable after cleanup: %v", err)
	}

	waitForIdle(t, supervisor)
}

func TestSupervisorContainsPanicAndNeverRetriesKnownOrAmbiguousFailure(t *testing.T) {
	tests := []struct {
		name      string
		result    Result
		panicWork bool
		wantState State
	}{
		{name: "known failure", result: Failed("provider_error"), wantState: StateFailed},
		{name: "outcome unknown", result: OutcomeUnknown("dispatch_ambiguous"), wantState: StateOutcomeUnknown},
		{name: "panic", panicWork: true, wantState: StateFailed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observer := &recordingEffectObserver{}
			provider := &recordingProvider{}
			supervisor := newTestSupervisor(t, 1, 1, provider, observer)
			work := newTestWork(test.name)
			work.result = test.result
			work.panicExecute = test.panicWork
			plan := newTestPlan(t, testProviderID, work, completedTestGate(t))

			if _, err := supervisor.Accept(context.Background(), plan); err != nil {
				t.Fatalf("Accept() error = %v", err)
			}

			waitForIdle(t, supervisor)

			if got := work.invocations.Load(); got != 1 {
				t.Fatalf("provider invocations = %d, want at-most-once invocation", got)
			}

			if got := work.cleaned.Load(); got != 1 {
				t.Fatalf("cleanup count = %d, want 1", got)
			}

			if !observer.sawState(test.wantState) {
				t.Fatalf("events = %#v, want terminal state %q", observer.eventsCopy(), test.wantState)
			}
		})
	}
}

func TestSupervisorCancellationBeforeAndAfterAcceptanceUsesCapturedLifetime(t *testing.T) {
	provider := &recordingProvider{}
	supervisor := newTestSupervisor(t, 1, 1, provider, nil)
	gate := newTestGate(t, BoundaryHTTPCommit)
	work := newTestWork("accepted")
	work.contextErrors = make(chan error, 1)
	requestContext, cancelRequest := context.WithCancel(context.Background())
	plan := newTestPlan(t, testProviderID, work, gate)

	if _, err := supervisor.Accept(requestContext, plan); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}

	cancelRequest()
	gate.Complete()
	waitForIdle(t, supervisor)

	select {
	case contextError := <-work.contextErrors:
		if contextError != nil {
			t.Fatalf("accepted execution context error = %v, want nil", contextError)
		}
	default:
		t.Fatal("provider did not report its accepted execution context")
	}

	canceledContext, cancelBefore := context.WithCancel(context.Background())
	cancelBefore()

	rejected := newTestPlan(t, testProviderID, newTestWork("rejected"), completedTestGate(t))
	if _, err := supervisor.Accept(canceledContext, rejected); !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept(pre-canceled) error = %v, want context.Canceled", err)
	}
}

func TestSupervisorRejectsCancellationDuringCaptureAndReleasesCapturedWork(t *testing.T) {
	provider := &blockingCaptureProvider{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	supervisor := newTestSupervisor(t, 1, 1, provider, nil)
	work := newTestWork("capture-canceled")
	requestContext, cancelRequest := context.WithCancel(context.Background())
	result := make(chan error, 1)
	plan := newTestPlan(t, testProviderID, work, completedTestGate(t))

	go func() {
		_, err := supervisor.Accept(requestContext, plan)
		result <- err
	}()

	select {
	case <-provider.started:
	case <-time.After(time.Second):
		t.Fatal("provider capture did not start")
	}

	cancelRequest()
	close(provider.release)

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Accept() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept() did not return after capture completed")
	}

	if got := work.invocations.Load(); got != 0 {
		t.Fatalf("provider invocations = %d, want 0", got)
	}

	if got := work.cleaned.Load(); got != 1 {
		t.Fatalf("cleanup count = %d, want 1", got)
	}

	if got := supervisor.InFlight(); got != 0 {
		t.Fatalf("in-flight work = %d, want 0", got)
	}
}

func TestSupervisorRejectsLifetimeCancellationDuringCaptureAndReleasesCapturedWork(t *testing.T) {
	provider := &blockingCaptureProvider{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	lifetime, cancelLifetime := context.WithCancel(context.Background())

	supervisor, err := New(Config{
		Capacity: 1,
		Workers:  1,
		Lifetime: lifetime,
	}, ProviderBinding{Name: testProviderID, Provider: provider})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	t.Cleanup(func() { shutdownSupervisor(t, supervisor) })

	work := newTestWork("lifetime-canceled")
	result := make(chan error, 1)
	plan := newTestPlan(t, testProviderID, work, completedTestGate(t))

	go func() {
		_, acceptErr := supervisor.Accept(context.Background(), plan)
		result <- acceptErr
	}()

	select {
	case <-provider.started:
	case <-time.After(time.Second):
		t.Fatal("provider capture did not start")
	}

	cancelLifetime()
	close(provider.release)

	select {
	case acceptErr := <-result:
		if !errors.Is(acceptErr, ErrShutdown) || !errors.Is(acceptErr, context.Canceled) {
			t.Fatalf("Accept() error = %v, want ErrShutdown joined with context.Canceled", acceptErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept() did not return after lifetime cancellation")
	}

	if got := work.cleaned.Load(); got != 1 {
		t.Fatalf("cleanup count = %d, want 1", got)
	}

	if got := supervisor.InFlight(); got != 0 {
		t.Fatalf("in-flight work = %d, want 0", got)
	}
}

func TestSupervisorPrioritizesCancellationWhenFinalizationIsAlreadyComplete(t *testing.T) {
	provider := &recordingProvider{}
	supervisor := newTestSupervisor(t, 1, 1, provider, nil)
	work := newTestWork("canceled-before-execution")
	plan := newTestPlan(t, testProviderID, work, completedTestGate(t))

	captured, err := provider.Capture(context.Background(), work)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}

	ownership := make(chan struct{})
	close(ownership)

	supervisor.mu.Lock()
	supervisor.reserveLocked()
	supervisor.mu.Unlock()
	supervisor.cancel()

	supervisor.execute(&acceptedWork{
		supervisor: supervisor,
		provider:   provider,
		work:       captured,
		plan:       plan,
		ownership:  ownership,
		deadline:   time.Now().Add(time.Second),
	})

	if got := work.invocations.Load(); got != 0 {
		t.Fatalf("provider invocations = %d, want 0", got)
	}

	if got := work.cleaned.Load(); got != 1 {
		t.Fatalf("cleanup count = %d, want 1", got)
	}

	if got := supervisor.InFlight(); got != 0 {
		t.Fatalf("in-flight work = %d, want 0", got)
	}
}

func TestSupervisorShutdownCancelsAcceptedWorkAndCleansQueuedCapacity(t *testing.T) {
	provider := &recordingProvider{}
	supervisor := newTestSupervisor(t, 2, 1, provider, nil)
	gate := newTestGate(t, BoundaryGRPCUnaryReturn)
	works := []*testWork{newTestWork("waiting"), newTestWork("queued")}

	for _, work := range works {
		plan := newTestPlan(t, testProviderID, work, gate)

		if _, err := supervisor.Accept(context.Background(), plan); err != nil {
			t.Fatalf("Accept(%s) error = %v", work.value, err)
		}
	}

	shutdownSupervisor(t, supervisor)

	if got := supervisor.InFlight(); got != 0 {
		t.Fatalf("in-flight work after shutdown = %d, want 0", got)
	}

	for _, work := range works {
		if got := work.invocations.Load(); got != 0 {
			t.Fatalf("work %q invocations = %d, want not started", work.value, got)
		}

		if got := work.cleaned.Load(); got != 1 {
			t.Fatalf("work %q cleanup count = %d, want 1", work.value, got)
		}
	}
}

func TestSupervisorRejectsAcceptanceFromAlreadyCanceledLifetime(t *testing.T) {
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	cancelLifetime()

	supervisor, err := New(Config{
		Capacity: 1,
		Workers:  1,
		Lifetime: lifetime,
	}, ProviderBinding{Name: testProviderID, Provider: &recordingProvider{}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	plan := newTestPlan(t, testProviderID, newTestWork("dead-generation"), completedTestGate(t))
	if _, err = supervisor.Accept(context.Background(), plan); !errors.Is(err, ErrShutdown) {
		t.Fatalf("Accept() error = %v, want ErrShutdown", err)
	}

	shutdownSupervisor(t, supervisor)
}

func TestSupervisorShutdownReusesOneWorkerCompletionWaiter(t *testing.T) {
	provider := &nonCooperativeProvider{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	supervisor := newTestSupervisor(t, 1, 1, provider, nil)
	work := newTestWork("shutdown-waiter")
	plan := newTestPlan(t, testProviderID, work, completedTestGate(t))

	if _, err := supervisor.Accept(context.Background(), plan); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}

	select {
	case <-provider.started:
	case <-time.After(time.Second):
		t.Fatal("provider execution did not start")
	}

	completion := supervisor.workersDone

	for range 3 {
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), time.Millisecond)
		err := supervisor.Shutdown(shutdownContext)

		cancelShutdown()

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Shutdown() error = %v, want context.DeadlineExceeded", err)
		}

		if supervisor.workersDone != completion {
			t.Fatal("Shutdown() replaced the supervisor-owned worker completion channel")
		}
	}

	close(provider.release)

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()

	if err := supervisor.Shutdown(shutdownContext); err != nil {
		t.Fatalf("final Shutdown() error = %v", err)
	}
}

type recordingProvider struct {
	mu            sync.Mutex
	seenValues    []string
	invoked       chan struct{}
	concurrent    atomic.Int32
	maxConcurrent atomic.Int32
}

type blockingCaptureProvider struct {
	started chan struct{}
	release chan struct{}
}

type nonCooperativeProvider struct {
	started chan struct{}
	release chan struct{}
}

// Capture retains the test work for a provider that deliberately ignores cancellation.
func (*nonCooperativeProvider) Capture(_ context.Context, work Work) (Work, error) {
	return work, nil
}

// Execute blocks independently of its context to exercise shutdown waiter ownership.
func (p *nonCooperativeProvider) Execute(_ context.Context, _ Work) Result {
	close(p.started)
	<-p.release

	return Succeeded()
}

// Release records no external resource for this shutdown-specific provider.
func (*nonCooperativeProvider) Release(Work) {}

// Capture waits until the test releases the cancellation race window.
func (p *blockingCaptureProvider) Capture(_ context.Context, work Work) (Work, error) {
	close(p.started)
	<-p.release

	return work, nil
}

// Execute records an unexpected invocation after rejected acceptance.
func (*blockingCaptureProvider) Execute(_ context.Context, work Work) Result {
	work.(*testWork).invocations.Add(1)

	return Succeeded()
}

// Release records cleanup of work captured before acceptance cancellation.
func (*blockingCaptureProvider) Release(work Work) {
	work.(*testWork).cleaned.Add(1)
}

// Capture owns an immutable copy of test work at the acceptance boundary.
func (p *recordingProvider) Capture(ctx context.Context, work Work) (Work, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	requested, ok := work.(*testWork)
	if !ok || requested == nil {
		return nil, ErrInvalidWork
	}

	captured := *requested
	captured.value = requested.value

	return &captured, nil
}

// Execute records concurrency and delegates the selected test behavior.
func (p *recordingProvider) Execute(ctx context.Context, work Work) Result {
	requested := work.(*testWork)
	current := p.concurrent.Add(1)

	defer p.concurrent.Add(-1)

	p.recordMaximumConcurrency(current)
	p.notifyInvocation(ctx, requested)

	if requested.panicExecute {
		panic("supervisor test panic")
	}

	if result, done := requested.waitForRelease(ctx); done {
		return result
	}

	p.mu.Lock()
	p.seenValues = append(p.seenValues, requested.value)
	p.mu.Unlock()

	if requested.result.State() != "" {
		return requested.result
	}

	return Succeeded()
}

// recordMaximumConcurrency updates the highest observed worker count.
func (p *recordingProvider) recordMaximumConcurrency(current int32) {
	for {
		maximum := p.maxConcurrent.Load()
		if current <= maximum || p.maxConcurrent.CompareAndSwap(maximum, current) {
			return
		}
	}
}

// notifyInvocation publishes execution-start and context observations.
func (p *recordingProvider) notifyInvocation(ctx context.Context, requested *testWork) {
	requested.invocations.Add(1)

	if p.invoked != nil {
		select {
		case p.invoked <- struct{}{}:
		default:
		}
	}

	if requested.started != nil {
		close(requested.started)
	}

	if requested.contextErrors != nil {
		requested.contextErrors <- ctx.Err()
	}
}

// waitForRelease applies optional test blocking and reports cancellation.
func (w *testWork) waitForRelease(ctx context.Context) (Result, bool) {
	if w.release != nil {
		select {
		case <-w.release:
		case <-ctx.Done():
			return Failed("canceled"), true
		}
	}

	return Result{}, false
}

// Release records cleanup against the caller-visible work owner.
func (*recordingProvider) Release(work Work) {
	requested := work.(*testWork)
	requested.cleaned.Add(1)
}

// values returns an owned copy of executed immutable values.
func (p *recordingProvider) values() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return append([]string(nil), p.seenValues...)
}

type testWork struct {
	started       chan struct{}
	release       chan struct{}
	contextErrors chan error
	value         string
	result        Result
	invocations   *atomic.Int32
	cleaned       *atomic.Int32
	panicExecute  bool
}

// newTestWork creates one work value whose ownership counters survive capture.
func newTestWork(value string) *testWork {
	return &testWork{
		value:       value,
		invocations: &atomic.Int32{},
		cleaned:     &atomic.Int32{},
	}
}

type recordingEffectObserver struct {
	mu     sync.Mutex
	events []Event
}

// Observe records one supervisor state transition.
func (o *recordingEffectObserver) Observe(_ context.Context, event Event) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.events = append(o.events, event)
}

// sawState reports whether the observer received a requested state.
func (o *recordingEffectObserver) sawState(state State) bool {
	for _, event := range o.eventsCopy() {
		if event.State == state {
			return true
		}
	}

	return false
}

// eventsCopy returns a detached observer snapshot.
func (o *recordingEffectObserver) eventsCopy() []Event {
	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]Event(nil), o.events...)
}

// states returns the ordered supervisor state transitions.
func (o *recordingEffectObserver) states() []State {
	events := o.eventsCopy()
	states := make([]State, 0, len(events))

	for _, event := range events {
		states = append(states, event.State)
	}

	return states
}

// newTestSupervisor constructs an isolated supervisor for one test.
func newTestSupervisor(t *testing.T, capacity int, workers int, provider Provider, observer Observer) *Supervisor {
	t.Helper()

	supervisor, err := New(Config{
		Capacity: capacity,
		Workers:  workers,
		Lifetime: context.Background(),
		Observer: observer,
	}, ProviderBinding{Name: testProviderID, Provider: provider})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	t.Cleanup(func() {
		shutdownSupervisor(t, supervisor)
	})

	return supervisor
}

// newTestPlan constructs a valid bounded plan around test work.
func newTestPlan(t *testing.T, provider string, work Work, gate FinalizationGate) Plan {
	t.Helper()

	plan, err := NewPlan(PlanInput{
		DecisionID:     testDecisionID,
		EffectOrdinal:  1,
		Target:         "authn/authenticate",
		Provider:       provider,
		DeadlineBudget: time.Second,
		Gate:           gate,
		Observability: ObservabilityMetadata{
			RuntimeGeneration: 42,
			Source:            "authn",
		},
		Work: work,
	})
	if err != nil {
		t.Fatalf("NewPlan() error = %v", err)
	}

	return plan
}

// waitForIdle waits for every accepted work item to release ownership.
func waitForIdle(t *testing.T, supervisor *Supervisor) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := supervisor.WaitIdle(ctx); err != nil {
		t.Fatalf("WaitIdle() error = %v", err)
	}
}

// shutdownSupervisor stops a supervisor within the test timeout.
func shutdownSupervisor(t *testing.T, supervisor *Supervisor) {
	t.Helper()

	if supervisor == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := supervisor.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

// waitForCondition polls a short-lived concurrent test invariant.
func waitForCondition(t *testing.T, condition func() bool, failure string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}

		time.Sleep(time.Millisecond)
	}

	t.Fatal(failure)
}
