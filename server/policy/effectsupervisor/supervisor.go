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
	"fmt"
	"sync"
	"time"

	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"
	"github.com/croessner/nauthilus/v4/server/policy/decision"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	oteltrace "go.opentelemetry.io/otel/trace"
)

const (
	receiptOrdinalSeparator = ":"
	providerErrorClass      = "provider_error"
	shutdownErrorClass      = "shutdown"
)

var (
	// ErrUnknownProvider marks a plan whose provider is absent from this supervisor generation.
	ErrUnknownProvider = errors.New("unknown post-action provider")

	// ErrSaturated marks a deterministic bounded-capacity rejection.
	ErrSaturated = errors.New("post-action supervisor capacity exhausted")

	// ErrShutdown marks rejection after supervisor shutdown begins.
	ErrShutdown = errors.New("post-action supervisor is shutting down")

	// ErrProviderPanic marks a contained provider capture or execution panic.
	ErrProviderPanic = errors.New("post-action provider panicked")
)

// State is one bounded internal effect lifecycle state.
type State string

const (
	// StateNotStarted records a plan before ownership transfer.
	StateNotStarted State = "not_started"

	// StateAttempted records the single provider invocation.
	StateAttempted State = "attempted"

	// StateAccepted records synchronous supervisor ownership.
	StateAccepted State = "accepted"

	// StateSucceeded records a known successful provider outcome.
	StateSucceeded State = "succeeded"

	// StateFailed records a known failure or contained worker failure.
	StateFailed State = "failed"

	// StateOutcomeUnknown records ambiguity after possible external dispatch.
	StateOutcomeUnknown State = "outcome_unknown"
)

// Phase separates synchronous acceptance from later response-gated execution.
type Phase string

const (
	// PhaseAcceptance identifies work before supervisor ownership is confirmed.
	PhaseAcceptance Phase = "acceptance"

	// PhaseExecution identifies work after supervisor ownership is confirmed.
	PhaseExecution Phase = "execution"
)

// Result is a bounded provider execution result with no retry instruction.
type Result struct {
	state      State
	errorClass string
}

// Succeeded returns a known successful execution result.
func Succeeded() Result {
	return Result{state: StateSucceeded}
}

// Failed returns a known failed execution result.
func Failed(errorClass string) Result {
	return Result{state: StateFailed, errorClass: safeErrorClass(errorClass)}
}

// OutcomeUnknown returns provider ambiguity after possible external dispatch.
func OutcomeUnknown(errorClass string) Result {
	return Result{state: StateOutcomeUnknown, errorClass: safeErrorClass(errorClass)}
}

// State returns the bounded terminal execution state.
func (r Result) State() State {
	return r.state
}

// ErrorClass returns a secret-safe bounded failure class.
func (r Result) ErrorClass() string {
	return r.errorClass
}

// Provider captures immutable work and owns its later invocation and release behavior.
type Provider interface {
	Capture(context.Context, Work) (Work, error)
	Execute(context.Context, Work) Result
	Release(Work)
}

// ProviderBinding binds one exact provider identity into a supervisor generation.
type ProviderBinding struct {
	Provider Provider
	Name     string
}

// Observer records bounded state transitions without controlling execution.
type Observer interface {
	Observe(context.Context, Event)
}

// Event is a redacted internal state transition record.
type Event struct {
	DecisionID        string
	Target            string
	Provider          string
	ErrorClass        string
	Source            string
	State             State
	Phase             Phase
	Boundary          Boundary
	EffectOrdinal     uint32
	RuntimeGeneration uint64
}

// Config defines bounded supervisor capacity, concurrency, lifetime, and observation.
type Config struct {
	Lifetime context.Context
	Observer Observer
	Capacity int
	Workers  int
}

// Acceptor is the narrow synchronous ownership-transfer boundary.
type Acceptor interface {
	Accept(context.Context, Plan) (Receipt, error)
}

// Receipt is a stable internal correlation result for one accepted effect attempt.
type Receipt struct {
	id         string
	decisionID string
	ordinal    uint32
}

// ID returns the stable internal Decision-ID/ordinal attempt identity.
func (r Receipt) ID() string {
	return r.id
}

// DecisionID returns the accepted correlation-only decision ID.
func (r Receipt) DecisionID() string {
	return r.decisionID
}

// Ordinal returns the accepted bounded effect ordinal.
func (r Receipt) Ordinal() uint32 {
	return r.ordinal
}

// Supervisor synchronously accepts bounded work and owns execution and cleanup.
type Supervisor struct {
	lifetime        context.Context
	cancel          context.CancelFunc
	observer        Observer
	providers       map[string]Provider
	queue           chan *acceptedWork
	idle            chan struct{}
	workersDone     chan struct{}
	capacity        int
	workerCount     int
	inFlight        int
	workersStarted  bool
	shutdown        bool
	mu              sync.Mutex
	workers         sync.WaitGroup
	workersDoneOnce sync.Once
}

type acceptedWork struct {
	supervisor  *Supervisor
	provider    Provider
	work        Work
	plan        Plan
	ownership   chan struct{}
	parentSpan  oteltrace.SpanContext
	deadline    time.Time
	releaseOnce sync.Once
}

// New constructs one supervisor generation with immutable provider bindings.
func New(config Config, bindings ...ProviderBinding) (*Supervisor, error) {
	if config.Capacity <= 0 || config.Workers <= 0 || config.Workers > config.Capacity {
		return nil, errors.New("post-action supervisor requires positive workers no greater than capacity")
	}

	providers, err := bindProviders(bindings)
	if err != nil {
		return nil, err
	}

	lifetime := config.Lifetime
	if lifetime == nil {
		lifetime = context.Background()
	}

	workerLifetime, cancel := context.WithCancel(lifetime)
	idle := make(chan struct{})
	close(idle)

	supervisor := &Supervisor{
		lifetime:    workerLifetime,
		cancel:      cancel,
		observer:    config.Observer,
		providers:   providers,
		queue:       make(chan *acceptedWork, config.Capacity),
		idle:        idle,
		workersDone: make(chan struct{}),
		capacity:    config.Capacity,
		workerCount: config.Workers,
	}

	if err := lifetime.Err(); err != nil {
		supervisor.mu.Lock()
		supervisor.beginShutdownLocked()
		supervisor.mu.Unlock()
	}

	if config.Lifetime != nil && config.Lifetime.Done() != nil && lifetime.Err() == nil {
		go supervisor.stopWithLifetime(config.Lifetime)
	}

	return supervisor, nil
}

// Accept validates, captures, reserves, and synchronously transfers ownership.
func (s *Supervisor) Accept(ctx context.Context, plan Plan) (Receipt, error) {
	if s == nil {
		return Receipt{}, ErrShutdown
	}

	if ctx == nil {
		ctx = context.Background()
	}

	if !plan.valid() {
		return Receipt{}, ErrInvalidPlan
	}

	s.observe(ctx, plan, StateNotStarted, PhaseAcceptance, "")

	if err := ctx.Err(); err != nil {
		s.observe(ctx, plan, StateFailed, PhaseAcceptance, contextErrorClass(err))

		return Receipt{}, err
	}

	accepted, receipt, errorClass, err := s.captureAndQueue(ctx, plan)
	if err != nil {
		s.observe(ctx, plan, StateFailed, PhaseAcceptance, errorClass)

		return Receipt{}, err
	}

	s.observe(ctx, plan, StateAccepted, PhaseAcceptance, "")
	close(accepted.ownership)

	return receipt, nil
}

// captureAndQueue resolves, captures, reserves, and queues work under the shutdown lock.
func (s *Supervisor) captureAndQueue(ctx context.Context, plan Plan) (*acceptedWork, Receipt, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.shutdown {
		return nil, Receipt{}, shutdownErrorClass, ErrShutdown
	}

	if err := s.lifetime.Err(); err != nil {
		s.beginShutdownLocked()

		return nil, Receipt{}, shutdownErrorClass, errors.Join(ErrShutdown, err)
	}

	provider, ok := s.providers[plan.provider]
	if !ok {
		return nil, Receipt{}, "unknown_provider", errors.Join(ErrUnknownProvider, fmt.Errorf("provider %q", plan.provider))
	}

	if s.inFlight >= s.capacity {
		return nil, Receipt{}, "saturated", ErrSaturated
	}

	captured, err := captureProviderWork(ctx, provider, plan.work)
	if err != nil {
		return nil, Receipt{}, contextErrorClass(err), err
	}

	if err := s.lifetime.Err(); err != nil {
		releaseProviderWork(provider, captured)
		s.beginShutdownLocked()

		return nil, Receipt{}, shutdownErrorClass, errors.Join(ErrShutdown, err)
	}

	if err := ctx.Err(); err != nil {
		releaseProviderWork(provider, captured)

		return nil, Receipt{}, contextErrorClass(err), err
	}

	s.startWorkersLocked()
	s.reserveLocked()

	receipt := newReceipt(plan)
	accepted := &acceptedWork{
		supervisor: s,
		provider:   provider,
		work:       captured,
		plan:       plan,
		ownership:  make(chan struct{}),
		parentSpan: oteltrace.SpanContextFromContext(ctx),
		deadline:   capturedDeadline(ctx, plan.deadlineBudget),
	}

	s.queue <- accepted

	return accepted, receipt, "", nil
}

// WaitIdle waits until every accepted work item has completed cleanup.
func (s *Supervisor) WaitIdle(ctx context.Context) error {
	if s == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.Lock()
	idle := s.idle
	s.mu.Unlock()

	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// InFlight returns the current accepted but not yet cleaned work count.
func (s *Supervisor) InFlight() int {
	if s == nil {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.inFlight
}

// IsShutdown reports whether the supervisor no longer accepts ownership.
func (s *Supervisor) IsShutdown() bool {
	if s == nil {
		return true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.shutdown
}

// Shutdown rejects new work, cancels accepted work, drains cleanup, and waits for workers.
func (s *Supervisor) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.Lock()
	s.beginShutdownLocked()
	done := s.workersDone
	s.mu.Unlock()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// beginShutdownLocked closes admission and starts exactly one worker waiter.
func (s *Supervisor) beginShutdownLocked() {
	if s.shutdown {
		return
	}

	s.shutdown = true
	close(s.queue)
	s.cancel()
	s.workersDoneOnce.Do(func() {
		go func() {
			s.workers.Wait()
			close(s.workersDone)
		}()
	})
}

// stopWithLifetime turns service lifetime cancellation into supervisor shutdown.
func (s *Supervisor) stopWithLifetime(lifetime context.Context) {
	<-lifetime.Done()

	_ = s.Shutdown(context.Background())
}

// startWorkersLocked creates the fixed worker set before the first ownership transfer.
func (s *Supervisor) startWorkersLocked() {
	if s.workersStarted {
		return
	}

	s.workersStarted = true
	for range s.workerCount {
		s.workers.Add(1)

		go s.worker()
	}
}

// reserveLocked records one accepted capacity owner and opens a new idle epoch.
func (s *Supervisor) reserveLocked() {
	if s.inFlight == 0 {
		s.idle = make(chan struct{})
	}

	s.inFlight++
}

// worker drains accepted work so shutdown cannot strand capacity or cleanup.
func (s *Supervisor) worker() {
	defer s.workers.Done()

	for accepted := range s.queue {
		s.execute(accepted)
	}
}

// execute waits for finalization and performs exactly one provider invocation.
func (s *Supervisor) execute(accepted *acceptedWork) {
	if accepted == nil {
		return
	}

	defer accepted.release()

	<-accepted.ownership

	executionContext, cancel := context.WithDeadline(s.lifetime, accepted.deadline)
	defer cancel()

	if accepted.parentSpan.IsValid() {
		executionContext = oteltrace.ContextWithSpanContext(executionContext, accepted.parentSpan)
	}

	if err := executionContext.Err(); err != nil {
		s.observe(executionContext, accepted.plan, StateFailed, PhaseExecution, contextErrorClass(err))

		return
	}

	select {
	case <-accepted.plan.executionDone:
	case <-executionContext.Done():
		s.observe(executionContext, accepted.plan, StateFailed, PhaseExecution, contextErrorClass(executionContext.Err()))

		return
	}

	if err := executionContext.Err(); err != nil {
		s.observe(executionContext, accepted.plan, StateFailed, PhaseExecution, contextErrorClass(err))

		return
	}

	tracer := monittrace.New("nauthilus/effect_supervisor")

	executionContext, span := tracer.Start(executionContext, "policy.effect.post_action",
		attribute.String(decision.DecisionIDAttributeName, accepted.plan.DecisionID()),
		attribute.Int64("nauthilus.policy.effect_ordinal", int64(accepted.plan.EffectOrdinal())),
		attribute.String("nauthilus.policy.target", accepted.plan.Target()),
		attribute.String("nauthilus.policy.provider", accepted.plan.Provider()),
		attribute.String("nauthilus.policy.finalization_boundary", string(accepted.plan.Boundary())),
	)
	defer span.End()

	s.observe(executionContext, accepted.plan, StateAttempted, PhaseExecution, "")
	result := executeProviderWork(executionContext, accepted.provider, accepted.work)

	span.SetAttributes(attribute.String("nauthilus.policy.effect_state", string(result.State())))

	if result.State() != StateSucceeded {
		span.SetStatus(codes.Error, "post-action execution did not produce a known success")
	}

	s.observe(executionContext, accepted.plan, result.State(), PhaseExecution, result.ErrorClass())
}

// release performs provider cleanup and capacity release through one idempotent path.
func (accepted *acceptedWork) release() {
	if accepted == nil || accepted.supervisor == nil {
		return
	}

	accepted.releaseOnce.Do(func() {
		releaseProviderWork(accepted.provider, accepted.work)

		accepted.supervisor.mu.Lock()
		accepted.supervisor.inFlight--

		if accepted.supervisor.inFlight == 0 {
			close(accepted.supervisor.idle)
		}
		accepted.supervisor.mu.Unlock()
	})
}

// observe isolates supervisor correctness from observer panics.
func (s *Supervisor) observe(ctx context.Context, plan Plan, state State, phase Phase, errorClass string) {
	if s == nil || s.observer == nil {
		return
	}

	defer func() {
		_ = recover()
	}()

	s.observer.Observe(ctx, Event{
		DecisionID:        plan.DecisionID(),
		EffectOrdinal:     plan.EffectOrdinal(),
		Target:            plan.Target(),
		Provider:          plan.Provider(),
		RuntimeGeneration: plan.Observability().RuntimeGeneration,
		Source:            plan.Observability().Source,
		Boundary:          plan.Boundary(),
		State:             state,
		Phase:             phase,
		ErrorClass:        safeErrorClass(errorClass),
	})
}

// bindProviders validates and copies one immutable provider registry.
func bindProviders(bindings []ProviderBinding) (map[string]Provider, error) {
	providers := make(map[string]Provider, len(bindings))

	for _, binding := range bindings {
		if !validProvider(binding.Name) || binding.Provider == nil {
			return nil, errors.New("post-action provider binding is invalid")
		}

		if _, exists := providers[binding.Name]; exists {
			return nil, fmt.Errorf("duplicate post-action provider %q", binding.Name)
		}

		providers[binding.Name] = binding.Provider
	}

	return providers, nil
}

// captureProviderWork contains provider capture panics before ownership transfer.
func captureProviderWork(ctx context.Context, provider Provider, work Work) (captured Work, err error) {
	defer func() {
		if recover() != nil {
			captured = nil
			err = ErrProviderPanic
		}
	}()

	return provider.Capture(ctx, work)
}

// executeProviderWork contains a provider panic and validates its bounded result.
func executeProviderWork(ctx context.Context, provider Provider, work Work) (result Result) {
	defer func() {
		if recover() != nil {
			result = Failed("panic")
		}
	}()

	result = provider.Execute(ctx, work)
	if result.State() != StateSucceeded && result.State() != StateFailed && result.State() != StateOutcomeUnknown {
		return Failed("invalid_result")
	}

	return result
}

// releaseProviderWork contains cleanup panics while preserving capacity release.
func releaseProviderWork(provider Provider, work Work) {
	defer func() {
		_ = recover()
	}()

	provider.Release(work)
}

// capturedDeadline preserves the earlier caller deadline without retaining caller cancellation.
func capturedDeadline(ctx context.Context, budget time.Duration) time.Time {
	deadline := time.Now().Add(budget)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		return callerDeadline
	}

	return deadline
}

// newReceipt derives the internal attempt identity from Decision ID and ordinal.
func newReceipt(plan Plan) Receipt {
	ordinal := fmt.Sprintf("%d", plan.EffectOrdinal())

	return Receipt{
		id:         plan.DecisionID() + receiptOrdinalSeparator + ordinal,
		decisionID: plan.DecisionID(),
		ordinal:    plan.EffectOrdinal(),
	}
}

// safeErrorClass reduces provider and lifecycle failures to bounded classes.
func safeErrorClass(errorClass string) string {
	if errorClass == "" {
		return ""
	}

	if len(errorClass) > maximumMetadataLength || !validProvider(errorClass) {
		return providerErrorClass
	}

	return errorClass
}

// contextErrorClass maps context termination without serializing raw errors.
func contextErrorClass(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, ErrProviderPanic):
		return "panic"
	default:
		return providerErrorClass
	}
}
