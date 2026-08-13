// Copyright (C) 2026 Christian Rößner
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

package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
)

type testGenerationExecutableWork struct {
	cleanups atomic.Int64
}

type testGenerationPostActionProvider struct {
	work *testGenerationExecutableWork
}

type blockingGenerationPostActionProvider struct {
	work    *testGenerationExecutableWork
	started chan<- struct{}
	release <-chan struct{}
}

type blockingGenerationFactProvider struct {
	started chan<- struct{}
	release <-chan struct{}
}

type blockingGenerationSyncEffectProvider struct {
	started chan<- struct{}
	release <-chan struct{}
}

type luaPreparedGenerationResource struct {
	disposals atomic.Int64
	closed    atomic.Bool
}

type failingGenerationResource struct {
	err error
}

type contextSensitiveGenerationResource struct {
	disposals atomic.Int64
	closed    atomic.Bool
	deadline  atomic.Bool
}

type blockingCleanupGenerationResource struct {
	started   chan<- struct{}
	release   <-chan struct{}
	disposals atomic.Int64
}

// Validate accepts the immutable test work.
func (*testGenerationExecutableWork) Validate() error {
	return nil
}

// Execute reports successful test work execution.
func (*testGenerationExecutableWork) Execute(context.Context) effectsupervisor.Result {
	return effectsupervisor.Succeeded()
}

// Cleanup records provider-owned cleanup calls.
func (w *testGenerationExecutableWork) Cleanup() {
	w.cleanups.Add(1)
}

// Prepare returns one immutable executable test owner.
func (p *testGenerationPostActionProvider) Prepare(
	context.Context,
	EffectExecution,
) (effectsupervisor.Work, error) {
	return p.work, nil
}

// Prepare keeps provider preparation in flight after request cancellation.
func (p *blockingGenerationPostActionProvider) Prepare(
	context.Context,
	EffectExecution,
) (effectsupervisor.Work, error) {
	close(p.started)
	<-p.release

	return p.work, nil
}

// Collect keeps one fact-provider call in flight after evaluation cancellation.
func (p *blockingGenerationFactProvider) Collect(
	context.Context,
	FactProviderInput,
) ([]ProvidedFact, error) {
	close(p.started)
	<-p.release

	return nil, nil
}

// Execute keeps one synchronous effect call in flight after evaluation cancellation.
func (p *blockingGenerationSyncEffectProvider) Execute(
	context.Context,
	EffectExecution,
) effectsupervisor.Result {
	close(p.started)
	<-p.release

	return effectsupervisor.Succeeded()
}

// Dispose closes the fake prepared Lua owner exactly once through generation ownership.
func (r *luaPreparedGenerationResource) Dispose(context.Context) error {
	r.closed.Store(true)
	r.disposals.Add(1)

	return nil
}

// use verifies that the prepared Lua owner remains valid for captured work.
func (r *luaPreparedGenerationResource) use() error {
	if r.closed.Load() {
		return errors.New("prepared Lua resource is closed")
	}

	return nil
}

// Dispose injects one explicit retirement failure.
func (r *failingGenerationResource) Dispose(context.Context) error {
	return r.err
}

// Dispose refuses canceled cleanup so tests can detect reused operation contexts.
func (r *contextSensitiveGenerationResource) Dispose(ctx context.Context) error {
	r.disposals.Add(1)

	_, hasDeadline := ctx.Deadline()
	r.deadline.Store(hasDeadline)

	if err := ctx.Err(); err != nil {
		return err
	}

	r.closed.Store(true)

	return nil
}

// Dispose blocks independently of shutdown waiting cancellation until the test releases it.
func (r *blockingCleanupGenerationResource) Dispose(context.Context) error {
	r.disposals.Add(1)
	close(r.started)
	<-r.release

	return nil
}

// TestGenerationCaptureDefersRetirementUntilEveryUserReleases proves final-user ownership.
func TestGenerationCaptureDefersRetirementUntilEveryUserReleases(t *testing.T) {
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)

	if _, err := coordinator.Apply(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     1,
	}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	oldResources := fixtureResources(fixture)
	started, release, results := startGenerationCaptureUsers(store, oldResources, 2)

	<-started
	<-started

	fixture.marker = testNewMarker
	fixture.resetResources()

	if _, err := coordinator.Apply(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     2,
	}); err != nil {
		t.Fatalf("replacement Apply() error = %v", err)
	}

	assertResourceDisposals(t, oldResources, 0)

	release <- struct{}{}

	if err := <-results; err != nil {
		t.Fatalf("first WithActive() error = %v", err)
	}

	assertResourceDisposals(t, oldResources, 0)

	release <- struct{}{}

	if err := <-results; err != nil {
		t.Fatalf("second WithActive() error = %v", err)
	}

	assertResourceDisposals(t, oldResources, 1)
}

// startGenerationCaptureUsers holds concurrent old-generation users behind one release gate.
func startGenerationCaptureUsers(
	store *GenerationStore,
	resources []*countingCandidateResource,
	count int,
) (<-chan struct{}, chan<- struct{}, <-chan error) {
	started := make(chan struct{}, count)
	release := make(chan struct{})
	results := make(chan error, count)

	for range count {
		go func() {
			results <- store.WithActive(context.Background(), func(generation *Generation) error {
				if generation.ID() != 1 {
					return fmt.Errorf("captured generation = %d, want 1", generation.ID())
				}

				started <- struct{}{}

				<-release

				return resourceDisposalsError(resources, 0)
			})
		}()
	}

	return started, release, results
}

// TestGenerationCaptureCancellationReleasesRetiredResources proves canceled users cannot leak leases.
func TestGenerationCaptureCancellationReleasesRetiredResources(t *testing.T) {
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)

	if _, err := coordinator.Apply(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     1,
	}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	oldResources := fixtureResources(fixture)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan error, 1)

	go func() {
		result <- store.WithActive(ctx, func(*Generation) error {
			close(started)
			<-ctx.Done()

			return ctx.Err()
		})
	}()

	<-started

	fixture.marker = testNewMarker
	fixture.resetResources()

	if _, err := coordinator.Apply(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     2,
	}); err != nil {
		t.Fatalf("replacement Apply() error = %v", err)
	}

	assertResourceDisposals(t, oldResources, 0)
	cancel()

	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("WithActive() error = %v, want context canceled", err)
	}

	assertResourceDisposals(t, oldResources, 1)
}

// TestGenerationLuaPreparedResourceRemainsUsableUntilCapturedRelease proves Lua lifetime ownership.
func TestGenerationLuaPreparedResourceRemainsUsableUntilCapturedRelease(t *testing.T) {
	resource := &luaPreparedGenerationResource{}
	resources := &candidateResourceOwnership{}
	resources.add(resource)

	lifetime := newGenerationLifetime(1, resources, nil)
	lease := lifetime.acquireCapture()

	if lease == nil {
		t.Fatal("initial generation capture was rejected")
	}

	if err := lifetime.retire(context.Background()); err != nil {
		t.Fatalf("retire() error = %v", err)
	}

	if err := resource.use(); err != nil {
		t.Fatalf("captured prepared Lua use error = %v", err)
	}

	if err := lease.release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}

	if err := lease.release(); err != nil {
		t.Fatalf("repeated release() error = %v", err)
	}

	if !resource.closed.Load() || resource.disposals.Load() != 1 {
		t.Fatalf(
			"prepared Lua closed/disposals = %t/%d, want true/1",
			resource.closed.Load(),
			resource.disposals.Load(),
		)
	}
}

// TestGenerationFailedCandidateDoesNotRetireActiveResources proves candidate isolation after leases land.
func TestGenerationFailedCandidateDoesNotRetireActiveResources(t *testing.T) {
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)

	if _, err := coordinator.Apply(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     1,
	}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	active := store.Active()
	activeResources := fixtureResources(fixture)
	fixture.marker = testNewMarker
	fixture.failAt = "application"
	fixture.resetResources()

	if _, err := coordinator.Apply(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     2,
	}); err == nil {
		t.Fatal("failed candidate Apply() error = nil")
	}

	if store.Active() != active {
		t.Fatal("failed candidate changed the active generation")
	}

	assertResourceDisposals(t, activeResources, 0)

	if err := store.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	assertResourceDisposals(t, activeResources, 1)
}

// TestGenerationRetirementPreservesResourceCloseFailure proves unsuccessful close is never hidden.
func TestGenerationRetirementPreservesResourceCloseFailure(t *testing.T) {
	closeFailure := errors.New("injected generation close failure")
	oldResources := &candidateResourceOwnership{}
	oldResources.add(&failingGenerationResource{err: closeFailure})
	oldGeneration := &Generation{
		id:       1,
		lifetime: newGenerationLifetime(1, oldResources, nil),
	}
	newResources := &candidateResourceOwnership{}
	newGeneration := &Generation{
		id:       2,
		lifetime: newGenerationLifetime(2, newResources, nil),
	}
	store := NewGenerationStore()

	if committed, err := store.commit(context.Background(), nil, oldGeneration); !committed || err != nil {
		t.Fatalf("initial commit = %t/%v, want true/nil", committed, err)
	}

	if committed, err := store.commit(context.Background(), oldGeneration, newGeneration); !committed ||
		!errors.Is(err, closeFailure) {
		t.Fatalf("replacement commit = %t/%v, want committed close failure", committed, err)
	}

	if err := store.RetirementError(); !errors.Is(err, ErrGenerationRetirement) ||
		!errors.Is(err, closeFailure) {
		t.Fatalf("RetirementError() = %v, want retained close failure", err)
	}

	if err := store.Shutdown(context.Background()); !errors.Is(err, ErrGenerationRetirement) ||
		!errors.Is(err, closeFailure) {
		t.Fatalf("Shutdown() error = %v, want retained close failure", err)
	}
}

// TestGenerationCoordinatorReportsCommittedRetirementFailure proves public commit visibility.
func TestGenerationCoordinatorReportsCommittedRetirementFailure(t *testing.T) {
	closeFailure := errors.New("injected committed retirement failure")
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	fixture.disposeErr = closeFailure
	coordinator := fixture.coordinator(store)

	if _, err := coordinator.Apply(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     1,
	}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	fixture.marker = testNewMarker
	fixture.disposeErr = nil
	fixture.resetResources()

	committed, err := coordinator.Apply(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     2,
	})
	if committed == nil || committed.ID() != 2 || store.Active() != committed {
		t.Fatal("replacement was not atomically committed before retirement reporting")
	}

	if !errors.Is(err, ErrGenerationRetirement) || !errors.Is(err, closeFailure) {
		t.Fatalf("replacement Apply() error = %v, want committed retirement failure", err)
	}
}

// TestGenerationRetirementKeepsFirstCleanupContext prevents shutdown cancellation from poisoning close.
func TestGenerationRetirementKeepsFirstCleanupContext(t *testing.T) {
	resource := &contextSensitiveGenerationResource{}
	resources := &candidateResourceOwnership{}
	resources.add(resource)
	lifetime := newGenerationLifetime(1, resources, nil)
	lease := lifetime.acquireCapture()

	if lease == nil {
		t.Fatal("initial generation capture was rejected")
	}

	if err := lifetime.retire(context.Background()); err != nil {
		t.Fatalf("initial retire() error = %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	if err := lifetime.retire(canceled); err != nil {
		t.Fatalf("repeated retire() error = %v", err)
	}

	if err := lease.release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}

	if !resource.closed.Load() || !resource.deadline.Load() || resource.disposals.Load() != 1 {
		t.Fatalf(
			"cleanup closed/deadline/disposals = %t/%t/%d, want true/true/1",
			resource.closed.Load(),
			resource.deadline.Load(),
			resource.disposals.Load(),
		)
	}
}

// TestGenerationCandidateCleanupIgnoresCanceledOperationContext proves cleanup is not best effort.
func TestGenerationCandidateCleanupIgnoresCanceledOperationContext(t *testing.T) {
	resource := &contextSensitiveGenerationResource{}
	resources := &candidateResourceOwnership{}
	resources.add(resource)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	if err := resources.dispose(canceled); err != nil {
		t.Fatalf("dispose() error = %v", err)
	}

	if !resource.closed.Load() || !resource.deadline.Load() || resource.disposals.Load() != 1 {
		t.Fatalf(
			"cleanup closed/deadline/disposals = %t/%t/%d, want true/true/1",
			resource.closed.Load(),
			resource.deadline.Load(),
			resource.disposals.Load(),
		)
	}
}

// TestGenerationDiscardCannotCloseResourcesDuringValidation proves exclusive candidate ownership.
func TestGenerationDiscardCannotCloseResourcesDuringValidation(t *testing.T) {
	var resources []*countingCandidateResource

	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)
	started := make(chan struct{})
	release := make(chan struct{})

	coordinator.slots.Validators = []GenerationValidator{GenerationValidationFunc(
		func(context.Context, *Generation) error {
			close(started)
			<-release

			return resourceDisposalsError(resources, 0)
		},
	)}

	candidate, err := coordinator.Prepare(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     1,
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	resources = fixtureResources(fixture)
	validationDone := make(chan error, 1)

	go func() {
		validationDone <- coordinator.Validate(context.Background(), candidate)
	}()

	<-started

	discardErr := coordinator.Discard(context.Background(), candidate)

	close(release)

	validationErr := <-validationDone

	if !errors.Is(discardErr, ErrCandidateConsumed) {
		t.Fatalf("concurrent Discard() error = %v, want ErrCandidateConsumed", discardErr)
	}

	if validationErr != nil {
		t.Fatalf("Validate() error = %v", validationErr)
	}

	assertResourceDisposals(t, resources, 0)

	if err = coordinator.Discard(context.Background(), candidate); err != nil {
		t.Fatalf("post-validation Discard() error = %v", err)
	}

	assertResourceDisposals(t, resources, 1)
}

// TestGenerationPostActionLeaseKeepsRetiredResourcesUsable proves detached-effect ownership.
func TestGenerationPostActionLeaseKeepsRetiredResourcesUsable(t *testing.T) {
	resource := &countingCandidateResource{}
	resources := &candidateResourceOwnership{}
	resources.add(resource)

	lifetime := newGenerationLifetime(1, resources, nil)
	requestLease := lifetime.acquireCapture()

	if requestLease == nil {
		t.Fatal("initial generation capture was rejected")
	}

	work := &testGenerationExecutableWork{}

	bindings, err := NewBindingSet(BindingSetInput{
		PostActions: map[string]PostActionProvider{
			"test/post_action": &testGenerationPostActionProvider{work: work},
		},
		PostActionAcceptance: &rejectingTestAcceptor{},
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	captured := bindings.withGenerationLifetime(lifetime)

	prepared, err := captured.PostActions()["test/post_action"].Prepare(context.Background(), EffectExecution{})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if err = lifetime.retire(context.Background()); err != nil {
		t.Fatalf("retire() error = %v", err)
	}

	if err = requestLease.release(); err != nil {
		t.Fatalf("request release error = %v", err)
	}

	assertResourceDisposals(t, []*countingCandidateResource{resource}, 0)

	executable, ok := prepared.(effectsupervisor.ExecutableWork)
	if !ok {
		t.Fatal("prepared work does not retain executable cleanup ownership")
	}

	executable.Cleanup()
	executable.Cleanup()

	assertResourceDisposals(t, []*countingCandidateResource{resource}, 1)

	if got := work.cleanups.Load(); got != 1 {
		t.Fatalf("underlying work cleanup count = %d, want 1", got)
	}
}

// TestGenerationPostActionPreparationLeaseSurvivesRequestCancellation covers abandoned preparation.
func TestGenerationPostActionPreparationLeaseSurvivesRequestCancellation(t *testing.T) {
	resource := &countingCandidateResource{}
	resources := &candidateResourceOwnership{}
	resources.add(resource)

	lifetime := newGenerationLifetime(1, resources, nil)
	requestLease := lifetime.acquireCapture()

	if requestLease == nil {
		t.Fatal("initial generation capture was rejected")
	}

	started := make(chan struct{})
	release := make(chan struct{})
	work := &testGenerationExecutableWork{}

	bindings, err := NewBindingSet(BindingSetInput{
		PostActions: map[string]PostActionProvider{
			"test/post_action": &blockingGenerationPostActionProvider{
				work: work, started: started, release: release,
			},
		},
		PostActionAcceptance: &rejectingTestAcceptor{},
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	preparedResult := make(chan effectsupervisor.Work, 1)

	go func() {
		prepared, _ := bindings.withGenerationLifetime(lifetime).
			PostActions()["test/post_action"].Prepare(context.Background(), EffectExecution{})
		preparedResult <- prepared
	}()

	<-started

	if err = lifetime.retire(context.Background()); err != nil {
		t.Fatalf("retire() error = %v", err)
	}

	if err = requestLease.release(); err != nil {
		t.Fatalf("request release error = %v", err)
	}

	assertResourceDisposals(t, []*countingCandidateResource{resource}, 0)
	close(release)

	prepared := <-preparedResult

	assertResourceDisposals(t, []*countingCandidateResource{resource}, 0)

	executable, ok := prepared.(effectsupervisor.ExecutableWork)
	if !ok {
		t.Fatal("prepared work does not retain executable cleanup ownership")
	}

	executable.Cleanup()
	assertResourceDisposals(t, []*countingCandidateResource{resource}, 1)
}

// TestGenerationFactProviderCallLeaseSurvivesCheckpointCancellation proves pre-spawn capture.
func TestGenerationFactProviderCallLeaseSurvivesCheckpointCancellation(t *testing.T) {
	lifetime, requestLease, resource := newCountingGenerationCapture(t)
	started := make(chan struct{})
	release := make(chan struct{})

	bindings, err := NewBindingSet(BindingSetInput{
		FactProviders: map[string]FactProviderBinding{
			"test/facts": {
				Provider:  &blockingGenerationFactProvider{started: started, release: release},
				Source:    decision.FactSourcePlugin,
				Authority: "test",
				Component: "test/facts",
			},
		},
		PostActionAcceptance: &rejectingTestAcceptor{},
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	provider := bindings.withGenerationLifetime(lifetime).FactProviders()["test/facts"].Provider
	capturer := provider.(interface {
		CaptureFactProviderCall() (FactProvider, error)
	})

	captured, err := capturer.CaptureFactProviderCall()
	if err != nil {
		t.Fatalf("CaptureFactProviderCall() error = %v", err)
	}

	done := make(chan struct{})

	go func() {
		_, _ = captured.Collect(context.Background(), FactProviderInput{})

		close(done)
	}()

	<-started
	retireCapturedGeneration(t, lifetime, requestLease)
	assertResourceDisposals(t, []*countingCandidateResource{resource}, 0)
	close(release)
	<-done
	assertResourceDisposals(t, []*countingCandidateResource{resource}, 1)
}

// TestGenerationSyncEffectCallLeaseSurvivesCheckpointCancellation proves pre-spawn capture.
func TestGenerationSyncEffectCallLeaseSurvivesCheckpointCancellation(t *testing.T) {
	lifetime, requestLease, resource := newCountingGenerationCapture(t)
	started := make(chan struct{})
	release := make(chan struct{})

	bindings, err := NewBindingSet(BindingSetInput{
		SyncEffects: map[string]SyncEffectProvider{
			"test/sync": &blockingGenerationSyncEffectProvider{started: started, release: release},
		},
		PostActionAcceptance: &rejectingTestAcceptor{},
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	provider := bindings.withGenerationLifetime(lifetime).SyncEffects()["test/sync"]
	capturer := provider.(interface {
		CaptureSyncEffectCall() (SyncEffectProvider, error)
	})

	captured, err := capturer.CaptureSyncEffectCall()
	if err != nil {
		t.Fatalf("CaptureSyncEffectCall() error = %v", err)
	}

	done := make(chan struct{})

	go func() {
		_ = captured.Execute(context.Background(), EffectExecution{})

		close(done)
	}()

	<-started
	retireCapturedGeneration(t, lifetime, requestLease)
	assertResourceDisposals(t, []*countingCandidateResource{resource}, 0)
	close(release)
	<-done
	assertResourceDisposals(t, []*countingCandidateResource{resource}, 1)
}

// TestGenerationShutdownIsIdempotentAndWaitsForCapturedUsers proves cancellation and retry safety.
func TestGenerationShutdownIsIdempotentAndWaitsForCapturedUsers(t *testing.T) {
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)

	if _, err := coordinator.Apply(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     1,
	}); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	resources := fixtureResources(fixture)
	started := make(chan struct{})
	release := make(chan struct{})
	useDone := make(chan error, 1)

	go func() {
		useDone <- store.WithActive(context.Background(), func(*Generation) error {
			close(started)
			<-release

			return nil
		})
	}()

	<-started

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := store.Shutdown(shutdownCtx)

	cancel()

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Shutdown() error = %v, want deadline exceeded", err)
	}

	assertIncompleteGenerationDrain(t, err)

	if store.Active() != nil {
		t.Fatal("Shutdown() retained an active generation pointer")
	}

	assertResourceDisposals(t, resources, 0)
	close(release)

	if err = <-useDone; err != nil {
		t.Fatalf("WithActive() error = %v", err)
	}

	if err = store.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown() error = %v", err)
	}

	if err = store.Shutdown(context.Background()); err != nil {
		t.Fatalf("third Shutdown() error = %v", err)
	}

	assertResourceDisposals(t, resources, 1)
}

// assertIncompleteGenerationDrain checks the private structural shutdown marker.
func assertIncompleteGenerationDrain(t *testing.T, err error) {
	t.Helper()

	var incomplete interface {
		GenerationDrainIncomplete() bool
	}

	if !errors.As(err, &incomplete) || !incomplete.GenerationDrainIncomplete() {
		t.Fatalf("Shutdown() error = %v, want incomplete drain marker", err)
	}
}

// TestGenerationShutdownCancellationDoesNotCancelStartedCleanup separates waiting from disposal.
func TestGenerationShutdownCancellationDoesNotCancelStartedCleanup(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	resource := &blockingCleanupGenerationResource{started: started, release: release}
	resources := &candidateResourceOwnership{}
	resources.add(resource)
	generation := &Generation{id: 1, lifetime: newGenerationLifetime(1, resources, nil)}
	store := NewGenerationStore()

	if committed, err := store.commit(context.Background(), nil, generation); !committed || err != nil {
		t.Fatalf("initial commit = %t/%v, want true/nil", committed, err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- store.Shutdown(shutdownCtx)
	}()

	<-started

	if err := <-shutdownDone; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Shutdown() error = %v, want deadline exceeded", err)
	}

	close(release)

	if err := store.Shutdown(context.Background()); err != nil {
		t.Fatalf("retry Shutdown() error = %v", err)
	}

	if got := resource.disposals.Load(); got != 1 {
		t.Fatalf("cleanup disposal count = %d, want 1", got)
	}
}

// TestGenerationShutdownAlreadyCanceledEmptyStoreCompletes makes completed drain win over caller cancellation.
func TestGenerationShutdownAlreadyCanceledEmptyStoreCompletes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for iteration := 0; iteration < 100; iteration++ {
		store := NewGenerationStore()

		if err := store.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown() iteration %d error = %v, want completed empty drain", iteration, err)
		}
	}
}

// TestGenerationRepeatedReloadRetireAndShutdownClosesEveryResourceOnce covers leak-prone interleavings.
func TestGenerationRepeatedReloadRetireAndShutdownClosesEveryResourceOnce(t *testing.T) {
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)
	allResources := make([]*countingCandidateResource, 0, 64)

	for id := uint64(1); id <= 16; id++ {
		if id > 1 {
			fixture.marker = fmt.Sprintf("generation-%d", id)
		}

		fixture.resetResources()

		if _, err := coordinator.Apply(context.Background(), PrepareInput{
			Config: &config.FileSettings{},
			ID:     id,
		}); err != nil {
			t.Fatalf("Apply(%d) error = %v", id, err)
		}

		allResources = append(allResources, fixtureResources(fixture)...)
	}

	if err := store.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	assertResourceDisposals(t, allResources, 1)
}

// fixtureResources returns the current detached candidate-resource batch.
func fixtureResources(fixture *generationFixture) []*countingCandidateResource {
	fixture.resourcesMu.Lock()
	defer fixture.resourcesMu.Unlock()

	return append([]*countingCandidateResource(nil), fixture.resources...)
}

// assertResourceDisposals checks every test resource without duplicating count logic.
func assertResourceDisposals(t *testing.T, resources []*countingCandidateResource, want int64) {
	t.Helper()

	for index, resource := range resources {
		if got := resource.disposals.Load(); got != want {
			t.Fatalf("resource %d disposal count = %d, want %d", index, got, want)
		}
	}
}

// resourceDisposalsError reports a synchronized count mismatch without calling testing from workers.
func resourceDisposalsError(resources []*countingCandidateResource, want int64) error {
	for index, resource := range resources {
		if got := resource.disposals.Load(); got != want {
			return fmt.Errorf("resource %d disposal count = %d, want %d", index, got, want)
		}
	}

	return nil
}

// newCountingGenerationCapture returns one active request lease and observable resource.
func newCountingGenerationCapture(
	t *testing.T,
) (*generationLifetime, *generationLease, *countingCandidateResource) {
	t.Helper()

	resource := &countingCandidateResource{}
	resources := &candidateResourceOwnership{}
	resources.add(resource)
	lifetime := newGenerationLifetime(1, resources, nil)
	lease := lifetime.acquireCapture()

	if lease == nil {
		t.Fatal("initial generation capture was rejected")
	}

	return lifetime, lease, resource
}

// retireCapturedGeneration retires one lifetime and idempotently releases its request lease.
func retireCapturedGeneration(
	t *testing.T,
	lifetime *generationLifetime,
	lease *generationLease,
) {
	t.Helper()

	if err := lifetime.retire(context.Background()); err != nil {
		t.Fatalf("retire() error = %v", err)
	}

	if err := lease.release(); err != nil {
		t.Fatalf("request release error = %v", err)
	}
}

// TestGenerationConcurrentCaptureReloadShutdown remains race-clean under overlapping ownership changes.
func TestGenerationConcurrentCaptureReloadShutdown(t *testing.T) {
	store := NewGenerationStore()
	fixture := newGenerationFixture(t, testOldMarker)
	coordinator := fixture.coordinator(store)

	if _, err := coordinator.Apply(context.Background(), PrepareInput{
		Config: &config.FileSettings{},
		ID:     1,
	}); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)

		go func() {
			defer wait.Done()

			for range 100 {
				err := store.WithActive(context.Background(), func(generation *Generation) error {
					if generation.ID() == 0 {
						return ErrInvalidGeneration
					}

					return nil
				})
				if err != nil && !errors.Is(err, ErrGenerationUnavailable) {
					t.Errorf("WithActive() error = %v", err)
				}
			}
		}()
	}

	for id := uint64(2); id <= 8; id++ {
		fixture.marker = fmt.Sprintf("race-%d", id)
		fixture.resetResources()

		if _, err := coordinator.Apply(context.Background(), PrepareInput{
			Config: &config.FileSettings{},
			ID:     id,
		}); err != nil {
			t.Fatalf("Apply(%d) error = %v", id, err)
		}
	}

	if err := store.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	wait.Wait()
}
