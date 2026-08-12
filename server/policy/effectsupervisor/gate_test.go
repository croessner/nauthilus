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
	"testing"
	"time"
)

func TestHTTPGateOpensOnlyAfterApplicationResponseCommit(t *testing.T) {
	provider := &recordingProvider{invoked: make(chan struct{}, 1)}
	supervisor := newTestSupervisor(t, 1, 1, provider, nil)
	gate := newTestGate(t, BoundaryHTTPCommit)
	plan := newTestPlan(t, testProviderID, newTestWork("http"), gate)

	if _, err := supervisor.Accept(context.Background(), plan); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}

	handlerReturned := true
	if !handlerReturned {
		t.Fatal("test setup did not return from the HTTP handler")
	}

	select {
	case <-provider.invoked:
		t.Fatal("HTTP post-action started before response commit")
	case <-time.After(25 * time.Millisecond):
	}

	responseCommitted := true

	gate.Complete()
	waitForIdle(t, supervisor)

	if !responseCommitted {
		t.Fatal("HTTP gate opened without a committed response")
	}
}

func TestGRPCGateOpensAtUnaryReturnAndIgnoresLaterSerializationFailure(t *testing.T) {
	observer := &recordingEffectObserver{}
	provider := &recordingProvider{invoked: make(chan struct{}, 1)}
	supervisor := newTestSupervisor(t, 1, 1, provider, observer)
	gate := newTestGate(t, BoundaryGRPCUnaryReturn)
	plan := newTestPlan(t, testProviderID, newTestWork("grpc"), gate)
	decision := "permit"

	if _, err := supervisor.Accept(context.Background(), plan); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}

	returnedResponse := decision

	gate.Complete()

	select {
	case <-provider.invoked:
	case <-time.After(time.Second):
		t.Fatal("gRPC post-action did not start after unary handler return")
	}

	serializationError := errors.New("codec failed after unary return")
	if serializationError == nil {
		t.Fatal("test setup did not produce serialization failure")
	}

	waitForIdle(t, supervisor)

	if decision != returnedResponse {
		t.Fatalf("finalized decision changed after serialization failure: got %q want %q", decision, returnedResponse)
	}

	if !observer.sawState(StateSucceeded) {
		t.Fatalf("events = %#v, want internally known succeeded outcome", observer.eventsCopy())
	}

	if observer.sawState(StateOutcomeUnknown) {
		t.Fatal("client transport failure was misclassified as provider outcome_unknown")
	}
}

func TestFinalizationGateCompletionIsIdempotentAndTyped(t *testing.T) {
	gate := newTestGate(t, BoundaryGRPCUnaryReturn)

	gate.Complete()
	gate.Complete()

	if gate.Boundary() != BoundaryGRPCUnaryReturn {
		t.Fatalf("boundary = %q, want %q", gate.Boundary(), BoundaryGRPCUnaryReturn)
	}

	select {
	case <-gate.Done():
	default:
		t.Fatal("completed gate remained open")
	}
}

func TestPlanCapturesFinalizationGateByValue(t *testing.T) {
	provider := &recordingProvider{invoked: make(chan struct{}, 1)}
	supervisor := newTestSupervisor(t, 1, 1, provider, nil)
	originalDone := make(chan struct{})
	gate := &mutableFinalizationGate{done: originalDone, boundary: BoundaryHTTPCommit}
	plan := newTestPlan(t, testProviderID, newTestWork("captured-gate"), gate)
	gate.done = make(chan struct{})
	gate.boundary = BoundaryGRPCUnaryReturn

	if plan.Boundary() != BoundaryHTTPCommit {
		t.Fatalf("captured boundary = %q, want %q", plan.Boundary(), BoundaryHTTPCommit)
	}

	if _, err := supervisor.Accept(context.Background(), plan); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}

	close(originalDone)
	waitForIdle(t, supervisor)

	select {
	case <-provider.invoked:
	default:
		t.Fatal("supervisor did not use the captured finalization channel")
	}
}

type mutableFinalizationGate struct {
	done     <-chan struct{}
	boundary Boundary
}

// Done returns the currently configured mutable test channel.
func (g *mutableFinalizationGate) Done() <-chan struct{} {
	return g.done
}

// Boundary returns the currently configured mutable test boundary.
func (g *mutableFinalizationGate) Boundary() Boundary {
	return g.boundary
}

// newTestGate constructs one typed application-response finalization gate.
func newTestGate(t *testing.T, boundary Boundary) *Gate {
	t.Helper()

	gate, err := NewGate(boundary)
	if err != nil {
		t.Fatalf("NewGate() error = %v", err)
	}

	return gate
}

// completedTestGate returns an already-open HTTP commit boundary.
func completedTestGate(t *testing.T) *Gate {
	t.Helper()

	gate := newTestGate(t, BoundaryHTTPCommit)
	gate.Complete()

	return gate
}
