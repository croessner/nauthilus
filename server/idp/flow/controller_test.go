// Copyright (C) 2025 Christian Rößner
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

package flow

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memoryStore struct {
	state *State
}

func (m *memoryStore) Load(_ context.Context, _ string) (*State, error) { return m.state, nil }
func (m *memoryStore) Save(_ context.Context, state *State) error {
	m.state = state

	return nil
}
func (m *memoryStore) Delete(_ context.Context, _ string) error {
	m.state = nil

	return nil
}
func (m *memoryStore) TouchTTL(context.Context, string, time.Duration) error { return nil }

func TestControllerPreviewStart(t *testing.T) {
	controller := NewController(nil)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	decision, err := controller.PreviewStart(&State{
		FlowID:       "f-1",
		FlowType:     FlowTypeOIDCAuthorization,
		Protocol:     FlowProtocolOIDC,
		CurrentStep:  FlowStepStart,
		ReturnTarget: "/login",
	}, now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if decision.Type != DecisionTypeRedirect || decision.RedirectURI != "/login" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestControllerStartRequiresStore(t *testing.T) {
	controller := NewController(nil)

	_, err := controller.Start(t.Context(), &State{
		FlowID:      "f-1",
		FlowType:    FlowTypeOIDCAuthorization,
		Protocol:    FlowProtocolOIDC,
		CurrentStep: FlowStepStart,
	}, time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestControllerStartSavesState(t *testing.T) {
	store := &memoryStore{}
	controller := NewController(store)
	state := &State{
		FlowID:      "f-1",
		FlowType:    FlowTypeOIDCAuthorization,
		Protocol:    FlowProtocolOIDC,
		CurrentStep: FlowStepStart,
	}

	if _, err := controller.Start(t.Context(), state, time.Now()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.state == nil || store.state.FlowID != "f-1" {
		t.Fatal("state was not saved")
	}
}

func TestControllerAdvanceRejectsInvalidTransition(t *testing.T) {
	store := &memoryStore{state: &State{
		FlowID:      "f-1",
		FlowType:    FlowTypeOIDCAuthorization,
		Protocol:    FlowProtocolOIDC,
		CurrentStep: FlowStepLogin,
	}}
	controller := NewController(store)

	_, err := controller.Advance(t.Context(), "f-1", FlowStepDone, time.Now())
	if err == nil {
		t.Fatal("expected transition error")
	}

	var transitionErr TransitionError
	if !errors.As(err, &transitionErr) {
		t.Fatalf("expected transition error, got: %v", err)
	}
}

func TestControllerRecoverInvalidTransitionAbortsFlow(t *testing.T) {
	store := &memoryStore{state: &State{
		FlowID:      "f-1",
		FlowType:    FlowTypeOIDCAuthorization,
		Protocol:    FlowProtocolOIDC,
		CurrentStep: FlowStepLogin,
	}}
	controller := NewController(store)

	recoveryDecision, err := controller.Recover(
		t.Context(),
		"f-1",
		TransitionError{FlowType: FlowTypeOIDCAuthorization, From: FlowStepLogin, To: FlowStepCallback, Action: FlowActionAdvance},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if recoveryDecision.Type != DecisionTypeRedirect || recoveryDecision.RedirectURI != defaultStartURI {
		t.Fatalf("unexpected recovery decision: %+v", recoveryDecision)
	}

	if recoveryDecision.Reason != reasonInvalidTransitionRecovered {
		t.Fatalf("unexpected recovery reason: %s", recoveryDecision.Reason)
	}

	if store.state != nil {
		t.Fatal("expected flow state to be deleted after invalid transition recovery")
	}
}

func TestControllerAdvanceStaleFlowID(t *testing.T) {
	controller := NewController(&memoryStore{})

	_, err := controller.Advance(t.Context(), "stale-flow", FlowStepLogin, time.Now())
	if !errors.Is(err, ErrFlowNotFound) {
		t.Fatalf("expected ErrFlowNotFound, got: %v", err)
	}
}

func TestControllerRecoverStaleFlowID(t *testing.T) {
	controller := NewController(&memoryStore{})

	recoveryDecision, err := controller.Recover(t.Context(), "stale-flow", ErrFlowNotFound)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if recoveryDecision.Type != DecisionTypeRedirect || recoveryDecision.RedirectURI != defaultStartURI {
		t.Fatalf("unexpected recovery decision: %+v", recoveryDecision)
	}

	if recoveryDecision.Reason != reasonStaleFlowRecovered {
		t.Fatalf("unexpected recovery reason: %s", recoveryDecision.Reason)
	}
}
