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

package flow

import (
	"errors"
	"testing"
	"time"
)

func TestMainFlowSequences_HappyPaths(t *testing.T) {
	now := time.Now().UTC()

	testCases := []struct {
		name      string
		state     *State
		steps     []FlowStep
		flowID    string
		wantFinal string
	}{
		{
			name: "oidc authorization",
			state: &State{
				FlowID:       "flow-oidc-auth",
				FlowType:     FlowTypeOIDCAuthorization,
				Protocol:     FlowProtocolOIDC,
				CurrentStep:  FlowStepStart,
				ReturnTarget: "/oidc/authorize?client_id=app",
			},
			steps:     []FlowStep{FlowStepLogin, FlowStepMFA, FlowStepCallback},
			flowID:    "flow-oidc-auth",
			wantFinal: "/oidc/authorize?client_id=app",
		},
		{
			name: "oidc device",
			state: &State{
				FlowID:       "flow-oidc-device",
				FlowType:     FlowTypeOIDCDeviceCode,
				Protocol:     FlowProtocolOIDC,
				CurrentStep:  FlowStepStart,
				ReturnTarget: "/oidc/device/verify",
			},
			steps:     []FlowStep{FlowStepDeviceVerification, FlowStepLogin, FlowStepCallback},
			flowID:    "flow-oidc-device",
			wantFinal: "/oidc/device/verify",
		},
		{
			name: "saml",
			state: &State{
				FlowID:       "flow-saml",
				FlowType:     FlowTypeSAML,
				Protocol:     FlowProtocolSAML,
				CurrentStep:  FlowStepStart,
				ReturnTarget: "/saml/sso",
			},
			steps:     []FlowStep{FlowStepLogin, FlowStepCallback},
			flowID:    "flow-saml",
			wantFinal: "/saml/sso",
		},
		{
			name: "require_mfa",
			state: &State{
				FlowID:       "flow-require-mfa",
				FlowType:     FlowTypeRequireMFA,
				Protocol:     FlowProtocolInternal,
				CurrentStep:  FlowStepStart,
				ReturnTarget: "/mfa/register/totp",
				PendingMFA:   true,
			},
			steps:     []FlowStep{FlowStepRequireMFAChallenge, FlowStepCallback},
			flowID:    "flow-require-mfa",
			wantFinal: "/mfa/register/totp",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryStore{}
			controller := NewController(store)

			startDecision, err := controller.Start(t.Context(), tc.state, now)
			if err != nil {
				t.Fatalf("start failed: %v", err)
			}

			if startDecision.Type != DecisionTypeRedirect {
				t.Fatalf("unexpected start decision: %+v", startDecision)
			}

			for _, step := range tc.steps {
				decision, advanceErr := controller.Advance(t.Context(), tc.flowID, step, now)
				if advanceErr != nil {
					t.Fatalf("advance to %s failed: %v", step, advanceErr)
				}

				if decision.Type != DecisionTypeRedirect {
					t.Fatalf("unexpected advance decision: %+v", decision)
				}
			}

			completeDecision, completeErr := controller.Complete(t.Context(), tc.flowID)
			if completeErr != nil {
				t.Fatalf("complete failed: %v", completeErr)
			}

			if completeDecision.RedirectURI != tc.wantFinal {
				t.Fatalf("unexpected complete redirect: got %q want %q", completeDecision.RedirectURI, tc.wantFinal)
			}

			if store.state != nil {
				t.Fatal("expected state to be deleted after complete")
			}
		})
	}
}

func TestMainFlowSequences_CancelPaths(t *testing.T) {
	now := time.Now().UTC()

	state := &State{
		FlowID:      "flow-cancel",
		FlowType:    FlowTypeSAML,
		Protocol:    FlowProtocolSAML,
		CurrentStep: FlowStepStart,
	}

	store := &memoryStore{}
	controller := NewController(store)

	if _, err := controller.Start(t.Context(), state, now); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	if _, err := controller.Advance(t.Context(), state.FlowID, FlowStepLogin, now); err != nil {
		t.Fatalf("advance failed: %v", err)
	}

	cancelDecision, err := controller.Cancel(t.Context(), state.FlowID)
	if err != nil {
		t.Fatalf("cancel failed: %v", err)
	}

	if cancelDecision.RedirectURI != "/" {
		t.Fatalf("unexpected cancel redirect: %s", cancelDecision.RedirectURI)
	}

	if store.state != nil {
		t.Fatal("expected state to be deleted after cancel")
	}
}

func TestMainFlowSequences_InvalidOrderAndDoubleSubmit(t *testing.T) {
	now := time.Now().UTC()

	state := &State{
		FlowID:      "flow-invalid-order",
		FlowType:    FlowTypeOIDCAuthorization,
		Protocol:    FlowProtocolOIDC,
		CurrentStep: FlowStepStart,
	}

	store := &memoryStore{}
	controller := NewController(store)

	if _, err := controller.Start(t.Context(), state, now); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Invalid order: start -> callback is not allowed.
	_, err := controller.Advance(t.Context(), state.FlowID, FlowStepCallback, now)
	if err == nil {
		t.Fatal("expected transition error")
	}

	var transitionErr TransitionError
	if !errors.As(err, &transitionErr) {
		t.Fatalf("expected TransitionError, got %v", err)
	}

	recoveryDecision, recoverErr := controller.Recover(t.Context(), state.FlowID, err)
	if recoverErr != nil {
		t.Fatalf("recover failed: %v", recoverErr)
	}

	if recoveryDecision.RedirectURI != "/login" {
		t.Fatalf("unexpected recovery redirect: %s", recoveryDecision.RedirectURI)
	}

	// Double submit simulation: flow already cleaned, complete should report stale flow.
	_, completeErr := controller.Complete(t.Context(), state.FlowID)
	if !errors.Is(completeErr, ErrFlowNotFound) {
		t.Fatalf("expected ErrFlowNotFound, got %v", completeErr)
	}
}
