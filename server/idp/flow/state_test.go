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
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestStateValidate(t *testing.T) {
	tests := []struct {
		name    string
		state   *State
		errWant error
	}{
		{
			name: "valid",
			state: &State{
				FlowID:      "f-1",
				FlowType:    FlowTypeOIDCAuthorization,
				Protocol:    FlowProtocolOIDC,
				CurrentStep: FlowStepLogin,
			},
			errWant: nil,
		},
		{
			name: "empty flow id",
			state: &State{
				FlowType:    FlowTypeOIDCAuthorization,
				Protocol:    FlowProtocolOIDC,
				CurrentStep: FlowStepLogin,
			},
			errWant: ErrEmptyFlowID,
		},
		{
			name: "invalid flow type",
			state: &State{
				FlowID:      "f-1",
				FlowType:    FlowTypeUnknown,
				Protocol:    FlowProtocolOIDC,
				CurrentStep: FlowStepLogin,
			},
			errWant: ErrInvalidFlowType,
		},
		{
			name: "invalid protocol",
			state: &State{
				FlowID:      "f-1",
				FlowType:    FlowTypeOIDCAuthorization,
				Protocol:    FlowProtocolUnknown,
				CurrentStep: FlowStepLogin,
			},
			errWant: ErrInvalidProtocol,
		},
		{
			name: "invalid step",
			state: &State{
				FlowID:      "f-1",
				FlowType:    FlowTypeOIDCAuthorization,
				Protocol:    FlowProtocolOIDC,
				CurrentStep: FlowStep("invalid"),
			},
			errWant: ErrInvalidStep,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.state.Validate()
			if tc.errWant == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.errWant != nil && !errors.Is(err, tc.errWant) {
				t.Fatalf("expected %v, got %v", tc.errWant, err)
			}
		})
	}
}

func TestStateNormalize(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	state := &State{FlowID: "flow-123"}
	state.Normalize(now)

	if state.Metadata == nil {
		t.Fatal("expected metadata map to be initialized")
	}

	if state.CreatedAt != now {
		t.Fatalf("expected created_at=%s, got %s", now, state.CreatedAt)
	}

	if state.UpdatedAt != now {
		t.Fatalf("expected updated_at=%s, got %s", now, state.UpdatedAt)
	}
}

func TestStateJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, time.February, 3, 10, 11, 12, 0, time.UTC)

	state := State{
		FlowID:       "flow-42",
		GrantType:    "authorization_code",
		CancelTarget: "/idp/cancel",
		ReturnTarget: "/idp/home",
		Metadata: map[string]string{
			"client_id": "nauthilus",
		},
		FlowType:    FlowTypeOIDCAuthorization,
		Protocol:    FlowProtocolOIDC,
		CurrentStep: FlowStepConsent,
		CreatedAt:   now,
		UpdatedAt:   now,
		PendingMFA:  true,
	}

	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded State
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.FlowID != state.FlowID || decoded.FlowType != state.FlowType || decoded.CurrentStep != state.CurrentStep {
		t.Fatalf("decoded core values mismatch: got %+v want %+v", decoded, state)
	}

	if decoded.Metadata["client_id"] != "nauthilus" {
		t.Fatalf("metadata mismatch: %+v", decoded.Metadata)
	}
}
