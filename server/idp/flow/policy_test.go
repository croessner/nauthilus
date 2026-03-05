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
	"errors"
	"testing"
)

func TestPolicyForFlowType(t *testing.T) {
	tests := []struct {
		name     string
		flowType FlowType
		errWant  error
	}{
		{name: "oidc auth", flowType: FlowTypeOIDCAuthorization},
		{name: "oidc device", flowType: FlowTypeOIDCDeviceCode},
		{name: "saml", flowType: FlowTypeSAML},
		{name: "require mfa", flowType: FlowTypeRequireMFA},
		{name: "invalid", flowType: FlowTypeUnknown, errWant: ErrInvalidFlowType},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := PolicyForFlowType(tc.flowType)
			if tc.errWant == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if policy.FlowType() != tc.flowType {
					t.Fatalf("unexpected flow type: %s", policy.FlowType())
				}

				return
			}

			if !errors.Is(err, tc.errWant) {
				t.Fatalf("expected %v, got %v", tc.errWant, err)
			}
		})
	}
}

func TestPolicyRules(t *testing.T) {
	tests := []struct {
		name          string
		flowType      FlowType
		step          FlowStep
		action        FlowAction
		from          FlowStep
		to            FlowStep
		stepAllowed   bool
		actionAllowed bool
		transitionOK  bool
	}{
		{
			name:          "oidc auth consent flow",
			flowType:      FlowTypeOIDCAuthorization,
			step:          FlowStepConsent,
			action:        FlowActionAdvance,
			from:          FlowStepConsent,
			to:            FlowStepCallback,
			stepAllowed:   true,
			actionAllowed: true,
			transitionOK:  true,
		},
		{
			name:          "oidc device requires device verification first",
			flowType:      FlowTypeOIDCDeviceCode,
			step:          FlowStepDeviceVerification,
			action:        FlowActionAdvance,
			from:          FlowStepStart,
			to:            FlowStepLogin,
			stepAllowed:   true,
			actionAllowed: true,
			transitionOK:  false,
		},
		{
			name:          "saml has no consent step",
			flowType:      FlowTypeSAML,
			step:          FlowStepConsent,
			action:        FlowActionAdvance,
			from:          FlowStepLogin,
			to:            FlowStepConsent,
			stepAllowed:   false,
			actionAllowed: false,
			transitionOK:  false,
		},
		{
			name:          "require mfa challenge advances to callback",
			flowType:      FlowTypeRequireMFA,
			step:          FlowStepRequireMFAChallenge,
			action:        FlowActionAdvance,
			from:          FlowStepRequireMFAChallenge,
			to:            FlowStepCallback,
			stepAllowed:   true,
			actionAllowed: true,
			transitionOK:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := PolicyForFlowType(tc.flowType)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if policy.AllowsStep(tc.step) != tc.stepAllowed {
				t.Fatalf("step check mismatch for %s", tc.step)
			}

			if policy.AllowsAction(tc.step, tc.action) != tc.actionAllowed {
				t.Fatalf("action check mismatch for %s/%s", tc.step, tc.action)
			}

			if policy.CanTransition(tc.from, tc.to) != tc.transitionOK {
				t.Fatalf("transition mismatch for %s -> %s", tc.from, tc.to)
			}
		})
	}
}
