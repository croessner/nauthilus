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

package decision_test

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

func TestDecisionResponseDeeplyOwnsEffectsStatusAndDiagnostics(t *testing.T) {
	parameter := mustStringValue(t, "quarantine")
	parameters := map[string]decision.Value{"mode": parameter}
	obligation := mustEffectRequest(t, parameters)
	details := []decision.ValidationDetail{
		decision.NewValidationDetail("resource.id", "required"),
	}
	status := mustStatus(t, details)
	metadata := mustPolicyMetadata(t)
	diagnostics := mustDiagnostics(t, parameter)

	response, err := decision.NewDecisionResponse(decision.DecisionResponseInput{
		RequestID:   "request-01",
		DecisionID:  "decision-01",
		Effect:      decision.EffectDeny,
		Status:      status,
		Obligations: []decision.EffectRequest{obligation},
		Policy:      metadata,
		Diagnostics: &diagnostics,
	})
	if err != nil {
		t.Fatalf("NewDecisionResponse() error = %v", err)
	}

	delete(parameters, "mode")

	details[0] = decision.NewValidationDetail("changed", "changed")

	obligations := response.Obligations()
	obligations[0] = decision.EffectRequest{}
	statusDetails := response.Status().Details()
	statusDetails[0] = decision.NewValidationDetail("changed", "changed")
	returnedParameters := response.Obligations()[0].Parameters().Values()
	delete(returnedParameters, "mode")

	diagnosticValues := response.Diagnostics().Entries().Values()
	delete(diagnosticValues, "reason")

	if response.Obligations()[0].ID() != "dkim2/quarantine" {
		t.Fatal("DecisionResponse exposed mutable obligation storage")
	}

	if _, ok := response.Obligations()[0].Parameters().Get("mode"); !ok {
		t.Fatal("DecisionResponse exposed mutable effect parameter storage")
	}

	if response.Status().Details()[0].Field() != "resource.id" {
		t.Fatal("DecisionResponse exposed mutable status detail storage")
	}

	if _, ok := response.Diagnostics().Entries().Get("reason"); !ok {
		t.Fatal("DecisionResponse exposed mutable diagnostics storage")
	}
}

func TestStatusDerivesRetryabilityFromStableTaxonomy(t *testing.T) {
	tests := []struct {
		name      string
		code      decision.StatusCode
		retryable bool
		valid     bool
	}{
		{name: "evaluation failure", code: decision.StatusCodeEvaluationFailed, retryable: true, valid: true},
		{name: "ambiguous effect", code: decision.StatusCodeEffectOutcomeUnknown, valid: true},
		{name: "unknown code", code: decision.StatusCode("provider_raw_error")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, err := decision.NewStatus(test.code, "safe", nil)
			if !test.valid {
				if !errors.Is(err, decision.ErrInvalidResponse) {
					t.Fatalf("NewStatus() error = %v, want ErrInvalidResponse", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("NewStatus() error = %v", err)
			}

			if status.Retryable() != test.retryable {
				t.Fatalf("Status.Retryable() = %t, want %t", status.Retryable(), test.retryable)
			}
		})
	}
}

// mustEffectRequest creates one typed obligation for response tests.
func mustEffectRequest(t *testing.T, parameters map[string]decision.Value) decision.EffectRequest {
	t.Helper()

	request, err := decision.NewEffectRequest(decision.EffectRequestInput{
		ID:         "dkim2/quarantine",
		Parameters: parameters,
	})
	if err != nil {
		t.Fatalf("NewEffectRequest() error = %v", err)
	}

	return request
}

// mustStatus creates safe status metadata for response tests.
func mustStatus(t *testing.T, details []decision.ValidationDetail) decision.Status {
	t.Helper()

	status, err := decision.NewStatus(decision.StatusCodePolicyDenied, "The operation is denied.", details)
	if err != nil {
		t.Fatalf("NewStatus() error = %v", err)
	}

	return status
}

// mustPolicyMetadata creates selected-policy metadata for response tests.
func mustPolicyMetadata(t *testing.T) decision.PolicyMetadata {
	t.Helper()

	metadata, err := decision.NewPolicyMetadata("dkim2/default", "v1", "deny-message", 42)
	if err != nil {
		t.Fatalf("NewPolicyMetadata() error = %v", err)
	}

	return metadata
}

// mustDiagnostics creates a sanitized diagnostics projection for response tests.
func mustDiagnostics(t *testing.T, value decision.Value) decision.Diagnostics {
	t.Helper()

	diagnostics, err := decision.NewDiagnostics(map[string]decision.Value{"reason": value})
	if err != nil {
		t.Fatalf("NewDiagnostics() error = %v", err)
	}

	return diagnostics
}

func TestDecisionEffectsAreClosedAndValidated(t *testing.T) {
	for _, effect := range []decision.Effect{
		decision.EffectPermit,
		decision.EffectDeny,
		decision.EffectNotApplicable,
		decision.EffectIndeterminate,
	} {
		if !effect.Valid() {
			t.Fatalf("Effect %q is not valid", effect)
		}
	}

	if decision.Effect("allow").Valid() {
		t.Fatal("unknown effect is valid")
	}
}
