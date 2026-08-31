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

package report

import (
	"encoding/json"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy"
)

func TestNewDecisionReportStartsEmpty(t *testing.T) {
	report := NewDecisionReport()

	if report.Attributes == nil {
		t.Fatal("attributes map is nil")
	}

	if report.Checks == nil {
		t.Fatal("checks map is nil")
	}

	if report.Policies == nil {
		t.Fatal("policies slice is nil")
	}
}

func TestDecisionReportRedactionExcludesSensitiveDetails(t *testing.T) {
	report := NewDecisionReport()
	report.Stage = policy.StageAuthDecision
	report.Attributes["auth.backend.tempfail"] = AttributeValue{
		ID:    "auth.backend.tempfail",
		Stage: policy.StageAuthDecision,
		Value: true,
		Details: map[string]DetailValue{
			"bind_password": {
				Value:       "secret-bind-password",
				Sensitivity: SensitivitySecret,
			},
			"reason_code": {
				Value:       "ldap_timeout",
				Sensitivity: SensitivityInternal,
			},
			"status_message": {
				Value:       "Try again later",
				Sensitivity: SensitivityPublic,
				Purpose:     PurposeResponseMessage,
				Selected:    true,
			},
		},
	}

	redacted := report.Redacted()

	payload, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal redacted report: %v", err)
	}

	if containsString(payload, "secret-bind-password") {
		t.Fatal("redacted report contains secret detail")
	}

	if containsString(payload, "ldap_timeout") {
		t.Fatal("redacted report contains internal detail")
	}

	if !containsString(payload, "Try again later") {
		t.Fatal("redacted report removed selected public response message")
	}
}

func TestDKIM2DecisionReportRedactionExcludesRequestIdentities(t *testing.T) {
	const (
		smtpPeerIP   = "203.0.113.77"
		signerDomain = "sensitive-signer.example"
	)

	for _, outcome := range []string{"permit", "provider_failure"} {
		t.Run(outcome, func(t *testing.T) {
			report := NewDecisionReport()
			report.Attributes["dkim2.assessment"] = AttributeValue{
				ID: "dkim2.assessment", Stage: policy.StageAuthDecision, Value: outcome,
				Details: map[string]DetailValue{
					"smtp_peer_ip":  {Value: smtpPeerIP, Sensitivity: SensitivitySecret},
					"signer_domain": {Value: signerDomain, Sensitivity: SensitivityInternal},
				},
			}

			payload, err := json.Marshal(report.Redacted())
			if err != nil {
				t.Fatalf("marshal redacted report: %v", err)
			}

			for _, secret := range []string{smtpPeerIP, signerDomain} {
				if containsString(payload, secret) {
					t.Fatalf("%s report leaks %q: %s", outcome, secret, payload)
				}
			}
		})
	}
}

func TestCloneFinalDecisionOwnsMutableEffectArguments(t *testing.T) {
	strings := []string{"first", "second"}
	bytes := []byte("payload")
	original := &FinalDecision{
		ResponseMessage: &ResponseMessageSelection{Message: "original"},
		Obligations: []EffectRequest{{
			ID: "effect",
			Args: map[string]any{
				"strings": strings,
				"bytes":   bytes,
			},
		}},
	}

	cloned := CloneFinalDecision(original)
	cloned.ResponseMessage.Message = "changed"
	cloned.Obligations[0].Args["strings"].([]string)[0] = "changed"
	cloned.Obligations[0].Args["bytes"].([]byte)[0] = 'X'

	if original.ResponseMessage.Message != "original" {
		t.Fatalf("original response message = %q, want original", original.ResponseMessage.Message)
	}

	if strings[0] != "first" || string(bytes) != "payload" {
		t.Fatalf("original effect arguments changed: strings=%v bytes=%q", strings, bytes)
	}
}

func containsString(payload []byte, needle string) bool {
	return string(payload) != "" && json.Valid(payload) && contains(string(payload), needle)
}

func contains(value string, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}

	return false
}
