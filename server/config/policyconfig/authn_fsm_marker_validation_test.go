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

package policyconfig

import (
	"errors"
	"strings"
	"testing"
)

// authnFSMMarkerDocument renders one authn rule bound to every authn target at its checkpoint.
func authnFSMMarkerDocument(checkpoint string, actions string, then string) string {
	return `
policy:
  namespaces:
    authn:
      policy_sets:
        configured:
          visibility: private
          rules:
            - name: subject_reject
              checkpoint: ` + checkpoint + `
              actions: ` + actions + `
              if:
                attribute: backend.authenticated
                is: false
              then:
` + then + `
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      default_policy: authn/standard_auth
      plans:
        ` + checkpoint + `:
          policy_sets: [authn/configured]
    - namespace: authn
      action: list_accounts
      schema: authn/list_accounts/v1
      default_policy: authn/standard_auth
      plans:
        ` + checkpoint + `:
          policy_sets: [authn/configured]
`
}

// validateYAMLDocument decodes and validates one standalone YAML policy document.
func validateYAMLDocument(t *testing.T, content string) error {
	t.Helper()

	document, err := Decode("yaml", strings.NewReader(content))
	requireNoError(t, err)

	return Validate(Normalize(document))
}

// authnFSMMarkerCase binds one authn rule outcome to the checkpoint and actions it is evaluated for.
type authnFSMMarkerCase struct {
	name       string
	checkpoint string
	actions    string
	then       string
	wantParts  []string
}

const authnFSMMarkerPath = "policy.namespaces.authn.policy_sets.configured.rules[0].then.fsm_event_marker"

// authnFSMMarkerInvalidCases lists authn rule markers the auth FSM cannot apply at their checkpoint.
func authnFSMMarkerInvalidCases() []authnFSMMarkerCase {
	return []authnFSMMarkerCase{
		{
			name:       "pre_auth marker on auth_decision rule is rejected",
			checkpoint: "auth_decision",
			actions:    "[authenticate]",
			then: `                decision: deny
                fsm_event_marker: auth.fsm.event.pre_auth_deny`,
			wantParts: []string{
				"auth.fsm.event.pre_auth_deny is not valid", "decision deny", "checkpoint auth_decision",
				"auth.fsm.event.auth_deny",
			},
		},
		{
			name:       "auth_decision marker on pre_auth rule is rejected",
			checkpoint: "pre_auth",
			actions:    "[authenticate]",
			then: `                decision: deny
                fsm_event_marker: auth.fsm.event.auth_deny`,
			wantParts: []string{"auth.fsm.event.auth_deny is not valid", "checkpoint pre_auth", "auth.fsm.event.pre_auth_deny"},
		},
		{
			name:       "marker contradicting the decision is rejected",
			checkpoint: "auth_decision",
			actions:    "[authenticate]",
			then: `                decision: deny
                fsm_event_marker: auth.fsm.event.auth_permit`,
			wantParts: []string{"auth.fsm.event.auth_permit is not valid", "decision deny"},
		},
		{
			name:       "authentication-only marker on list_accounts is rejected",
			checkpoint: "auth_decision",
			actions:    "[]",
			then: `                decision: deny
                fsm_event_marker: auth.fsm.event.auth_empty_pass`,
			wantParts: []string{"target authn/list_accounts", "auth.fsm.event.auth_empty_pass is not valid", "auth.fsm.event.auth_deny"},
		},
		{
			name:       "neutral pre_auth rule with a terminal marker is rejected",
			checkpoint: "pre_auth",
			actions:    "[authenticate]",
			then: `                decision: neutral
                fsm_event_marker: auth.fsm.event.pre_auth_deny`,
			wantParts: []string{"decision neutral", "auth.fsm.event.pre_auth_ok"},
		},
	}
}

// requireAuthnRuleRejection asserts one validation error at wantPath whose message carries every wanted part.
func requireAuthnRuleRejection(t *testing.T, err error, wantPath string, wantParts []string) {
	t.Helper()

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, wantPath, pathError.Path)

	if !errors.Is(err, ErrValidation) {
		t.Fatalf("error = %v, want ErrValidation", err)
	}

	for _, part := range wantParts {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("error %q does not contain %q", err.Error(), part)
		}
	}
}

func TestAuthnRuleFSMEventMarkerValidation(t *testing.T) {
	for _, test := range authnFSMMarkerInvalidCases() {
		t.Run(test.name, func(t *testing.T) {
			err := validateYAMLDocument(t, authnFSMMarkerDocument(test.checkpoint, test.actions, test.then))

			requireAuthnRuleRejection(t, err, authnFSMMarkerPath, test.wantParts)
		})
	}
}

// authnFSMMarkerAcceptedCases lists authn rule outcomes the auth FSM can apply.
func authnFSMMarkerAcceptedCases() []authnFSMMarkerCase {
	return []authnFSMMarkerCase{
		{
			name:       "deny with auth_deny at auth_decision",
			checkpoint: "auth_decision",
			actions:    "[authenticate]",
			then: `                decision: deny
                outcome_marker: auth.outcome.subject_reject
                fsm_event_marker: auth.fsm.event.auth_deny
                response_marker: auth.response.fail`,
		},
		{
			name:       "deny with auth_empty_pass at auth_decision",
			checkpoint: "auth_decision",
			actions:    "[authenticate]",
			then: `                decision: deny
                fsm_event_marker: auth.fsm.event.auth_empty_pass`,
		},
		{
			name:       "tempfail with auth_empty_user at auth_decision",
			checkpoint: "auth_decision",
			actions:    "[authenticate]",
			then: `                decision: tempfail
                fsm_event_marker: auth.fsm.event.auth_empty_user`,
		},
		{
			name:       "permit with auth_permit for every authn action",
			checkpoint: "auth_decision",
			actions:    "[]",
			then: `                decision: permit
                fsm_event_marker: auth.fsm.event.auth_permit`,
		},
		{
			name:       "deny with pre_auth_deny at pre_auth",
			checkpoint: "pre_auth",
			actions:    "[authenticate]",
			then: `                decision: deny
                fsm_event_marker: auth.fsm.event.pre_auth_deny`,
		},
		{
			name:       "neutral with pre_auth_ok at pre_auth",
			checkpoint: "pre_auth",
			actions:    "[authenticate]",
			then: `                decision: neutral
                fsm_event_marker: auth.fsm.event.pre_auth_ok`,
		},
		{
			name:       "neutral without marker at pre_auth",
			checkpoint: "pre_auth",
			actions:    "[authenticate]",
			then:       `                decision: neutral`,
		},
		{
			name:       "deny without marker at auth_decision derives auth_deny",
			checkpoint: "auth_decision",
			actions:    "[authenticate]",
			then: `                decision: deny
                outcome_marker: auth.outcome.subject_reject
                response_marker: auth.response.fail`,
		},
		{
			name:       "tempfail without marker at pre_auth derives pre_auth_tempfail",
			checkpoint: "pre_auth",
			actions:    "[authenticate]",
			then:       `                decision: tempfail`,
		},
		{
			name:       "deny without marker for every authn action derives auth_deny",
			checkpoint: "auth_decision",
			actions:    "[]",
			then:       `                decision: deny`,
		},
		{
			name:       "permit without marker at auth_decision derives auth_permit",
			checkpoint: "auth_decision",
			actions:    "[]",
			then:       `                decision: permit`,
		},
		{
			name:       "rule restricted to an unbound action is not checked for that target",
			checkpoint: "auth_decision",
			actions:    "[lookup_identity]",
			then:       `                decision: deny`,
		},
	}
}

func TestAuthnRuleFSMEventMarkerAcceptsValidMarkers(t *testing.T) {
	for _, test := range authnFSMMarkerAcceptedCases() {
		t.Run(test.name, func(t *testing.T) {
			requireNoError(t, validateYAMLDocument(t, authnFSMMarkerDocument(test.checkpoint, test.actions, test.then)))
		})
	}
}

// TestAuthnRuleFSMEventMarkerRejectsUnderivableMarker covers a terminal decision whose checkpoint has no auth FSM
// transition, so neither a derived nor an explicit marker could apply it.
func TestAuthnRuleFSMEventMarkerRejectsUnderivableMarker(t *testing.T) {
	err := validateYAMLDocument(t, authnDomainPlanDocument([]string{"pre_auth"}, "pre_auth", `                decision: permit`))

	requireAuthnRuleRejection(t, err, authnFSMMarkerPath, []string{
		`rule "configured_outcome"`, "target authn/authenticate", "decision permit", "checkpoint pre_auth",
		"no transition",
	})
}

func TestGenericNamespaceTerminalRulesDoNotRequireFSMEventMarker(t *testing.T) {
	const content = `
policy:
  namespaces:
    dkim2:
      schema_contributions:
        static:
          verify-message:
            versions:
              v1:
                facts: []
      policy_sets:
        verifier:
          visibility: private
          rules:
            - name: reject_failed_signature
              checkpoint: final_decision
              actions: [verify-message]
              if:
                always: true
              then:
                decision: deny
            - name: accept_message
              checkpoint: final_decision
              if:
                always: true
              then:
                decision: permit
  targets:
    - namespace: dkim2
      action: verify-message
      schema: dkim2/verify-message/v1
      mode: enforce
      default_policy: dkim2/verifier
      no_match: deny
      timeouts:
        evaluation: 2s
        provider_default: 500ms
      plans:
        final_decision:
          policy_sets: [dkim2/verifier]
`

	requireNoError(t, validateYAMLDocument(t, content))
}
