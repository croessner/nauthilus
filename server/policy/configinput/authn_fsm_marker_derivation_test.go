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

package configinput

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy"
)

// configuredAuthnMarkerDerivationFixture binds unmarked and explicitly marked authn rules at every checkpoint kind.
const configuredAuthnMarkerDerivationFixture = `policy:
  namespaces:
    authn:
      policy_sets:
        configured:
          visibility: private
          rules:
            - name: pre_auth_unmarked_deny
              checkpoint: pre_auth
              actions: [authenticate]
              if: {always: true}
              then: {decision: deny}
            - name: pre_auth_unmarked_tempfail
              checkpoint: pre_auth
              actions: [authenticate]
              if: {always: true}
              then: {decision: tempfail}
            - name: pre_auth_unmarked_neutral
              checkpoint: pre_auth
              actions: [authenticate]
              if: {always: true}
              then: {decision: neutral}
            - name: subject_reject
              checkpoint: auth_decision
              actions: [authenticate]
              if: {always: true}
              then: {decision: deny}
            - name: unmarked_tempfail
              checkpoint: auth_decision
              actions: [authenticate]
              if: {always: true}
              then: {decision: tempfail}
            - name: unmarked_permit
              checkpoint: auth_decision
              actions: [authenticate]
              if: {always: true}
              then: {decision: permit}
            - name: explicit_empty_password
              checkpoint: auth_decision
              actions: [authenticate]
              if: {always: true}
              then:
                decision: deny
                fsm_event_marker: auth.fsm.event.auth_empty_pass
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      default_policy: authn/standard_auth
      plans:
        pre_auth:
          policy_sets: [authn/configured]
        auth_decision:
          policy_sets: [authn/configured]
`

// TestConfiguredAuthnRulesDeriveOmittedFSMEventMarkers proves an omitted marker compiles to the marker the auth FSM
// derives from checkpoint and decision, while an explicit marker is retained unchanged.
func TestConfiguredAuthnRulesDeriveOmittedFSMEventMarkers(t *testing.T) {
	input, err := Normalize(context.Background(), decodePolicy(t, configuredAuthnMarkerDerivationFixture))
	requireNoError(t, err)

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	target := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(policy.OperationAuthenticate))

	configured, ok := target.LookupPolicySet(mustPolicySetID(t, policy.AuthnNamespace, "configured"))
	if !ok {
		t.Fatal("configured authn policy set is missing")
	}

	want := map[string]string{
		"pre_auth_unmarked_deny":     policy.FSMEventMarkerPreAuthDeny,
		"pre_auth_unmarked_tempfail": policy.FSMEventMarkerPreAuthTempFail,
		"pre_auth_unmarked_neutral":  policy.FSMEventMarkerPreAuthOK,
		"subject_reject":             policy.FSMEventMarkerAuthDeny,
		"unmarked_tempfail":          policy.FSMEventMarkerAuthTempFail,
		"unmarked_permit":            policy.FSMEventMarkerAuthPermit,
		"explicit_empty_password":    policy.FSMEventMarkerAuthEmptyPass,
	}

	rules := configured.Rules()
	if len(rules) != len(want) {
		t.Fatalf("configured authn rules = %d, want %d", len(rules), len(want))
	}

	for _, rule := range rules {
		if got := rule.FSMEventMarker(); got != want[rule.Name()] {
			t.Errorf("rule %s fsm_event_marker = %q, want %q", rule.Name(), got, want[rule.Name()])
		}
	}
}
