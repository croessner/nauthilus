// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"strings"
	"testing"

	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

const configuredAuthnOperatorDecisionsFixture = `policy:
  namespaces:
    authn:
      domain_plans:
        configured:
          checkpoints:
            auth_backend:
              providers:
                - name: ldap_backend
                  use: authn/builtin/ldap_backend
                  actions: [authenticate]
            auth_decision: {providers: []}
      policy_sets:
        configured:
          visibility: private
          rules:
            - name: backend_error_tempfail
              checkpoint: auth_decision
              actions: [authenticate]
              if: {attribute: nauthilus.auth.backend.tempfail, is: true}
              then:
                decision: tempfail
                outcome_marker: auth.outcome.backend_tempfail
                fsm_event_marker: auth.fsm.event.auth_tempfail
                response_marker: auth.response.tempfail
            - name: optional_dependency_neutral
              checkpoint: auth_decision
              actions: [authenticate]
              if: {attribute: nauthilus.auth.backend.empty_username, is: true}
              then:
                decision: neutral
                outcome_marker: auth.outcome.optional_dependency_error
                fsm_event_marker: auth.fsm.event.auth_ok
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
      default_policy: authn/standard_auth
      plans:
        auth_decision:
          policy_sets: [authn/configured]
`

const configuredGenericOperatorDecisionFixture = `policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          submit:
            versions:
              v1: {facts: []}
      policy_sets:
        configured:
          rules:
            - name: backend_error_tempfail
              checkpoint: final_decision
              if: {always: true}
              then: {decision: tempfail}
`

func TestConfiguredAuthnRulesRetainOperatorTempFailAndNeutralDecisions(t *testing.T) {
	input, err := Normalize(context.Background(), decodePolicy(t, configuredAuthnOperatorDecisionsFixture))
	requireNoError(t, err)

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	target := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(policy.OperationAuthenticate))

	configured, ok := target.LookupPolicySet(mustPolicySetID(t, policy.AuthnNamespace, "configured"))
	if !ok {
		t.Fatal("configured authn policy set is missing")
	}

	rules := configured.Rules()
	if len(rules) != 2 {
		t.Fatalf("configured authn rules = %d, want 2", len(rules))
	}

	if rules[0].Decision() != decision.EffectIndeterminate {
		t.Fatalf("tempfail decision = %q, want %q", rules[0].Decision(), decision.EffectIndeterminate)
	}

	if rules[1].Decision() != decision.EffectNotApplicable {
		t.Fatalf("neutral decision = %q, want %q", rules[1].Decision(), decision.EffectNotApplicable)
	}
}

func TestGenericPolicyRulesRejectAuthnOperatorDecisions(t *testing.T) {
	_, err := Normalize(context.Background(), decodePolicy(t, configuredGenericOperatorDecisionFixture))
	if err == nil || !strings.Contains(err.Error(), "must be permit or deny") {
		t.Fatalf("Normalize() error = %v, want generic decision vocabulary rejection", err)
	}
}
