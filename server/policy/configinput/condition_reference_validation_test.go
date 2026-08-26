// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
)

const missingRuleConditionReferenceFixture = `policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          submit:
            versions:
              v1:
                facts:
                  - attribute: input.protocol
                    category: environment
                    type: string
                    allowed_sources: [caller]
      domain_plans:
        default:
          checkpoints:
            final_decision: {providers: []}
      policy_sets:
        default:
          rules:
            - name: missing_reference_under_not
              checkpoint: final_decision
              if:
                not:
                  attribute: input.protocol
                  in: "@string.missing"
              then: {decision: permit}
  targets:
    - namespace: mail
      action: submit
      schema: mail/submit/v1
      domain_plan: mail/default
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [mail/default]}
`

// TestCompiledPolicyRuleRejectsMissingConditionReferenceUnderNot prevents unknown inversion.
func TestCompiledPolicyRuleRejectsMissingConditionReferenceUnderNot(t *testing.T) {
	err := compilePolicyFixture(t, missingRuleConditionReferenceFixture)
	if err == nil || !strings.Contains(err.Error(), "condition-set reference @string.missing is unavailable") {
		t.Fatalf("Compile() error = %v, want missing condition-set reference", err)
	}
}

// TestPolicyCompiledPlanRejectsDefinitionRequiredGuardAndRunIfMismatch closes merged dependency validation.
func TestPolicyCompiledPlanRejectsDefinitionRequiredGuardAndRunIfMismatch(t *testing.T) {
	tests := []struct {
		name              string
		primarySchedule   string
		dependentSchedule string
		want              string
	}{
		{
			name:              "run_if mismatch",
			primarySchedule:   "                  run_if: {auth_state: unauthenticated}\n",
			dependentSchedule: "                  run_if: {auth_state: authenticated}\n",
			want:              "incompatible run_if.auth_state",
		},
		{
			name:            "scheduler guard mismatch",
			primarySchedule: "                  skip_if: [blocked]\n",
			want:            "must include scheduler guards used by dependency primary",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := compilePolicyFixture(
				t,
				definitionRequiredDependencyFixture(test.primarySchedule, test.dependentSchedule),
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Compile() error = %v, want %q", err, test.want)
			}
		})
	}
}

// compilePolicyFixture decodes, normalizes, and compiles one complete test candidate.
func compilePolicyFixture(t *testing.T, fixture string) error {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	input, err := Normalize(t.Context(), document)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	_, err = input.Compile(t.Context(), &nativeGenerationAcceptor{})

	return err
}

// definitionRequiredDependencyFixture builds one provider-definition dependency without authored after edges.
func definitionRequiredDependencyFixture(primarySchedule string, dependentSchedule string) string {
	return fmt.Sprintf(`policy:
  namespaces:
    authn:
      providers:
        primary:
          kind: native
          module: test
          targets: [{action: authenticate}]
          executions: [host_sync]
          failure: indeterminate
          timeout: 100ms
        dependent:
          kind: native
          module: test
          targets: [{action: authenticate}]
          requires: [primary]
          executions: [host_sync]
          failure: indeterminate
          timeout: 100ms
      domain_plans:
        configured:
          scheduler_guards:
            blocked: {if: {always: true}}
          checkpoints:
            pre_auth:
              providers:
                - name: primary
                  use: authn/primary
%s                - name: dependent
                  use: authn/dependent
%s            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
`, primarySchedule, dependentSchedule)
}
