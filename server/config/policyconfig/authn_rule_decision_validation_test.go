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
	"strings"
	"testing"
)

const authnDecisionPath = "policy.namespaces.authn.policy_sets.configured.rules[0].then.decision"

// authnDomainPlanDocument renders one authn rule bound at ruleCheckpoint of a configured domain plan.
func authnDomainPlanDocument(planCheckpoints []string, ruleCheckpoint string, then string) string {
	var checkpoints strings.Builder

	for _, checkpoint := range planCheckpoints {
		checkpoints.WriteString("            " + checkpoint + ": {providers: []}\n")
	}

	return `
policy:
  namespaces:
    authn:
      domain_plans:
        configured:
          checkpoints:
` + checkpoints.String() + `      policy_sets:
        configured:
          visibility: private
          rules:
            - name: configured_outcome
              checkpoint: ` + ruleCheckpoint + `
              actions: [authenticate]
              if: {always: true}
              then:
` + then + `
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
      default_policy: authn/standard_auth
      plans:
        ` + ruleCheckpoint + `:
          policy_sets: [authn/configured]
`
}

// authnDecisionCase binds one rule outcome to the plan topology it is evaluated in.
type authnDecisionCase struct {
	name            string
	planCheckpoints []string
	ruleCheckpoint  string
	then            string
	wantParts       []string
}

// authnDecisionRejectionCases lists decisions the authn orchestration cannot apply at their checkpoint.
func authnDecisionRejectionCases() []authnDecisionCase {
	fullPlan := []string{"pre_auth", "auth_backend", "subject_analysis", "auth_decision"}

	return []authnDecisionCase{
		{
			name: "neutral at the final auth_decision checkpoint", planCheckpoints: fullPlan,
			ruleCheckpoint: "auth_decision", then: `                decision: neutral`,
			wantParts: []string{
				`rule "configured_outcome"`, "target authn/authenticate", "decision neutral",
				"final checkpoint auth_decision", "allowed decisions: permit, deny, tempfail",
			},
		},
		{
			name: "permit at the intermediate subject_analysis checkpoint", planCheckpoints: fullPlan,
			ruleCheckpoint: "subject_analysis",
			then: `                decision: permit
                fsm_event_marker: auth.fsm.event.auth_permit`,
			wantParts: []string{
				"decision permit", "intermediate checkpoint subject_analysis", "final checkpoint is auth_decision",
				"allowed decisions: deny, tempfail, neutral",
			},
		},
		{
			name: "permit at the intermediate auth_backend checkpoint", planCheckpoints: fullPlan,
			ruleCheckpoint: "auth_backend",
			then: `                decision: permit
                fsm_event_marker: auth.fsm.event.auth_permit`,
			wantParts: []string{"decision permit", "intermediate checkpoint auth_backend"},
		},
		{
			name: "permit at the intermediate pre_auth checkpoint", planCheckpoints: fullPlan,
			ruleCheckpoint: "pre_auth", then: `                decision: permit`,
			wantParts: []string{"decision permit", "intermediate checkpoint pre_auth"},
		},
	}
}

func TestAuthnRuleDecisionMustMatchCheckpointPosition(t *testing.T) {
	for _, test := range authnDecisionRejectionCases() {
		t.Run(test.name, func(t *testing.T) {
			err := validateYAMLDocument(t, authnDomainPlanDocument(test.planCheckpoints, test.ruleCheckpoint, test.then))

			requireAuthnRuleRejection(t, err, authnDecisionPath, test.wantParts)
		})
	}
}

func TestAuthnRuleDecisionAcceptsCheckpointPosition(t *testing.T) {
	fullPlan := []string{"pre_auth", "auth_backend", "subject_analysis", "auth_decision"}
	tests := []authnDecisionCase{
		{
			name: "neutral at an intermediate checkpoint", planCheckpoints: fullPlan,
			ruleCheckpoint: "subject_analysis", then: `                decision: neutral`,
		},
		{
			name: "deny at an intermediate checkpoint", planCheckpoints: fullPlan, ruleCheckpoint: "auth_backend",
			then: `                decision: deny
                fsm_event_marker: auth.fsm.event.auth_deny`,
		},
		{
			name: "permit at the final auth_decision checkpoint", planCheckpoints: fullPlan,
			ruleCheckpoint: "auth_decision",
			then: `                decision: permit
                fsm_event_marker: auth.fsm.event.auth_permit`,
		},
		{
			name:            "permit at the last checkpoint of a plan without auth_decision",
			planCheckpoints: []string{"pre_auth", "subject_analysis"}, ruleCheckpoint: "subject_analysis",
			then: `                decision: permit
                fsm_event_marker: auth.fsm.event.auth_permit`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireNoError(t, validateYAMLDocument(t, authnDomainPlanDocument(test.planCheckpoints, test.ruleCheckpoint, test.then)))
		})
	}
}

func TestAuthnRuleDecisionUsesBuiltinPlanWithoutDomainPlan(t *testing.T) {
	err := validateYAMLDocument(t, authnFSMMarkerDocument("auth_decision", "[authenticate]", `                decision: neutral`))

	var pathError *PathError
	requireErrorAs(t, err, &pathError)
	requireEqual(t, authnDecisionPath, pathError.Path)
}
