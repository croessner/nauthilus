// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/policy/report"
)

// authnEnvironmentTriggerDecisionCase pairs one selected policy decision with the rejection state it must leave.
type authnEnvironmentTriggerDecisionCase struct {
	name         string
	final        report.FinalDecision
	wantRejected bool
}

// authnEnvironmentTriggerDecisionCases lists a permit and a non-pre-auth deny that must not mark the request,
// and the pre-auth deny that must.
func authnEnvironmentTriggerDecisionCases() []authnEnvironmentTriggerDecisionCase {
	return []authnEnvironmentTriggerDecisionCase{
		{
			name:  "operator permit ignores the trigger",
			final: report.FinalDecision{PolicyName: "operator_permit", Stage: policy.StageAuthDecision, Effect: policy.DecisionPermit},
		},
		{
			name:  "auth decision deny is not an environment rejection",
			final: report.FinalDecision{PolicyName: "operator_deny", Stage: policy.StageAuthDecision, Effect: policy.DecisionDeny},
		},
		{
			name:         "pre-auth deny rejects the request",
			final:        report.FinalDecision{PolicyName: "standard_trigger", Stage: policy.StagePreAuth, Effect: policy.DecisionDeny},
			wantRejected: true,
		},
	}
}

// TestLuaEnvironmentTriggerSideEffectsFollowPolicyDecision proves that ENVIRONMENT_TRIGGER_YES is only a fact: the
// request is marked as rejected by an environment source only after the policy selected a pre-auth deny.
func TestLuaEnvironmentTriggerSideEffectsFollowPolicyDecision(t *testing.T) {
	for _, test := range authnEnvironmentTriggerDecisionCases() {
		t.Run(test.name, func(t *testing.T) {
			auth, ctx, _ := newCurrentBehaviorAuthState(t, newCurrentBehaviorConfig(t, definitions.ControlLua))
			prototype := compileAuthnCandidateLuaSource(t, "trigger.lua", `
function nauthilus_call_environment(_request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)

			const providerID = "authn/lua_environment_trigger"

			session := &authnConfiguredHostSession{
				recordingAuthnDecisionSession: newRecordingAuthnDecisionSession([]string{"pre_auth"}),
				provider: authnConfiguredLuaSource{
					id: providerID, kind: decisionservice.AuthnHostProviderKindLuaEnvironment,
					name: "trigger", prototype: prototype, pools: vmpool.NewManager(),
				},
			}
			execution := &authnCandidateExecution{
				auth: auth, ginCtx: ctx, selected: make(map[string]*report.FinalDecision),
				operation: policy.OperationAuthenticate,
			}

			if _, err := execution.prepareConfiguredHostProvider(session, providerID); err != nil {
				t.Fatalf("prepareConfiguredHostProvider() error = %v", err)
			}

			assertAuthnEnvironmentTriggerUndecided(t, execution)
			execution.CaptureAuthnDecision(t.Context(), authnCandidateTarget(t), string(policy.StageAuthDecision), &test.final)
			assertAuthnEnvironmentTriggerDecided(t, execution, test.wantRejected, definitions.ControlLua)
		})
	}
}

// TestNativeEnvironmentTriggerSideEffectsFollowPolicyDecision applies the same contract to native sources.
func TestNativeEnvironmentTriggerSideEffectsFollowPolicyDecision(t *testing.T) {
	for _, test := range authnEnvironmentTriggerDecisionCases() {
		t.Run(test.name, func(t *testing.T) {
			auth, ctx, _ := newCurrentBehaviorAuthState(t, newCurrentBehaviorConfig(t))
			auth.deps.NativeRuntime = authnCapturedNativeRuntime{}
			provider := &authnCapturedNativeEnvironmentSource{id: "authn/plugin.example.environment", triggered: true}
			session := &authnConfiguredHostSession{
				recordingAuthnDecisionSession: newRecordingAuthnDecisionSession([]string{"pre_auth"}),
				provider:                      provider,
			}
			execution := &authnCandidateExecution{
				auth: auth, ginCtx: ctx, selected: make(map[string]*report.FinalDecision),
				operation: policy.OperationAuthenticate,
			}

			if _, err := execution.prepareConfiguredHostProvider(session, provider.id); err != nil {
				t.Fatalf("prepareConfiguredHostProvider() error = %v", err)
			}

			assertAuthnEnvironmentTriggerUndecided(t, execution)
			execution.CaptureAuthnDecision(t.Context(), authnCandidateTarget(t), string(policy.StageAuthDecision), &test.final)
			assertAuthnEnvironmentTriggerDecided(t, execution, test.wantRejected, provider.id)
		})
	}
}

// assertAuthnEnvironmentTriggerUndecided checks that a triggered source left no rejection state behind.
func assertAuthnEnvironmentTriggerUndecided(t *testing.T, execution *authnCandidateExecution) {
	t.Helper()

	if execution.ginCtx.GetBool(definitions.CtxEnvironmentRejectedKey) {
		t.Fatal("environment trigger marked the request rejected before the policy decided")
	}

	if execution.auth.Runtime.EnvironmentName != "" {
		t.Fatalf("environment trigger set environment name %q before the policy decided", execution.auth.Runtime.EnvironmentName)
	}

	if execution.preAuthResult != definitions.AuthResultUnset {
		t.Fatalf("environment trigger set pre-auth result %q before the policy decided", execution.preAuthResult)
	}

	if flags := execution.auth.AuthnRequestStageFlags(); flags.EnvironmentRejected || !flags.SubjectStageExpected {
		t.Fatalf("environment trigger changed request stage flags before the policy decided: %+v", flags)
	}
}

// assertAuthnEnvironmentTriggerDecided checks the rejection state after the policy selected one decision.
func assertAuthnEnvironmentTriggerDecided(
	t *testing.T,
	execution *authnCandidateExecution,
	wantRejected bool,
	wantEnvironment string,
) {
	t.Helper()

	if got := execution.ginCtx.GetBool(definitions.CtxEnvironmentRejectedKey); got != wantRejected {
		t.Fatalf("environment rejected = %t, want %t", got, wantRejected)
	}

	environment := ""
	if wantRejected {
		environment = wantEnvironment
	}

	if execution.auth.Runtime.EnvironmentName != environment {
		t.Fatalf("environment name = %q, want %q", execution.auth.Runtime.EnvironmentName, environment)
	}
}

// authnCandidateTarget returns the authenticate target the captured decisions belong to.
func authnCandidateTarget(t *testing.T) decision.Target {
	t.Helper()

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return target
}
