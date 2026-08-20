// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package registry

import (
	"testing"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/stretchr/testify/assert"
)

func TestProviderInstanceDefinitionRetainsAuthoredMetadataAndAllowsSharedUse(t *testing.T) {
	actions := []string{string(policy.OperationAuthenticate)}
	after := []string{"primary"}
	skipIf := []string{"trusted_client"}

	secondary, err := NewProviderInstanceDefinition(ProviderInstanceDefinitionInput{
		Path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[1]",
		Name: "secondary", Use: policy.AuthnProviderTLSEncryption,
		Actions: actions, After: after, RunIfAuthState: policy.RunIfUnauthenticated,
		SkipIf: skipIf, ObserveSafe: true, ObserveSafeAuthored: true,
		Output: "auth.tls.secondary",
	})
	compiledMetadataNoError(t, err)

	primary, err := NewProviderInstanceDefinition(ProviderInstanceDefinitionInput{
		Path: "policy.namespaces.authn.domain_plans.password.checkpoints.pre_auth.providers[0]",
		Name: "primary", Use: policy.AuthnProviderTLSEncryption,
		Actions: []string{string(policy.OperationAuthenticate)}, RunIfAuthState: policy.RunIfAny,
	})
	compiledMetadataNoError(t, err)

	actions[0] = "lookup_identity"
	after[0] = "mutated"
	skipIf[0] = "mutated"

	assert.NotEmpty(t, secondary.Path())
	assert.Equal(t, "secondary", secondary.Name())
	assert.Equal(t, policy.AuthnProviderTLSEncryption, secondary.Use())
	assert.Equal(t, []string{string(policy.OperationAuthenticate)}, secondary.Actions())
	assert.Equal(t, []string{"primary"}, secondary.After())
	assert.Equal(t, []string{"trusted_client"}, secondary.SkipIf())
	assert.Equal(t, policy.RunIfUnauthenticated, secondary.RunIfAuthState())
	assert.True(t, secondary.ObserveSafe())
	assert.True(t, secondary.ObserveSafeAuthored())
	assert.Equal(t, "auth.tls.secondary", secondary.Output())

	returned := secondary.After()
	returned[0] = "mutated_again"

	assert.Equal(t, "primary", secondary.After()[0])

	checkpoint, err := NewCheckpointDefinitionWithProviderInstances(
		string(policy.StagePreAuth), nil, []ProviderInstanceDefinition{primary, secondary},
	)
	compiledMetadataNoError(t, err)

	assert.Equal(t, []string{policy.AuthnProviderTLSEncryption, policy.AuthnProviderTLSEncryption}, checkpoint.Providers())

	instances := checkpoint.ProviderInstances()
	instances[0] = ProviderInstanceDefinition{}

	assert.Equal(t, "primary", checkpoint.ProviderInstances()[0].Name())
}

func TestDomainPlanAndTargetActivationRetainCompiledConfigurationMetadata(t *testing.T) {
	target, err := decision.NewTarget("mail", "submit")
	compiledMetadataNoError(t, err)

	checkpoint, err := NewCheckpointDefinition(decision.CheckpointFinalDecision, nil, nil)
	compiledMetadataNoError(t, err)

	expression, err := NewPolicyExpression(PolicyExpressionInput{Kind: ExpressionKindAlways})
	compiledMetadataNoError(t, err)

	guard, err := NewSchedulerGuardDefinition(SchedulerGuardDefinitionInput{
		Path: "policy.namespaces.mail.domain_plans.submit.scheduler_guards.business_hours",
		Name: "business_hours", Expression: expression,
	})
	compiledMetadataNoError(t, err)

	plan, err := NewDomainPlanDefinitionWithSchedulerGuards(target, []CheckpointDefinition{checkpoint}, []SchedulerGuardDefinition{guard})
	compiledMetadataNoError(t, err)

	guards := plan.SchedulerGuards()
	if !assert.Len(t, guards, 1) {
		return
	}

	assert.Equal(t, "business_hours", guards[0].Name())
	assert.NotEmpty(t, guards[0].Path())
	assert.Equal(t, schedulerGuardOnMissingRun, guards[0].OnMissingAttribute())
	assert.True(t, guards[0].Expression().Equal(expression))

	guards[0] = SchedulerGuardDefinition{}

	assert.Equal(t, "business_hours", plan.SchedulerGuards()[0].Name())

	activation, err := NewTargetActivation("policy.targets[0]", "mail", "submit", "mail/submit/v1")
	compiledMetadataNoError(t, err)

	report := NewTargetReportSettings(true, false, true, true)

	activation, err = activation.WithReport(report)
	compiledMetadataNoError(t, err)
	assert.True(t, activation.Report().Enabled())
	assert.False(t, activation.Report().IncludeFSM())
	assert.True(t, activation.Report().IncludeChecks())
	assert.True(t, activation.Report().IncludeAttributes())
}

// compiledMetadataNoError stops a metadata test before zero-value access after constructor failure.
func compiledMetadataNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}
