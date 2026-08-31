// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package runtime

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	"github.com/stretchr/testify/assert"
)

func TestCompiledProviderInstancesRetainAuthoredIdentityAndSharedUse(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	shared := providerInstanceDefinition(t, target, "mail/shared", nil)
	instances := []registry.ProviderInstanceDefinition{
		providerInstance(t, "providers[0]", "primary", shared.ID(), nil),
		providerInstance(t, "providers[1]", "secondary", shared.ID(), []string{"primary"}),
	}
	guard := providerInstanceGuard(t)
	report := registry.NewTargetReportSettings(true, false, true, true)
	record := providerInstanceRecord(t, target, schema, []registry.ProviderDefinition{shared}, instances, []registry.SchedulerGuardDefinition{guard}, report)

	catalog, err := NewTargetCatalog([]TargetCatalogRecord{record})
	providerInstanceNoError(t, err)

	compiled, ok := catalog.Lookup(target)
	assert.True(t, ok)
	assertCompiledProviderTarget(t, compiled, shared.ID())
}

// assertCompiledProviderTarget verifies retained target, guard, and checkpoint metadata.
func assertCompiledProviderTarget(t *testing.T, compiled CompiledTarget, sharedUse string) {
	t.Helper()

	assert.True(t, compiled.Report().Enabled())
	assert.False(t, compiled.Report().IncludeFSM())
	assert.True(t, compiled.Report().IncludeChecks())
	assert.True(t, compiled.Report().IncludeAttributes())

	plan := compiled.DomainPlan()
	compiledGuard, ok := plan.SchedulerGuard("trusted_client")
	assert.True(t, ok)
	assert.Equal(t, "run", compiledGuard.OnMissingAttribute())
	assert.True(t, compiledGuard.Expression().Valid())

	guards := plan.SchedulerGuards()
	if !assert.Len(t, guards, 1) {
		return
	}

	guards[0] = registry.SchedulerGuardDefinition{}

	assert.Equal(t, "trusted_client", plan.SchedulerGuards()[0].Name())

	checkpoint, ok := plan.Checkpoint(decision.CheckpointFinalDecision)
	assert.True(t, ok)
	assertCompiledProviderCheckpoint(t, checkpoint, sharedUse)
}

// assertCompiledProviderCheckpoint verifies immutable instances and dependency levels.
func assertCompiledProviderCheckpoint(t *testing.T, checkpoint CompiledCheckpoint, sharedUse string) {
	t.Helper()

	assert.Equal(t, []string{sharedUse, sharedUse}, checkpoint.ProviderIDs())

	compiledInstances := checkpoint.ProviderInstances()
	if !assert.Len(t, compiledInstances, 2) {
		return
	}

	assert.Equal(t, "primary", compiledInstances[0].Name())
	assert.Empty(t, compiledInstances[0].RunIfAuthState())
	assert.Equal(t, "secondary", compiledInstances[1].Name())
	assert.Equal(t, sharedUse, compiledInstances[1].Use())
	assert.Equal(t, []string{"primary"}, compiledInstances[1].After())
	assert.Equal(t, []string{"primary"}, compiledInstances[1].Dependencies())
	assert.Equal(t, [][]string{{"primary"}, {"secondary"}}, checkpoint.ProviderLevels())

	lookup, ok := checkpoint.LookupProviderInstance("secondary")
	assert.True(t, ok)
	assert.Equal(t, "secondary", lookup.Name())

	compiledInstances[1] = CompiledProviderInstance{}

	assert.Equal(t, "secondary", checkpoint.ProviderInstances()[1].Name())
}

func TestCompiledProviderDependenciesMergeDefinitionRequiresAndInstanceAfter(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	base := providerInstanceDefinition(t, target, "mail/base", nil)
	dependent := providerInstanceDefinition(t, target, "mail/dependent", []string{base.ID()})
	final := providerInstanceDefinition(t, target, "mail/final", nil)
	instances := []registry.ProviderInstanceDefinition{
		providerInstance(t, "providers[0]", "primary", base.ID(), nil),
		providerInstance(t, "providers[1]", "dependent", dependent.ID(), nil),
		providerInstance(t, "providers[2]", "final", final.ID(), []string{"dependent"}),
	}
	record := providerInstanceRecord(
		t, target, schema, []registry.ProviderDefinition{base, dependent, final}, instances, nil,
		registry.TargetReportSettings{},
	)

	catalog, err := NewTargetCatalog([]TargetCatalogRecord{record})
	if err != nil {
		t.Fatalf("NewTargetCatalog() error = %v", err)
	}

	compiled, _ := catalog.Lookup(target)
	checkpoint, _ := compiled.DomainPlan().Checkpoint(decision.CheckpointFinalDecision)
	dependentInstance, _ := checkpoint.LookupProviderInstance("dependent")

	if !slices.Equal(dependentInstance.Dependencies(), []string{"primary"}) {
		t.Fatalf("dependent dependencies = %v", dependentInstance.Dependencies())
	}

	if got := checkpoint.ProviderLevels(); len(got) != 3 ||
		!slices.Equal(got[0], []string{"primary"}) ||
		!slices.Equal(got[1], []string{"dependent"}) ||
		!slices.Equal(got[2], []string{"final"}) {
		t.Fatalf("ProviderLevels() = %v", got)
	}
}

func TestTargetCatalogRejectsProviderInstanceRecordDrift(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	provider := providerInstanceDefinition(t, target, "mail/shared", nil)
	instances := []registry.ProviderInstanceDefinition{
		providerInstance(t, "providers[0]", "primary", provider.ID(), nil),
	}
	record := providerInstanceRecord(
		t, target, schema, []registry.ProviderDefinition{provider}, instances, nil,
		registry.TargetReportSettings{},
	)
	record.Checkpoints[0].ProviderInstances = []registry.ProviderInstanceDefinition{
		providerInstance(t, "providers[0]", "forged", provider.ID(), nil),
	}

	if _, err := NewTargetCatalog([]TargetCatalogRecord{record}); err == nil || !strings.Contains(err.Error(), "source schedule") {
		t.Fatalf("NewTargetCatalog(forged instance) error = %v", err)
	}
}

func TestTargetCatalogRejectsProviderIDsWithoutExactInstances(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	provider := providerInstanceDefinition(t, target, "mail/shared", nil)

	checkpoint, err := registry.NewCheckpointDefinition(
		decision.CheckpointFinalDecision,
		nil,
		[]string{provider.ID()},
	)
	if err != nil {
		t.Fatalf("NewCheckpointDefinition() error = %v", err)
	}

	plan, err := registry.NewDomainPlanDefinition(target, []registry.CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("NewDomainPlanDefinition() error = %v", err)
	}

	record := TargetCatalogRecord{
		Target: target, Schema: schema, SourcePlan: plan,
		Providers: []registry.ProviderDefinition{provider},
		Checkpoints: []CheckpointRecord{{
			Name: decision.CheckpointFinalDecision, ProviderIDs: []string{provider.ID()},
		}},
		NoMatch: registry.NoMatchDeny, AuthorityMode: registry.AuthorityModeEnforce,
	}

	if _, err = NewTargetCatalog([]TargetCatalogRecord{record}); err == nil ||
		!strings.Contains(err.Error(), "exact provider instances") {
		t.Fatalf("NewTargetCatalog(provider-ID-only projection) error = %v", err)
	}
}

func TestTargetCatalogRejectsAmbiguousDefinitionRequirementAcrossSharedUse(t *testing.T) {
	target, schema := completionRuntimeTargetAndSchema(t)
	shared := providerInstanceDefinition(t, target, "mail/shared", nil)
	dependent := providerInstanceDefinition(t, target, "mail/dependent", []string{shared.ID()})
	instances := []registry.ProviderInstanceDefinition{
		providerInstance(t, "providers[0]", "first", shared.ID(), nil),
		providerInstance(t, "providers[1]", "second", shared.ID(), nil),
		providerInstance(t, "providers[2]", "dependent", dependent.ID(), nil),
	}
	record := providerInstanceRecord(
		t, target, schema, []registry.ProviderDefinition{shared, dependent}, instances, nil,
		registry.TargetReportSettings{},
	)

	if _, err := NewTargetCatalog([]TargetCatalogRecord{record}); err == nil ||
		!strings.Contains(err.Error(), "ambiguous required use") {
		t.Fatalf("NewTargetCatalog(ambiguous requirement) error = %v", err)
	}
}

func TestRequiredProviderReferencesCompileToExactInstanceNames(t *testing.T) {
	primary := providerInstance(t, "providers[0]", "primary", "mail/shared", nil)
	alias := providerInstance(t, "providers[1]", "alias", "mail/shared", nil)

	if _, err := resolveRequiredProviderReferences(
		[]string{"mail/shared"},
		[]registry.ProviderInstanceDefinition{primary},
	); err == nil || !strings.Contains(err.Error(), "unscheduled provider instance") {
		t.Fatalf("resolveRequiredProviderReferences(qualified use) error = %v", err)
	}

	resolved, err := resolveRequiredProviderReferences([]string{"alias"}, []registry.ProviderInstanceDefinition{primary, alias})
	if err != nil || !slices.Equal(resolved, []string{"alias"}) {
		t.Fatalf("resolveRequiredProviderReferences(local name) = %v, %v", resolved, err)
	}

}

// providerInstanceNoError stops an instance test before zero-value access after constructor failure.
func providerInstanceNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

// providerInstanceDefinition constructs one scheduled provider descriptor.
func providerInstanceDefinition(
	t *testing.T,
	target decision.Target,
	id string,
	requires []string,
) registry.ProviderDefinition {
	t.Helper()

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID: id, Targets: []decision.Target{target}, Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
		Requires: requires, Failure: registry.ProviderFailureIndeterminate, Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition(%s) error = %v", id, err)
	}

	return provider
}

// providerInstance constructs one source-owned checkpoint provider instance.
func providerInstance(
	t *testing.T,
	path string,
	name string,
	use string,
	after []string,
) registry.ProviderInstanceDefinition {
	t.Helper()

	instance, err := registry.NewProviderInstanceDefinition(registry.ProviderInstanceDefinitionInput{
		Path: path, Name: name, Use: use, After: after,
	})
	if err != nil {
		t.Fatalf("NewProviderInstanceDefinition(%s) error = %v", name, err)
	}

	return instance
}

// providerInstanceGuard constructs one omitted-default scheduler guard.
func providerInstanceGuard(t *testing.T) registry.SchedulerGuardDefinition {
	t.Helper()

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindAlways,
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	guard, err := registry.NewSchedulerGuardDefinition(registry.SchedulerGuardDefinitionInput{
		Path: "policy.namespaces.mail.domain_plans.submit.scheduler_guards.trusted_client",
		Name: "trusted_client", Expression: expression,
	})
	if err != nil {
		t.Fatalf("NewSchedulerGuardDefinition() error = %v", err)
	}

	return guard
}

// providerInstanceRecord constructs one source-plan-backed generic runtime record.
func providerInstanceRecord(
	t *testing.T,
	target decision.Target,
	schema registry.SchemaDefinition,
	providers []registry.ProviderDefinition,
	instances []registry.ProviderInstanceDefinition,
	guards []registry.SchedulerGuardDefinition,
	report registry.TargetReportSettings,
) TargetCatalogRecord {
	t.Helper()

	checkpoint, err := registry.NewCheckpointDefinitionWithProviderInstances(
		decision.CheckpointFinalDecision, nil, instances,
	)
	if err != nil {
		t.Fatalf("NewCheckpointDefinitionWithProviderInstances() error = %v", err)
	}

	plan, err := registry.NewDomainPlanDefinitionWithSchedulerGuards(
		target, []registry.CheckpointDefinition{checkpoint}, guards,
	)
	if err != nil {
		t.Fatalf("NewDomainPlanDefinitionWithSchedulerGuards() error = %v", err)
	}

	uses := make([]string, 0, len(instances))
	for _, instance := range instances {
		uses = append(uses, instance.Use())
	}

	return TargetCatalogRecord{
		Target: target, Schema: schema, SourcePlan: plan, Providers: providers, Report: report,
		Checkpoints: []CheckpointRecord{{
			Name: decision.CheckpointFinalDecision, ProviderIDs: uses, ProviderInstances: instances,
		}},
		NoMatch: registry.NoMatchDeny, AuthorityMode: registry.AuthorityModeEnforce,
	}
}
