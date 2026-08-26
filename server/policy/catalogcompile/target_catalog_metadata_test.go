// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package catalogcompile

import (
	"context"
	"slices"
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

func TestPolicyCompiledPlanCompilerProjectsTargetReport(t *testing.T) {
	activation := mustCompilerActivation(
		t,
		"policy.targets[0]",
		"authn",
		"authenticate",
		"authn/authenticate/v1",
	)
	report := registry.NewTargetReportSettings(true, false, true, true)

	activation, err := activation.WithReport(report)
	if err != nil {
		t.Fatalf("TargetActivation.WithReport() error = %v", err)
	}

	catalog, err := NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributor(catalogAcceptanceCapability{}),
	).Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	target := mustCompilerTarget(t, "authn", "authenticate")

	compiled, ok := catalog.Lookup(target)
	if !ok {
		t.Fatal("compiled authn target is missing")
	}

	got := compiled.Report()
	if !got.Enabled() || got.IncludeFSM() || !got.IncludeChecks() || !got.IncludeAttributes() {
		t.Fatalf("compiled target report = %#v, want exact activation report", got)
	}
}

func TestPolicyCompiledPlanMergeRetainsDistinctProviderInstances(t *testing.T) {
	target := mustCompilerTarget(t, "authn", "authenticate")
	fallback := mustCompilerImport(t, "plan.fallback", "authn/standard_auth", target, "pre_auth")
	configured := mustCompilerImport(t, "target.configured", "authn/configured", target, "pre_auth")
	use := "authn/plugin.example.environment"

	primary := mustCompilerProviderInstance(t, registry.ProviderInstanceDefinitionInput{
		Path: "plan.providers[0]", Name: "primary", Use: use,
		Actions: []string{"authenticate"}, Output: "nauthilus.auth.primary_signal",
	})

	alias := mustCompilerProviderInstance(t, registry.ProviderInstanceDefinitionInput{
		Path: "plan.providers[1]", Name: "alias", Use: use,
		Actions: []string{"authenticate"}, After: []string{"primary"},
	})

	checkpoint := mustCompilerCheckpoint(t,
		"pre_auth",
		[]registry.PolicySetImport{fallback},
		[]registry.ProviderInstanceDefinition{primary, alias},
	)

	merged := mustMergeCheckpointBindings(t, checkpoint, []registry.PolicySetImport{configured})

	instances := merged.ProviderInstances()
	if len(instances) != 2 {
		t.Fatalf("merged provider instances = %#v, want distinct primary and alias", instances)
	}

	if got := []string{instances[0].Name(), instances[1].Name()}; !slices.Equal(got, []string{"primary", "alias"}) {
		t.Fatalf("merged provider instance names = %v, want distinct primary and alias", got)
	}

	if instances[0].Use() != instances[1].Use() {
		t.Fatalf("merged provider instance metadata = %#v, want shared use with retained dependency", instances)
	}

	if got := instances[1].After(); !slices.Equal(got, []string{"primary"}) {
		t.Fatalf("merged alias dependencies = %v, want retained primary dependency", got)
	}

	sets := merged.PolicySets()
	if len(sets) != 2 {
		t.Fatalf("merged policy sets = %#v, want configured authority before fallback", sets)
	}

	gotSets := []string{sets[0].Set().String(), sets[1].Set().String()}
	if !slices.Equal(gotSets, []string{"authn/configured", "authn/standard_auth"}) {
		t.Fatalf("merged policy sets = %v, want configured authority before fallback", gotSets)
	}
}

// mustCompilerProviderInstance constructs one provider instance for compiler metadata tests.
func mustCompilerProviderInstance(
	t *testing.T,
	input registry.ProviderInstanceDefinitionInput,
) registry.ProviderInstanceDefinition {
	t.Helper()

	instance, err := registry.NewProviderInstanceDefinition(input)
	if err != nil {
		t.Fatalf("NewProviderInstanceDefinition() error = %v", err)
	}

	return instance
}

// mustCompilerCheckpoint constructs one checkpoint with exact provider-instance metadata.
func mustCompilerCheckpoint(
	t *testing.T,
	name string,
	sets []registry.PolicySetImport,
	instances []registry.ProviderInstanceDefinition,
) registry.CheckpointDefinition {
	t.Helper()

	checkpoint, err := registry.NewCheckpointDefinitionWithProviderInstances(name, sets, instances)
	if err != nil {
		t.Fatalf("NewCheckpointDefinitionWithProviderInstances() error = %v", err)
	}

	return checkpoint
}

// mustMergeCheckpointBindings composes target-local bindings without dropping checkpoint metadata.
func mustMergeCheckpointBindings(
	t *testing.T,
	checkpoint registry.CheckpointDefinition,
	sets []registry.PolicySetImport,
) registry.CheckpointDefinition {
	t.Helper()

	merged, err := mergeCheckpointBindings(checkpoint, sets)
	if err != nil {
		t.Fatalf("mergeCheckpointBindings() error = %v", err)
	}

	return merged
}

// mustCompilerImport constructs one target-local set import for compiler metadata tests.
func mustCompilerImport(
	t *testing.T,
	path string,
	set string,
	target decision.Target,
	checkpoint string,
) registry.PolicySetImport {
	t.Helper()

	imported, err := registry.NewPolicySetImport(path, set, target, checkpoint, registry.ExportContract{})
	if err != nil {
		t.Fatalf("NewPolicySetImport() error = %v", err)
	}

	return imported
}
