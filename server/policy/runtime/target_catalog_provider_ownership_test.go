// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package runtime

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// TestAuthnGenericNativeProviderRemainsEvaluatorOwned protects decision fact-provider scheduling.
func TestAuthnGenericNativeProviderRemainsEvaluatorOwned(t *testing.T) {
	target := authnProviderOwnershipTarget(t)
	provider := authnProviderOwnershipDefinition(t, registry.ProviderDefinitionInput{
		ID:            "authn/plugin.geoip.environment",
		Targets:       []decision.Target{target},
		ProducedFacts: []string{"plugin.geoip.matched"},
		Failure:       registry.ProviderFailureIndeterminate,
		Timeout:       500 * time.Millisecond,
	})
	compiled := CompiledTarget{
		target:    target,
		providers: map[string]registry.ProviderDefinition{provider.ID(): provider},
	}

	if compiled.HostPreparesProvider(provider.ID()) {
		t.Fatal("HostPreparesProvider() = true, want evaluator-owned generic provider")
	}
}

// TestAuthnPublicSourceProviderRemainsHostOwned protects legacy auth source execution.
func TestAuthnPublicSourceProviderRemainsHostOwned(t *testing.T) {
	target := authnProviderOwnershipTarget(t)
	provider := authnProviderOwnershipDefinition(t, registry.ProviderDefinitionInput{
		ID:         "authn/plugin.rns_auth.environment",
		Targets:    []decision.Target{target},
		Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
	})
	compiled := CompiledTarget{
		target:    target,
		providers: map[string]registry.ProviderDefinition{provider.ID(): provider},
	}

	if !compiled.HostPreparesProvider(provider.ID()) {
		t.Fatal("HostPreparesProvider() = false, want host-owned auth source provider")
	}
}

// authnProviderOwnershipTarget constructs the exact authentication target.
func authnProviderOwnershipTarget(t *testing.T) decision.Target {
	t.Helper()

	target, err := decision.NewTarget("authn", "authenticate")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return target
}

// authnProviderOwnershipDefinition constructs one validated provider definition.
func authnProviderOwnershipDefinition(
	t *testing.T,
	input registry.ProviderDefinitionInput,
) registry.ProviderDefinition {
	t.Helper()

	provider, err := registry.NewProviderDefinition(input)
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	return provider
}
