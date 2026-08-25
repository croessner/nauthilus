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

package policyprovider_test

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/lualib/policyprovider"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

func TestLuaContributionAdapterBuildsOnlyProviderAndEffectDefinitions(t *testing.T) {
	ownership := mustNamespaceOwnership(t, "lua.risk", []string{"mail"})

	adapter, err := policyprovider.NewDefinitionAdapter(ownership, "risk")
	if err != nil {
		t.Fatalf("NewDefinitionAdapter() error = %v", err)
	}

	factDescriptor := validFactProviderDescriptor()
	effectDescriptor := validEffectProviderDescriptor()

	contribution, err := adapter.Adapt(
		[]policyprovider.FactProviderDescriptor{factDescriptor},
		[]policyprovider.EffectProviderDescriptor{effectDescriptor},
	)
	if err != nil {
		t.Fatalf("Adapt() error = %v", err)
	}

	if err := contribution.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	assertLuaContributionSections(t, contribution)
	assertLuaContributionProviders(t, contribution)
	assertLuaContributionEffects(t, contribution)
}

// assertLuaContributionSections proves the adapter cannot contribute catalog-owned sections.
func assertLuaContributionSections(t *testing.T, contribution registry.DefinitionContribution) {
	t.Helper()

	if len(contribution.Targets()) != 0 || len(contribution.Schemas()) != 0 ||
		len(contribution.PolicySets()) != 0 || len(contribution.Plans()) != 0 {
		t.Fatal("Lua adapter contributed catalog-owned definitions")
	}
}

// assertLuaContributionProviders verifies host-derived provider and fact identities.
func assertLuaContributionProviders(t *testing.T, contribution registry.DefinitionContribution) {
	t.Helper()

	providers := contribution.Providers()
	if len(providers) != 2 {
		t.Fatalf("Providers() length = %d, want 2", len(providers))
	}

	if providers[0].ID() != "mail/lua.risk.reputation" || len(providers[0].Executions()) != 0 {
		t.Fatalf("fact provider = %q executions %#v", providers[0].ID(), providers[0].Executions())
	}

	if got := providers[0].ProducedFacts(); len(got) != 1 || got[0] != "lua.risk.risk.score" {
		t.Fatalf("ProducedFacts() = %#v", got)
	}

	assertLuaProviderOutput(t, providers[0])

	if providers[1].ID() != "mail/lua.risk.audit" {
		t.Fatalf("effect provider ID = %q", providers[1].ID())
	}
}

// assertLuaProviderOutput verifies the complete typed fact-output metadata.
func assertLuaProviderOutput(t *testing.T, provider registry.ProviderDefinition) {
	t.Helper()

	outputs := provider.Outputs()
	if len(outputs) != 1 {
		t.Fatalf("Outputs() length = %d, want 1", len(outputs))
	}

	output := outputs[0]
	if output.ID() != "lua.risk.risk.score" ||
		output.Category() != decision.FactCategoryEnvironment ||
		output.Kind() != decision.ValueKindString ||
		output.MaxLength() != 64 || output.MaxItems() != 0 || output.MaxBytes() != 0 {
		t.Fatalf("typed output = %#v", output)
	}
}

// assertLuaContributionEffects verifies host-derived selected-effect bindings.
func assertLuaContributionEffects(t *testing.T, contribution registry.DefinitionContribution) {
	t.Helper()

	effects := contribution.Effects()
	if len(effects) != 1 || effects[0].ID() != "mail/record-audit" || effects[0].Provider() != "mail/lua.risk.audit" {
		t.Fatalf("Effects() = %#v", effects)
	}
}

func TestLuaContributionAdapterRejectsForeignDefinitionNamespaceAndInvalidAuthority(t *testing.T) {
	ownership := mustNamespaceOwnership(t, "lua.risk", []string{"mail"})

	if _, err := policyprovider.NewDefinitionAdapter(ownership, "other.provider"); err == nil {
		t.Fatal("NewDefinitionAdapter(invalid authority) error = nil")
	}

	mismatchedOwnership := mustNamespaceOwnership(t, "lua.other", []string{"mail"})
	if _, err := policyprovider.NewDefinitionAdapter(mismatchedOwnership, "risk"); err == nil {
		t.Fatal("NewDefinitionAdapter(mismatched owner) error = nil")
	}

	adapter, err := policyprovider.NewDefinitionAdapter(ownership, "risk")
	if err != nil {
		t.Fatalf("NewDefinitionAdapter() error = %v", err)
	}

	factDescriptor := validFactProviderDescriptor()

	factDescriptor.Namespace = "foreign"
	if _, err = adapter.Adapt([]policyprovider.FactProviderDescriptor{factDescriptor}, nil); err == nil {
		t.Fatal("Adapt(foreign fact namespace) error = nil")
	}

	effectDescriptor := validEffectProviderDescriptor()

	effectDescriptor.Namespace = "foreign"
	if _, err = adapter.Adapt(nil, []policyprovider.EffectProviderDescriptor{effectDescriptor}); err == nil {
		t.Fatal("Adapt(foreign effect namespace) error = nil")
	}
}

func TestLuaContributionTargetSelectorsAreExactCapabilityReferences(t *testing.T) {
	ownership := mustNamespaceOwnership(t, "lua.risk", []string{"mail"})

	adapter, err := policyprovider.NewDefinitionAdapter(ownership, "risk")
	if err != nil {
		t.Fatalf("NewDefinitionAdapter() error = %v", err)
	}

	descriptor := validFactProviderDescriptor()

	descriptor.Targets[0].Namespace = "authn"

	contribution, err := adapter.Adapt([]policyprovider.FactProviderDescriptor{descriptor}, nil)
	if err != nil {
		t.Fatalf("Adapt(cross-namespace target) error = %v", err)
	}

	targets := contribution.Providers()[0].Targets()
	if len(targets) != 1 || targets[0].String() != "authn/authenticate" {
		t.Fatalf("Targets() = %#v", targets)
	}
}

func TestLuaContributionAdapterDeeplyOwnsDescriptorValues(t *testing.T) {
	ownership := mustNamespaceOwnership(t, "lua.risk", []string{"mail"})

	adapter, err := policyprovider.NewDefinitionAdapter(ownership, "risk")
	if err != nil {
		t.Fatalf("NewDefinitionAdapter() error = %v", err)
	}

	factDescriptor := validFactProviderDescriptor()
	effectDescriptor := validEffectProviderDescriptor()

	contribution, err := adapter.Adapt(
		[]policyprovider.FactProviderDescriptor{factDescriptor},
		[]policyprovider.EffectProviderDescriptor{effectDescriptor},
	)
	if err != nil {
		t.Fatalf("Adapt() error = %v", err)
	}

	factDescriptor.Targets[0].Namespace = "changed"
	factDescriptor.Outputs[0].Name = "changed"
	factDescriptor.Outputs[0].Category = decision.FactCategorySubject
	factDescriptor.Outputs[0].Kind = decision.ValueKindBytes
	factDescriptor.Outputs[0].MaxLength = 0
	factDescriptor.Outputs[0].MaxBytes = 1
	effectDescriptor.Effects[0].Targets[0].Action = "changed"
	effectDescriptor.Effects[0].Parameters[0].AllowedStrings[0] = "changed"

	providers := contribution.Providers()
	providers[0].Targets()[0] = mustPolicyTarget(t, "changed", "changed")

	if got := contribution.Providers()[0].Targets()[0].String(); got != "authn/authenticate" {
		t.Fatalf("owned provider target = %q", got)
	}

	if got := contribution.Providers()[0].ProducedFacts()[0]; got != "lua.risk.risk.score" {
		t.Fatalf("owned output = %q", got)
	}

	returnedOutputs := contribution.Providers()[0].Outputs()
	returnedOutputs[0] = registry.ProviderFactOutput{}

	ownedOutput := contribution.Providers()[0].Outputs()[0]
	if ownedOutput.ID() != "lua.risk.risk.score" ||
		ownedOutput.Category() != decision.FactCategoryEnvironment ||
		ownedOutput.Kind() != decision.ValueKindString || ownedOutput.MaxLength() != 64 {
		t.Fatalf("owned typed output = %#v", ownedOutput)
	}

	parameter := contribution.Effects()[0].Parameters()[0]
	if got := parameter.AllowedStrings()[0]; got != "accepted" {
		t.Fatalf("owned allowed string = %q", got)
	}
}

func TestLuaContributionAdapterRejectsEmptyAndDuplicateDefinitions(t *testing.T) {
	ownership := mustNamespaceOwnership(t, "lua.risk", []string{"mail"})

	adapter, err := policyprovider.NewDefinitionAdapter(ownership, "risk")
	if err != nil {
		t.Fatalf("NewDefinitionAdapter() error = %v", err)
	}

	if _, err = adapter.Adapt(nil, nil); err == nil {
		t.Fatal("Adapt(empty) error = nil")
	}

	descriptor := validFactProviderDescriptor()
	if _, err = adapter.Adapt([]policyprovider.FactProviderDescriptor{descriptor, descriptor}, nil); err == nil {
		t.Fatal("Adapt(duplicate providers) error = nil")
	}
}

// mustNamespaceOwnership constructs one host-assigned namespace fixture.
func mustNamespaceOwnership(t *testing.T, owner string, namespaces []string) registry.NamespaceOwnership {
	t.Helper()

	ownership, err := registry.NewNamespaceOwnership(owner, namespaces)
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	return ownership
}

// mustPolicyTarget constructs one exact target fixture.
func mustPolicyTarget(t *testing.T, namespace string, action string) decision.Target {
	t.Helper()

	target, err := decision.NewTarget(namespace, action)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return target
}
