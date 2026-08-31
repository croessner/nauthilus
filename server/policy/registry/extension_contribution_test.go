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

package registry

import (
	"errors"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

func TestExtensionContributionAcceptsFactOnlyProviderAndCapabilityTargets(t *testing.T) {
	fixture := newExtensionContributionFixture(t)
	contribution := fixture.contribution

	if len(contribution.Targets()) != 0 || len(contribution.Schemas()) != 0 || len(contribution.Plans()) != 0 {
		t.Fatal("extension contribution unexpectedly owns catalog structure")
	}

	if providers := contribution.Providers(); len(providers) != 2 || !providers[0].Scheduled() || len(providers[0].Executions()) != 0 {
		t.Fatalf("Providers() = %#v, want a scheduled fact-only provider and one effect provider", providers)
	}

	if effects := contribution.Effects(); len(effects) != 1 || !effects[0].AllowsTarget(fixture.authnTarget) {
		t.Fatalf("Effects() = %#v, want exact authn capability selector", effects)
	}
}

func TestExtensionContributionDeeplyOwnsProviderAndEffectMetadata(t *testing.T) {
	fixture := newExtensionContributionFixture(t)
	contribution := fixture.contribution

	fixture.factTargets[0] = fixture.mailTarget
	fixture.factOutputs[0] = ProviderFactOutput{}
	returnedProviders := contribution.Providers()
	returnedProviders[0].targets[0] = fixture.mailTarget
	returnedProviders[0].producedFacts[0] = "plugin.native.returned_mutation"
	returnedProviders[0].outputs[0] = ProviderFactOutput{}
	returnedEffects := contribution.Effects()
	returnedEffects[0].parameters[0].allowedStrings[0] = "mutated"

	ownedProviders := contribution.Providers()
	if got := ownedProviders[0].Targets()[0].String(); got != fixture.authnTarget.String() {
		t.Fatalf("owned provider target = %q, want %q", got, fixture.authnTarget.String())
	}

	if got := ownedProviders[0].ProducedFacts()[0]; got != "plugin.native.risk_score" {
		t.Fatalf("owned produced fact = %q", got)
	}

	ownedOutput := ownedProviders[0].Outputs()[0]
	if ownedOutput.ID() != "plugin.native.risk_score" || ownedOutput.Category() != decision.FactCategoryEnvironment ||
		ownedOutput.Kind() != decision.ValueKindString || ownedOutput.MaxLength() != 64 {
		t.Fatalf("owned typed fact output = %#v", ownedOutput)
	}

	if got := contribution.Effects()[0].Parameters()[0].AllowedStrings()[0]; got != "strict" {
		t.Fatalf("owned parameter enum = %q, want strict", got)
	}
}

// extensionContributionFixture owns mutable inputs and the detached contribution built from them.
type extensionContributionFixture struct {
	contribution DefinitionContribution
	factTargets  []decision.Target
	factOutputs  []ProviderFactOutput
	authnTarget  decision.Target
	mailTarget   decision.Target
}

// newExtensionContributionFixture constructs one fact/effect capability contribution for focused assertions.
func newExtensionContributionFixture(t *testing.T) extensionContributionFixture {
	t.Helper()

	authnTarget := mustExtensionTarget(t, "authn", "authenticate")
	mailTarget := mustExtensionTarget(t, "mail", "submit")
	factTargets := []decision.Target{authnTarget, mailTarget}
	factOutput := mustProviderFactOutput(t, ProviderFactOutputInput{
		ID:        "plugin.native.risk_score",
		Category:  decision.FactCategoryEnvironment,
		Kind:      decision.ValueKindString,
		MaxLength: 64,
	})
	factOutputs := []ProviderFactOutput{factOutput}
	factProvider := mustExtensionProvider(t, ProviderDefinitionInput{
		ID:      "mail/plugin.native.risk",
		Targets: factTargets,
		Outputs: factOutputs,
		Failure: ProviderFailureIndeterminate,
		Timeout: time.Second,
	})
	effectProvider := mustExtensionProvider(t, ProviderDefinitionInput{
		ID:         "mail/plugin.native.effects",
		Targets:    []decision.Target{authnTarget},
		Executions: []ExecutionClass{ExecutionHostSync},
	})
	parameter := mustExtensionParameter(t, ParameterSchemaInput{
		Name:           "mode",
		Kind:           decision.ValueKindString,
		MaxLength:      16,
		AllowedStrings: []string{"strict", "audit"},
		Required:       true,
	})
	effect := mustExtensionEffect(t, EffectDefinitionInput{
		ID:         "mail/quarantine",
		Provider:   effectProvider.ID(),
		Targets:    []decision.Target{authnTarget},
		Parameters: []ParameterSchema{parameter},
		Kind:       EffectKindObligation,
		Execution:  ExecutionHostSync,
	})

	contribution, err := NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
		Ownership: mustOwnership(t, "plugin.native", "mail"),
		Providers: []ExtensionProviderDefinition{
			{Definition: factProvider, ProducedFactPrefix: "plugin.native."},
			{Definition: effectProvider},
		},
		Effects: []EffectDefinition{effect},
	})
	if err != nil {
		t.Fatalf("NewExtensionDefinitionContribution() error = %v", err)
	}

	return extensionContributionFixture{
		contribution: contribution,
		factTargets:  factTargets,
		factOutputs:  factOutputs,
		authnTarget:  authnTarget,
		mailTarget:   mailTarget,
	}
}

func TestExtensionContributionRequiresTypedProviderFactOutputs(t *testing.T) {
	target := mustExtensionTarget(t, "authn", "authenticate")
	ownership := mustOwnership(t, "plugin.native", "mail")

	provider := mustExtensionProvider(t, ProviderDefinitionInput{
		ID:            "mail/plugin.native.risk",
		Targets:       []decision.Target{target},
		ProducedFacts: []string{"plugin.native.score"},
		Failure:       ProviderFailureIndeterminate,
		Timeout:       time.Second,
	})

	_, err := NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
		Ownership: ownership,
		Providers: []ExtensionProviderDefinition{{
			Definition:         provider,
			ProducedFactPrefix: "plugin.native.",
		}},
	})
	if !errors.Is(err, ErrInvalidProviderDefinition) {
		t.Fatalf("missing typed outputs error = %v, want invalid provider definition", err)
	}
}

func TestProviderFactOutputRejectsInvalidIdentityAndShape(t *testing.T) {
	tests := []ProviderFactOutputInput{
		{ID: "plugin.Native.score", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindString, MaxLength: 64},
		{ID: "plugin.native.score", Category: "identity", Kind: decision.ValueKindString, MaxLength: 64},
		{ID: "plugin.native.score", Category: decision.FactCategoryEnvironment, Kind: "json"},
		{ID: "plugin.native.score", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindString},
		{ID: "plugin.native.score", Category: decision.FactCategoryEnvironment, Kind: decision.ValueKindBoolean, MaxLength: 1},
	}

	for _, input := range tests {
		if _, err := NewProviderFactOutput(input); !errors.Is(err, ErrInvalidProviderDefinition) {
			t.Fatalf("NewProviderFactOutput(%#v) error = %v, want invalid provider definition", input, err)
		}
	}
}

func TestProviderDefinitionRejectsMismatchedTypedFactOutputs(t *testing.T) {
	target := mustExtensionTarget(t, "authn", "authenticate")
	output := mustProviderFactOutput(t, ProviderFactOutputInput{
		ID:       "plugin.native.score",
		Category: decision.FactCategoryEnvironment,
		Kind:     decision.ValueKindBoolean,
	})

	_, err := NewProviderDefinition(ProviderDefinitionInput{
		ID:            "mail/plugin.native.risk",
		Targets:       []decision.Target{target},
		ProducedFacts: []string{"plugin.native.other"},
		Outputs:       []ProviderFactOutput{output},
		Failure:       ProviderFailureIndeterminate,
		Timeout:       time.Second,
	})
	if !errors.Is(err, ErrInvalidProviderDefinition) {
		t.Fatalf("mismatched output error = %v, want invalid provider definition", err)
	}

	_, err = NewProviderDefinition(ProviderDefinitionInput{
		ID:      "mail/plugin.native.risk",
		Targets: []decision.Target{target},
		Outputs: []ProviderFactOutput{output, output},
		Failure: ProviderFailureIndeterminate,
		Timeout: time.Second,
	})
	if !errors.Is(err, ErrDuplicateDefinition) {
		t.Fatalf("duplicate output error = %v, want duplicate definition", err)
	}
}

func TestExtensionContributionRejectsInvalidProducedFactAuthorityPrefix(t *testing.T) {
	target := mustExtensionTarget(t, "authn", "authenticate")
	ownership := mustOwnership(t, "plugin.native", "mail")

	tests := []struct {
		name   string
		facts  []string
		prefix string
	}{
		{name: "missing prefix", facts: []string{"plugin.native.score"}},
		{name: "foreign authority", facts: []string{"plugin.foreign.score"}, prefix: "plugin.native."},
		{name: "uppercase authority", facts: []string{"plugin.native.score"}, prefix: "plugin.Native."},
		{name: "missing trailing separator", facts: []string{"plugin.native.score"}, prefix: "plugin.native"},
		{name: "unsupported source", facts: []string{"backend.native.score"}, prefix: "backend.native."},
		{name: "unused prefix", prefix: "plugin.native."},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outputs := make([]ProviderFactOutput, 0, len(test.facts))
			for _, factID := range test.facts {
				outputs = append(outputs, mustProviderFactOutput(t, ProviderFactOutputInput{
					ID:       factID,
					Category: decision.FactCategoryEnvironment,
					Kind:     decision.ValueKindBoolean,
				}))
			}

			provider := mustExtensionProvider(t, ProviderDefinitionInput{
				ID:            "mail/plugin.native.risk",
				Targets:       []decision.Target{target},
				Executions:    []ExecutionClass{ExecutionHostSync},
				ProducedFacts: test.facts,
				Outputs:       outputs,
				Failure:       ProviderFailureIndeterminate,
				Timeout:       time.Second,
			})

			_, err := NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
				Ownership: ownership,
				Providers: []ExtensionProviderDefinition{{
					Definition:         provider,
					ProducedFactPrefix: test.prefix,
				}},
			})
			if !errors.Is(err, ErrInvalidProviderDefinition) {
				t.Fatalf("NewExtensionDefinitionContribution() error = %v, want invalid provider definition", err)
			}
		})
	}
}

func TestExtensionContributionRejectsFactAuthorityUnboundFromProviderIdentity(t *testing.T) {
	target := mustExtensionTarget(t, "authn", "authenticate")
	output := mustProviderFactOutput(t, ProviderFactOutputInput{
		ID:       "plugin.foreign.score",
		Category: decision.FactCategoryEnvironment,
		Kind:     decision.ValueKindBoolean,
	})
	provider := mustExtensionProvider(t, ProviderDefinitionInput{
		ID:      "mail/plugin.native.risk",
		Targets: []decision.Target{target},
		Outputs: []ProviderFactOutput{output},
		Failure: ProviderFailureIndeterminate,
		Timeout: time.Second,
	})

	_, err := NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
		Ownership: mustOwnership(t, "plugin.native", "mail"),
		Providers: []ExtensionProviderDefinition{{
			Definition:         provider,
			ProducedFactPrefix: "plugin.foreign.",
		}},
	})
	if !errors.Is(err, ErrInvalidProviderDefinition) {
		t.Fatalf("foreign provider authority error = %v, want invalid provider definition", err)
	}
}

func TestExtensionContributionRejectsForeignDefinitionNamespaces(t *testing.T) {
	target := mustExtensionTarget(t, "authn", "authenticate")
	ownership := mustOwnership(t, "plugin.native", "mail")
	foreignProvider := mustExtensionProvider(t, ProviderDefinitionInput{
		ID:         "mcp/plugin.native.effect",
		Targets:    []decision.Target{target},
		Executions: []ExecutionClass{ExecutionHostSync},
	})

	_, err := NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
		Ownership: ownership,
		Providers: []ExtensionProviderDefinition{{Definition: foreignProvider}},
	})
	if !errors.Is(err, ErrNamespaceOwnership) {
		t.Fatalf("foreign provider error = %v, want namespace ownership", err)
	}

	ownedProvider := mustExtensionProvider(t, ProviderDefinitionInput{
		ID:         "mail/plugin.native.effect",
		Targets:    []decision.Target{target},
		Executions: []ExecutionClass{ExecutionHostSync},
	})
	foreignEffect := mustExtensionEffect(t, EffectDefinitionInput{
		ID:        "mcp/quarantine",
		Provider:  ownedProvider.ID(),
		Targets:   []decision.Target{target},
		Kind:      EffectKindObligation,
		Execution: ExecutionHostSync,
	})

	_, err = NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
		Ownership: ownership,
		Providers: []ExtensionProviderDefinition{{Definition: ownedProvider}},
		Effects:   []EffectDefinition{foreignEffect},
	})
	if !errors.Is(err, ErrNamespaceOwnership) {
		t.Fatalf("foreign effect error = %v, want namespace ownership", err)
	}
}

func TestExtensionContributionRejectsForgedTargetSelectors(t *testing.T) {
	target := mustExtensionTarget(t, "authn", "authenticate")
	ownership := mustOwnership(t, "plugin.native", "mail")
	provider := ProviderDefinition{
		id:         "mail/plugin.native.risk",
		targets:    []decision.Target{target, target},
		executions: []ExecutionClass{ExecutionHostSync},
	}

	_, err := NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
		Ownership: ownership,
		Providers: []ExtensionProviderDefinition{{Definition: provider}},
	})
	if !errors.Is(err, ErrDuplicateDefinition) {
		t.Fatalf("duplicate provider target error = %v, want duplicate definition", err)
	}

	effect := EffectDefinition{
		id:        "mail/quarantine",
		provider:  "mail/plugin.native.risk",
		targets:   []decision.Target{{}},
		kind:      EffectKindObligation,
		execution: ExecutionHostSync,
	}

	_, err = NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
		Ownership: ownership,
		Effects:   []EffectDefinition{effect},
	})
	if !errors.Is(err, ErrInvalidEffectDefinition) {
		t.Fatalf("invalid effect target error = %v, want invalid effect definition", err)
	}
}

// mustExtensionTarget constructs one exact capability selector.
func mustExtensionTarget(t *testing.T, namespace string, action string) decision.Target {
	t.Helper()

	target, err := decision.NewTarget(namespace, action)
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	return target
}

// mustExtensionProvider constructs one internal provider descriptor.
func mustExtensionProvider(t *testing.T, input ProviderDefinitionInput) ProviderDefinition {
	t.Helper()

	provider, err := NewProviderDefinition(input)
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	return provider
}

// mustExtensionEffect constructs one internal effect descriptor.
func mustExtensionEffect(t *testing.T, input EffectDefinitionInput) EffectDefinition {
	t.Helper()

	effect, err := NewEffectDefinition(input)
	if err != nil {
		t.Fatalf("NewEffectDefinition() error = %v", err)
	}

	return effect
}

// mustExtensionParameter constructs one typed effect parameter descriptor.
func mustExtensionParameter(t *testing.T, input ParameterSchemaInput) ParameterSchema {
	t.Helper()

	parameter, err := NewParameterSchema(input)
	if err != nil {
		t.Fatalf("NewParameterSchema() error = %v", err)
	}

	return parameter
}

// mustProviderFactOutput constructs one typed provider output descriptor.
func mustProviderFactOutput(t *testing.T, input ProviderFactOutputInput) ProviderFactOutput {
	t.Helper()

	output, err := NewProviderFactOutput(input)
	if err != nil {
		t.Fatalf("NewProviderFactOutput() error = %v", err)
	}

	return output
}
