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
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

func TestExtendBuiltinAuthnSchemasAddsBoundOutputsOnlyToExactActions(t *testing.T) {
	builtin, extended := mustExtendedBuiltinAuthnSchemas(t)

	assertExtendedBuiltinAuthnFacts(t, extended)
	assertBuiltinContributionMaterialUnchanged(t, builtin, extended)
	assertBuiltinAuthnInputUnchanged(t, builtin)
}

// mustExtendedBuiltinAuthnSchemas composes real native, Lua, non-authn, and schema-neutral fixtures.
func mustExtendedBuiltinAuthnSchemas(t *testing.T) (DefinitionContribution, DefinitionContribution) {
	t.Helper()

	builtin := mustBuiltinAuthnContribution(t)
	authenticate := mustExtensionTarget(t, policy.AuthnNamespace, builtinActionAuthenticate)
	lookup := mustExtensionTarget(t, policy.AuthnNamespace, builtinActionLookupIdentity)
	mailSubmit := mustExtensionTarget(t, "mail", "submit")

	extended, err := ExtendBuiltinAuthnSchemas(
		builtin,
		mustGeoIPAuthnExtensionContribution(t, authenticate, mailSubmit),
		mustLuaRiskAuthnExtensionContribution(t, lookup),
		mustMailAuditExtensionContribution(t, mailSubmit),
		mustEffectOnlyExtensionContribution(t, authenticate),
		mustReturnOnlyExtensionContribution(t, authenticate),
	)
	if err != nil {
		t.Fatalf("ExtendBuiltinAuthnSchemas() error = %v", err)
	}

	return builtin, extended
}

// mustGeoIPAuthnExtensionContribution constructs typed native outputs for one exact authn action.
func mustGeoIPAuthnExtensionContribution(
	t *testing.T,
	authenticate decision.Target,
	mailSubmit decision.Target,
) DefinitionContribution {
	t.Helper()

	return mustAuthnExtensionContribution(t, authnExtensionFixture{
		owner:     "plugin.geoip",
		namespace: policy.AuthnNamespace,
		provider:  "authn/plugin.geoip.environment",
		prefix:    "plugin.geoip.",
		targets:   []decision.Target{authenticate, mailSubmit},
		outputs: []ProviderFactOutputInput{
			{
				ID:        "plugin.geoip.country_iso",
				Category:  decision.FactCategoryEnvironment,
				Kind:      decision.ValueKindString,
				MaxLength: 64,
			},
			{
				ID:       "plugin.geoip.payload",
				Category: decision.FactCategoryResource,
				Kind:     decision.ValueKindBytes,
				MaxBytes: 512,
			},
		},
	})
}

// mustLuaRiskAuthnExtensionContribution constructs one typed Lua output for lookup_identity.
func mustLuaRiskAuthnExtensionContribution(t *testing.T, lookup decision.Target) DefinitionContribution {
	t.Helper()

	return mustAuthnExtensionContribution(t, authnExtensionFixture{
		owner:     "lua.risk",
		namespace: policy.AuthnNamespace,
		provider:  "authn/lua.risk.environment",
		prefix:    "lua.risk.",
		targets:   []decision.Target{lookup},
		outputs: []ProviderFactOutputInput{{
			ID:        "lua.risk.groups",
			Category:  decision.FactCategorySubject,
			Kind:      decision.ValueKindStrings,
			MaxLength: 32,
			MaxItems:  8,
		}},
	})
}

// mustMailAuditExtensionContribution constructs a non-authn contribution used to prove absence.
func mustMailAuditExtensionContribution(t *testing.T, mailSubmit decision.Target) DefinitionContribution {
	t.Helper()

	return mustAuthnExtensionContribution(t, authnExtensionFixture{
		owner:     "plugin.audit",
		namespace: "mail",
		provider:  "mail/plugin.audit.collect",
		prefix:    "plugin.audit.",
		targets:   []decision.Target{mailSubmit},
		outputs: []ProviderFactOutputInput{{
			ID:       "plugin.audit.accepted",
			Category: decision.FactCategoryEnvironment,
			Kind:     decision.ValueKindBoolean,
		}},
	})
}

// assertExtendedBuiltinAuthnFacts verifies exact per-action schema projection and absence.
func assertExtendedBuiltinAuthnFacts(
	t *testing.T,
	extended DefinitionContribution,
) {
	t.Helper()

	authenticateFacts := indexAuthnFactSchemas(
		builtinAuthnSchemaForAction(t, extended.Schemas(), builtinActionAuthenticate).Facts(),
	)
	assertExtensionFactSchema(t, authenticateFacts, ProviderFactOutputInput{
		ID:        "plugin.geoip.country_iso",
		Category:  decision.FactCategoryEnvironment,
		Kind:      decision.ValueKindString,
		MaxLength: 64,
	}, decision.FactSourcePlugin)
	assertExtensionFactSchema(t, authenticateFacts, ProviderFactOutputInput{
		ID:       "plugin.geoip.payload",
		Category: decision.FactCategoryResource,
		Kind:     decision.ValueKindBytes,
		MaxBytes: 512,
	}, decision.FactSourcePlugin)

	lookupFacts := indexAuthnFactSchemas(
		builtinAuthnSchemaForAction(t, extended.Schemas(), builtinActionLookupIdentity).Facts(),
	)
	assertExtensionFactSchema(t, lookupFacts, ProviderFactOutputInput{
		ID:        "lua.risk.groups",
		Category:  decision.FactCategorySubject,
		Kind:      decision.ValueKindStrings,
		MaxLength: 32,
		MaxItems:  8,
	}, decision.FactSourceLua)

	listFacts := indexAuthnFactSchemas(
		builtinAuthnSchemaForAction(t, extended.Schemas(), builtinActionListAccounts).Facts(),
	)
	for _, facts := range []map[string]FactSchema{authenticateFacts, lookupFacts, listFacts} {
		if _, exists := facts["plugin.audit.accepted"]; exists {
			t.Fatal("non-authn provider fact leaked into a builtin authn schema")
		}
	}

	if _, exists := lookupFacts["plugin.geoip.country_iso"]; exists {
		t.Fatal("authenticate-only native fact leaked into lookup_identity")
	}

	if _, exists := authenticateFacts["lua.risk.groups"]; exists {
		t.Fatal("lookup-only Lua fact leaked into authenticate")
	}
}

// assertBuiltinAuthnInputUnchanged verifies extension composition did not mutate the input contribution.
func assertBuiltinAuthnInputUnchanged(t *testing.T, builtin DefinitionContribution) {
	t.Helper()

	originalSchemas := mustBuiltinAuthnContribution(t).Schemas()

	for index, schema := range builtin.Schemas() {
		if !reflect.DeepEqual(schema.Facts(), originalSchemas[index].Facts()) {
			t.Fatalf("input builtin schema %q was mutated", schema.Identity().String())
		}
	}
}

func TestExtendBuiltinAuthnSchemasRejectsFactCollisionsAndShapeMismatches(t *testing.T) {
	authenticate := mustExtensionTarget(t, policy.AuthnNamespace, builtinActionAuthenticate)
	baseFixture := authnExtensionFixture{
		owner:     "plugin.geoip",
		namespace: policy.AuthnNamespace,
		provider:  "authn/plugin.geoip.environment",
		prefix:    "plugin.geoip.",
		targets:   []decision.Target{authenticate},
		outputs: []ProviderFactOutputInput{{
			ID:        "plugin.geoip.country_iso",
			Category:  decision.FactCategoryEnvironment,
			Kind:      decision.ValueKindString,
			MaxLength: 64,
		}},
	}

	tests := []struct {
		name      string
		second    ProviderFactOutputInput
		wantError error
	}{
		{
			name:      "exact collision",
			second:    baseFixture.outputs[0],
			wantError: ErrDuplicateDefinition,
		},
		{
			name: "shape mismatch",
			second: ProviderFactOutputInput{
				ID:       "plugin.geoip.country_iso",
				Category: decision.FactCategoryEnvironment,
				Kind:     decision.ValueKindBoolean,
			},
			wantError: ErrFactSchemaMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := mustAuthnExtensionContribution(t, baseFixture)
			secondFixture := baseFixture
			secondFixture.outputs = []ProviderFactOutputInput{test.second}
			second := mustAuthnExtensionContribution(t, secondFixture)

			_, err := ExtendBuiltinAuthnSchemas(mustBuiltinAuthnContribution(t), first, second)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("ExtendBuiltinAuthnSchemas() error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestExtendBuiltinAuthnSchemasRejectsUnboundOrStaticContributions(t *testing.T) {
	authenticate := mustExtensionTarget(t, policy.AuthnNamespace, builtinActionAuthenticate)
	output := mustProviderFactOutput(t, ProviderFactOutputInput{
		ID:       "plugin.geoip.risk",
		Category: decision.FactCategoryEnvironment,
		Kind:     decision.ValueKindBoolean,
	})
	provider := mustExtensionProvider(t, ProviderDefinitionInput{
		ID:      "authn/plugin.geoip.environment",
		Targets: []decision.Target{authenticate},
		Outputs: []ProviderFactOutput{output},
		Failure: ProviderFailureIndeterminate,
		Timeout: time.Second,
	})

	staticContribution, err := NewCompleteDefinitionContribution(DefinitionContributionInput{
		Ownership: mustOwnership(t, "config.authn", policy.AuthnNamespace),
		Providers: []ProviderDefinition{provider},
	})
	if err != nil {
		t.Fatalf("NewCompleteDefinitionContribution() error = %v", err)
	}

	_, err = ExtendBuiltinAuthnSchemas(mustBuiltinAuthnContribution(t), staticContribution)
	if !errors.Is(err, ErrInvalidContribution) {
		t.Fatalf("static contribution error = %v, want invalid contribution", err)
	}

	unboundProvider := mustExtensionProvider(t, ProviderDefinitionInput{
		ID:      "authn/plugin.geoip.environment",
		Targets: []decision.Target{authenticate},
		Outputs: []ProviderFactOutput{mustProviderFactOutput(t, ProviderFactOutputInput{
			ID:       "backend.geoip.risk",
			Category: decision.FactCategoryEnvironment,
			Kind:     decision.ValueKindBoolean,
		})},
		Failure: ProviderFailureIndeterminate,
		Timeout: time.Second,
	})

	unboundContribution, err := NewCompleteDefinitionContribution(DefinitionContributionInput{
		Ownership: mustOwnership(t, "plugin.geoip", policy.AuthnNamespace),
		Providers: []ProviderDefinition{unboundProvider},
	})
	if err != nil {
		t.Fatalf("NewCompleteDefinitionContribution() error = %v", err)
	}

	_, err = ExtendBuiltinAuthnSchemas(mustBuiltinAuthnContribution(t), unboundContribution)
	if !errors.Is(err, ErrInvalidProviderDefinition) {
		t.Fatalf("unbound provider source error = %v, want invalid provider definition", err)
	}
}

// authnExtensionFixture describes one exact immutable provider contribution.
type authnExtensionFixture struct {
	owner     string
	namespace string
	provider  string
	prefix    string
	targets   []decision.Target
	outputs   []ProviderFactOutputInput
}

// mustBuiltinAuthnContribution constructs the frozen builtin contribution for focused extension tests.
func mustBuiltinAuthnContribution(t *testing.T) DefinitionContribution {
	t.Helper()

	contribution, err := NewBuiltinTargetContributor().Contribute(context.Background())
	if err != nil {
		t.Fatalf("Contribute() error = %v", err)
	}

	return contribution
}

// mustAuthnExtensionContribution constructs one validated scheduled extension provider.
func mustAuthnExtensionContribution(t *testing.T, fixture authnExtensionFixture) DefinitionContribution {
	t.Helper()

	outputs := make([]ProviderFactOutput, 0, len(fixture.outputs))
	for _, input := range fixture.outputs {
		outputs = append(outputs, mustProviderFactOutput(t, input))
	}

	provider := mustExtensionProvider(t, ProviderDefinitionInput{
		ID:      fixture.provider,
		Targets: fixture.targets,
		Outputs: outputs,
		Failure: ProviderFailureIndeterminate,
		Timeout: time.Second,
	})

	contribution, err := NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
		Ownership: mustOwnership(t, fixture.owner, fixture.namespace),
		Providers: []ExtensionProviderDefinition{{
			Definition:         provider,
			ProducedFactPrefix: fixture.prefix,
		}},
	})
	if err != nil {
		t.Fatalf("NewExtensionDefinitionContribution() error = %v", err)
	}

	return contribution
}

// mustEffectOnlyExtensionContribution constructs an extension provider without fact outputs.
func mustEffectOnlyExtensionContribution(t *testing.T, target decision.Target) DefinitionContribution {
	t.Helper()

	provider := mustExtensionProvider(t, ProviderDefinitionInput{
		ID:         "authn/plugin.notify.effects",
		Targets:    []decision.Target{target},
		Executions: []ExecutionClass{ExecutionHostSync},
	})

	contribution, err := NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
		Ownership: mustOwnership(t, "plugin.notify", policy.AuthnNamespace),
		Providers: []ExtensionProviderDefinition{{Definition: provider}},
	})
	if err != nil {
		t.Fatalf("NewExtensionDefinitionContribution() error = %v", err)
	}

	return contribution
}

// mustReturnOnlyExtensionContribution constructs an extension effect with no executable provider.
func mustReturnOnlyExtensionContribution(t *testing.T, target decision.Target) DefinitionContribution {
	t.Helper()

	effect := mustExtensionEffect(t, EffectDefinitionInput{
		ID:        "authn/plugin_notify_advice",
		Targets:   []decision.Target{target},
		Kind:      EffectKindAdvice,
		Execution: ExecutionReturnOnly,
	})

	contribution, err := NewExtensionDefinitionContribution(ExtensionDefinitionContributionInput{
		Ownership: mustOwnership(t, "plugin.notify", policy.AuthnNamespace),
		Effects:   []EffectDefinition{effect},
	})
	if err != nil {
		t.Fatalf("NewExtensionDefinitionContribution() error = %v", err)
	}

	return contribution
}

// assertExtensionFactSchema verifies exact source, type, category, and bounded shape preservation.
func assertExtensionFactSchema(
	t *testing.T,
	facts map[string]FactSchema,
	want ProviderFactOutputInput,
	source decision.FactSource,
) {
	t.Helper()

	fact, exists := facts[want.ID]
	if !exists {
		t.Fatalf("fact schema %q missing", want.ID)
	}

	if fact.Category() != want.Category || fact.Kind() != want.Kind ||
		fact.MaxLength() != want.MaxLength || fact.MaxItems() != want.MaxItems || fact.MaxBytes() != want.MaxBytes {
		t.Fatalf("fact schema %q shape = %#v, want %#v", want.ID, fact, want)
	}

	if sources := fact.AllowedSources(); !reflect.DeepEqual(sources, []decision.FactSource{source}) {
		t.Fatalf("fact schema %q sources = %v, want [%s]", want.ID, sources, source)
	}
}

// assertBuiltinContributionMaterialUnchanged verifies schemas are the sole extended material.
func assertBuiltinContributionMaterialUnchanged(
	t *testing.T,
	builtin DefinitionContribution,
	extended DefinitionContribution,
) {
	t.Helper()

	if !reflect.DeepEqual(extended.Ownership(), builtin.Ownership()) ||
		!reflect.DeepEqual(extended.Targets(), builtin.Targets()) ||
		!reflect.DeepEqual(extended.PolicySets(), builtin.PolicySets()) ||
		!reflect.DeepEqual(extended.Plans(), builtin.Plans()) ||
		!reflect.DeepEqual(extended.Providers(), builtin.Providers()) ||
		!reflect.DeepEqual(extended.Effects(), builtin.Effects()) {
		t.Fatal("extension changed non-schema builtin contribution material")
	}
}
