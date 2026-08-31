// Copyright (C) 2026 Christian Roessner
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

package pluginregistry

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
)

const (
	testDecisionAction         = "evaluate"
	testDecisionEffectName     = "notify"
	testDecisionEffectProvider = "notifier"
	testDecisionFactName       = "risk.score"
	testDecisionFactProvider   = "risk"
	testDecisionNamespace      = "mail.security"
	testDecisionTargetNS       = "mail"
)

func TestRegistrarImplementsOptionalDecisionRegistrar(t *testing.T) {
	var registrar any = NewRegistry().NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	if _, ok := registrar.(pluginapi.DecisionRegistrar); !ok {
		t.Fatal("native registrar does not implement the additive DecisionRegistrar interface")
	}
}

func TestDecisionProviderRegistrationStagesAndOwnsDescriptors(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})
	descriptor := validNativeFactProviderDescriptor()
	provider := &fakeDecisionFactProvider{descriptor: descriptor}

	if err := registrar.RegisterDecisionFactProvider(provider); err != nil {
		t.Fatalf("RegisterDecisionFactProvider() error = %v", err)
	}

	if got := registry.DecisionFactProviders(); got != nil {
		t.Fatalf("committed decision fact providers = %#v before Commit()", got)
	}

	descriptor.Targets[0].Action = "changed"
	descriptor.Outputs[0].Name = "changed"
	descriptor.Outputs[1].Category = pluginapi.DecisionFactCategoryEnvironment
	descriptor.Outputs[1].Kind = pluginapi.DecisionValueKindBoolean
	descriptor.Outputs[1].MaxLength = 0
	descriptor.Outputs[1].MaxItems = 0
	descriptor.Outputs[2].MaxBytes = 1
	provider.descriptor = descriptor

	staged := registrar.Components()
	if len(staged) != 1 {
		t.Fatalf("staged components len = %d, want 1", len(staged))
	}

	assertOwnedDecisionFactDescriptor(t, staged[0].DecisionFactProviderDescriptor)

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	committed := registry.DecisionFactProviders()
	if len(committed) != 1 {
		t.Fatalf("committed decision fact providers len = %d, want 1", len(committed))
	}

	committed[0].DecisionFactProviderDescriptor.Targets[0].Action = "mutated"
	committed[0].DecisionFactProviderDescriptor.Outputs[0].Name = "mutated"

	assertOwnedDecisionFactDescriptor(t, registry.DecisionFactProviders()[0].DecisionFactProviderDescriptor)
}

func TestDecisionProviderRegistrationRejectsDuplicateIdentity(t *testing.T) {
	registrar := NewRegistry().NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})
	descriptor := validNativeFactProviderDescriptor()

	if err := registrar.RegisterDecisionFactProvider(&fakeDecisionFactProvider{descriptor: descriptor}); err != nil {
		t.Fatalf("first RegisterDecisionFactProvider() error = %v", err)
	}

	err := registrar.RegisterDecisionFactProvider(&fakeDecisionFactProvider{descriptor: descriptor})
	if !errors.Is(err, ErrDuplicateComponent) {
		t.Fatalf("second RegisterDecisionFactProvider() error = %v, want ErrDuplicateComponent", err)
	}
}

func TestDecisionEffectProviderRegistrationOwnsDescriptor(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})
	descriptor := validNativeEffectProviderDescriptor()
	provider := &fakeDecisionEffectProvider{descriptor: descriptor}

	if err := registrar.RegisterDecisionEffectProvider(provider); err != nil {
		t.Fatalf("RegisterDecisionEffectProvider() error = %v", err)
	}

	descriptor.Effects[0].Targets[0].Action = "changed"
	descriptor.Effects[0].Parameters[0].AllowedStrings[0] = "changed"
	provider.descriptor = descriptor

	staged := registrar.Components()[0].DecisionEffectProviderDescriptor
	if staged.Effects[0].Targets[0].Action != testDecisionAction {
		t.Fatalf("owned effect targets = %#v", staged.Effects[0].Targets)
	}

	if got := staged.Effects[0].Parameters[0].AllowedStrings; !reflect.DeepEqual(got, []string{"ops", "security"}) {
		t.Fatalf("owned effect parameter enum = %#v", got)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	committed := registry.DecisionEffectProviders()
	committed[0].DecisionEffectProviderDescriptor.Effects[0].Parameters[0].AllowedStrings[0] = "mutated"

	got := registry.DecisionEffectProviders()[0].DecisionEffectProviderDescriptor.Effects[0].Parameters[0].AllowedStrings
	if !reflect.DeepEqual(got, []string{"ops", "security"}) {
		t.Fatalf("committed effect parameter enum exposed mutable storage: %#v", got)
	}
}

func TestNativeDecisionContributionAdaptsProvidersAndEffectsInward(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})
	factProvider := &fakeDecisionFactProvider{descriptor: validNativeFactProviderDescriptor()}
	effectProvider := &fakeDecisionEffectProvider{descriptor: validNativeEffectProviderDescriptor()}

	if err := registrar.RegisterDecisionFactProvider(factProvider); err != nil {
		t.Fatalf("RegisterDecisionFactProvider() error = %v", err)
	}

	if err := registrar.RegisterDecisionEffectProvider(effectProvider); err != nil {
		t.Fatalf("RegisterDecisionEffectProvider() error = %v", err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	ownership := mustDecisionNamespaceOwnership(t, []string{testDecisionNamespace})

	contribution, err := NewNativeDecisionContribution(registry, testRegistryModuleGeoIP, ownership)
	if err != nil {
		t.Fatalf("NewNativeDecisionContribution() error = %v", err)
	}

	assertNativeContributionOwnsNoCatalogStructure(t, contribution)
	assertNativeFactProviderContribution(t, contribution)
	assertNativeEffectProviderContribution(t, contribution)
}

// assertNativeContributionOwnsNoCatalogStructure checks the definition-only authority boundary.
func assertNativeContributionOwnsNoCatalogStructure(t *testing.T, contribution policyregistry.DefinitionContribution) {
	t.Helper()

	if got := contribution.Targets(); len(got) != 0 {
		t.Fatalf("contributed targets = %#v, want none", got)
	}

	if got := contribution.Schemas(); len(got) != 0 {
		t.Fatalf("contributed schemas = %#v, want none", got)
	}

	if got := contribution.PolicySets(); len(got) != 0 {
		t.Fatalf("contributed policy sets = %#v, want none", got)
	}

	if got := contribution.Plans(); len(got) != 0 {
		t.Fatalf("contributed plans = %#v, want none", got)
	}
}

// assertNativeFactProviderContribution checks host-derived fact authority and fail-closed scheduling.
func assertNativeFactProviderContribution(t *testing.T, contribution policyregistry.DefinitionContribution) {
	t.Helper()

	providers := contribution.Providers()
	if len(providers) != 2 {
		t.Fatalf("contributed providers len = %d, want 2", len(providers))
	}

	factDefinition := providerDefinitionByID(t, providers, testDecisionNamespace+"/plugin.geoip."+testDecisionFactProvider)
	if got := factDefinition.Executions(); got != nil {
		t.Fatalf("fact provider executions = %#v, want none", got)
	}

	wantFactIDs := []string{
		"plugin.geoip." + testDecisionFactName,
		"plugin.geoip.subject.groups",
		"plugin.geoip.resource.payload",
	}
	if got := factDefinition.ProducedFacts(); !reflect.DeepEqual(got, wantFactIDs) {
		t.Fatalf("fact provider outputs = %#v", got)
	}

	assertNativeProviderFactOutputs(t, factDefinition)

	if factDefinition.Failure() != policyregistry.ProviderFailureIndeterminate || factDefinition.Timeout() != time.Second {
		t.Fatalf("fact provider schedule = %q, %s", factDefinition.Failure(), factDefinition.Timeout())
	}

	if got := factDefinition.Targets(); len(got) != 1 || got[0].String() != testDecisionTargetNS+"/"+testDecisionAction {
		t.Fatalf("fact provider targets = %#v", got)
	}
}

// assertNativeProviderFactOutputs checks typed capability metadata without contributing active schemas.
func assertNativeProviderFactOutputs(t *testing.T, provider policyregistry.ProviderDefinition) {
	t.Helper()

	outputs := provider.Outputs()
	if len(outputs) != 3 {
		t.Fatalf("typed provider outputs len = %d, want 3", len(outputs))
	}

	want := []policyregistry.ProviderFactOutputInput{
		{
			ID:        "plugin.geoip." + testDecisionFactName,
			Category:  "environment",
			Kind:      "string",
			MaxLength: 64,
		},
		{
			ID:        "plugin.geoip.subject.groups",
			Category:  "subject",
			Kind:      "strings",
			MaxLength: 128,
			MaxItems:  16,
		},
		{
			ID:       "plugin.geoip.resource.payload",
			Category: "resource",
			Kind:     "bytes",
			MaxBytes: 1024,
		},
	}

	for index, output := range outputs {
		got := policyregistry.ProviderFactOutputInput{
			ID:        output.ID(),
			Category:  output.Category(),
			Kind:      output.Kind(),
			MaxLength: output.MaxLength(),
			MaxItems:  output.MaxItems(),
			MaxBytes:  output.MaxBytes(),
		}
		if got != want[index] {
			t.Fatalf("typed provider output %d = %#v, want %#v", index, got, want[index])
		}
	}

	outputs[0] = policyregistry.ProviderFactOutput{}

	if got := provider.Outputs()[0].ID(); got != "plugin.geoip."+testDecisionFactName {
		t.Fatalf("typed provider output storage was mutable: %q", got)
	}
}

// assertNativeEffectProviderContribution checks selected-effect binding and typed parameters.
func assertNativeEffectProviderContribution(t *testing.T, contribution policyregistry.DefinitionContribution) {
	t.Helper()

	providers := contribution.Providers()
	effectProviderID := testDecisionNamespace + "/plugin.geoip." + testDecisionEffectProvider

	effectDefinition := providerDefinitionByID(t, providers, effectProviderID)
	if got := effectDefinition.Executions(); !reflect.DeepEqual(got, []policyregistry.ExecutionClass{policyregistry.ExecutionHostSync}) {
		t.Fatalf("effect provider executions = %#v", got)
	}

	effects := contribution.Effects()
	if len(effects) != 1 {
		t.Fatalf("contributed effects len = %d, want 1", len(effects))
	}

	if effects[0].ID() != testDecisionNamespace+"/"+testDecisionEffectName || effects[0].Provider() != effectProviderID {
		t.Fatalf("effect identity = %q via %q", effects[0].ID(), effects[0].Provider())
	}

	parameters := effects[0].Parameters()
	if len(parameters) != 1 || parameters[0].Name() != "recipient" || !reflect.DeepEqual(parameters[0].AllowedStrings(), []string{"ops", "security"}) {
		t.Fatalf("effect parameters = %#v", parameters)
	}

	parameters[0].AllowedStrings()[0] = "mutated"
	if got := contribution.Effects()[0].Parameters()[0].AllowedStrings(); !reflect.DeepEqual(got, []string{"ops", "security"}) {
		t.Fatalf("effect parameter enum exposed mutable storage: %#v", got)
	}
}

func TestNativeDecisionContributionRejectsForeignDefinitionNamespace(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	if err := registrar.RegisterDecisionFactProvider(&fakeDecisionFactProvider{descriptor: validNativeFactProviderDescriptor()}); err != nil {
		t.Fatalf("RegisterDecisionFactProvider() error = %v", err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	ownership := mustDecisionNamespaceOwnership(t, []string{"other"})

	_, err := NewNativeDecisionContribution(registry, testRegistryModuleGeoIP, ownership)
	if !errors.Is(err, policyregistry.ErrNamespaceOwnership) {
		t.Fatalf("NewNativeDecisionContribution() error = %v, want ErrNamespaceOwnership", err)
	}
}

func TestNativeDecisionContributionRejectsMismatchedHostAuthority(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	if err := registrar.RegisterDecisionFactProvider(&fakeDecisionFactProvider{descriptor: validNativeFactProviderDescriptor()}); err != nil {
		t.Fatalf("RegisterDecisionFactProvider() error = %v", err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	ownership, err := policyregistry.NewNamespaceOwnership("plugin.other", []string{testDecisionNamespace})
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	_, err = NewNativeDecisionContribution(registry, testRegistryModuleGeoIP, ownership)
	if !errors.Is(err, policyregistry.ErrNamespaceOwnership) {
		t.Fatalf("NewNativeDecisionContribution() error = %v, want ErrNamespaceOwnership", err)
	}
}

func TestNativeDecisionEffectExecutionMapsOnlyHostOwnedClasses(t *testing.T) {
	tests := []struct {
		name  string
		input pluginapi.DecisionEffectExecution
		want  policyregistry.ExecutionClass
	}{
		{name: "synchronous", input: pluginapi.DecisionEffectExecutionHostSync, want: policyregistry.ExecutionHostSync},
		{name: "post action", input: pluginapi.DecisionEffectExecutionHostPostAction, want: policyregistry.ExecutionHostPostAction},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := nativeDecisionExecution(testCase.input)
			if err != nil {
				t.Fatalf("nativeDecisionExecution() error = %v", err)
			}

			if got != testCase.want {
				t.Fatalf("nativeDecisionExecution() = %q, want %q", got, testCase.want)
			}
		})
	}

	if _, err := nativeDecisionExecution("return_only"); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("nativeDecisionExecution(return_only) error = %v, want ErrInvalidDescriptor", err)
	}
}

func TestDecisionRegistrationKeepsLegacyAuthComponentsSeparate(t *testing.T) {
	registry := NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: testRegistryModuleGeoIP})

	if err := registrar.RegisterEnvironmentSource(fakeEnvironmentSource{name: testRegistryEnvironmentName}); err != nil {
		t.Fatalf("RegisterEnvironmentSource() error = %v", err)
	}

	if err := registrar.RegisterDecisionFactProvider(&fakeDecisionFactProvider{descriptor: validNativeFactProviderDescriptor()}); err != nil {
		t.Fatalf("RegisterDecisionFactProvider() error = %v", err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	if len(registry.EnvironmentSources()) != 1 || len(registry.DecisionFactProviders()) != 1 {
		t.Fatalf("legacy/generic component counts = %d/%d", len(registry.EnvironmentSources()), len(registry.DecisionFactProviders()))
	}

	legacy := registry.EnvironmentSources()[0]
	if legacy.Kind != ComponentKindEnvironmentSource || legacy.DecisionFactProviderDescriptor.Name != "" {
		t.Fatalf("legacy component crossed generic boundary: %#v", legacy)
	}

	generic := registry.DecisionFactProviders()[0]
	if generic.Kind != ComponentKindDecisionFactProvider || generic.SourceDescriptor.Name != "" {
		t.Fatalf("generic component crossed legacy auth boundary: %#v", generic)
	}
}

// assertOwnedDecisionFactDescriptor verifies that registration detached mutable descriptor slices.
func assertOwnedDecisionFactDescriptor(t *testing.T, descriptor pluginapi.DecisionFactProviderDescriptor) {
	t.Helper()

	if len(descriptor.Targets) != 1 || descriptor.Targets[0].Action != testDecisionAction {
		t.Fatalf("owned targets = %#v", descriptor.Targets)
	}

	if len(descriptor.Outputs) != 3 || descriptor.Outputs[0].Name != testDecisionFactName {
		t.Fatalf("owned outputs = %#v", descriptor.Outputs)
	}

	groups := descriptor.Outputs[1]
	if groups.Category != pluginapi.DecisionFactCategorySubject || groups.Kind != pluginapi.DecisionValueKindStrings ||
		groups.MaxLength != 128 || groups.MaxItems != 16 {
		t.Fatalf("owned string-list output = %#v", groups)
	}

	payload := descriptor.Outputs[2]
	if payload.Category != pluginapi.DecisionFactCategoryResource || payload.Kind != pluginapi.DecisionValueKindBytes ||
		payload.MaxBytes != 1024 {
		t.Fatalf("owned bytes output = %#v", payload)
	}
}

// mustDecisionNamespaceOwnership constructs host-assigned ownership for adapter tests.
func mustDecisionNamespaceOwnership(t *testing.T, namespaces []string) policyregistry.NamespaceOwnership {
	t.Helper()

	ownership, err := policyregistry.NewNamespaceOwnership("plugin.geoip", namespaces)
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	return ownership
}

// providerDefinitionByID locates one exact internal provider descriptor.
func providerDefinitionByID(t *testing.T, providers []policyregistry.ProviderDefinition, id string) policyregistry.ProviderDefinition {
	t.Helper()

	for _, provider := range providers {
		if provider.ID() == id {
			return provider
		}
	}

	t.Fatalf("provider %q not found in %#v", id, providers)

	return policyregistry.ProviderDefinition{}
}

// validNativeFactProviderDescriptor returns a cross-namespace target capability for native adaptation.
func validNativeFactProviderDescriptor() pluginapi.DecisionFactProviderDescriptor {
	return pluginapi.DecisionFactProviderDescriptor{
		Namespace: testDecisionNamespace,
		Name:      testDecisionFactProvider,
		Targets: []pluginapi.DecisionTargetSelector{
			{Namespace: testDecisionTargetNS, Action: testDecisionAction},
		},
		Outputs: []pluginapi.DecisionFactOutputDescriptor{
			{
				Name:      testDecisionFactName,
				Category:  pluginapi.DecisionFactCategoryEnvironment,
				Kind:      pluginapi.DecisionValueKindString,
				MaxLength: 64,
			},
			{
				Name:      "subject.groups",
				Category:  pluginapi.DecisionFactCategorySubject,
				Kind:      pluginapi.DecisionValueKindStrings,
				MaxLength: 128,
				MaxItems:  16,
			},
			{
				Name:     "resource.payload",
				Category: pluginapi.DecisionFactCategoryResource,
				Kind:     pluginapi.DecisionValueKindBytes,
				MaxBytes: 1024,
			},
		},
		Timeout: time.Second,
	}
}

// validNativeEffectProviderDescriptor returns one selected synchronous effect contract.
func validNativeEffectProviderDescriptor() pluginapi.DecisionEffectProviderDescriptor {
	return pluginapi.DecisionEffectProviderDescriptor{
		Namespace: testDecisionNamespace,
		Name:      testDecisionEffectProvider,
		Effects: []pluginapi.DecisionEffectDescriptor{
			{
				Name:      testDecisionEffectName,
				Execution: pluginapi.DecisionEffectExecutionHostSync,
				Targets: []pluginapi.DecisionTargetSelector{
					{Namespace: testDecisionTargetNS, Action: testDecisionAction},
				},
				Parameters: []pluginapi.DecisionEffectParameterDescriptor{
					{
						Name:           "recipient",
						Kind:           pluginapi.DecisionValueKindString,
						MaxLength:      64,
						AllowedStrings: []string{"ops", "security"},
						NonEmpty:       true,
						Required:       true,
					},
				},
			},
		},
	}
}

type fakeDecisionFactProvider struct {
	descriptor pluginapi.DecisionFactProviderDescriptor
}

// Descriptor returns the fake fact-provider capability declaration.
func (p *fakeDecisionFactProvider) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	return p.descriptor
}

// Collect returns no facts because callback wiring is outside this contract test.
func (p *fakeDecisionFactProvider) Collect(context.Context, pluginapi.DecisionFactRequest) (pluginapi.DecisionFactResult, error) {
	return pluginapi.DecisionFactResult{}, nil
}

type fakeDecisionEffectProvider struct {
	descriptor pluginapi.DecisionEffectProviderDescriptor
}

// Descriptor returns the fake effect-provider capability declaration.
func (p *fakeDecisionEffectProvider) Descriptor() pluginapi.DecisionEffectProviderDescriptor {
	return p.descriptor
}

// Execute reports success without executing because runtime wiring is outside this contract test.
func (p *fakeDecisionEffectProvider) Execute(context.Context, pluginapi.DecisionEffectRequest) (pluginapi.DecisionEffectResult, error) {
	return pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeSucceeded}, nil
}
