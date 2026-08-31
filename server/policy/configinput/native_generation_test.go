// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const configuredNativePolicyFixture = `policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          filter:
            versions:
              v1:
                facts:
                  - attribute: plugin.reputation.risk_score
                    category: environment
                    type: string
                    allowed_sources: [plugin]
                    max_length: 16
      providers:
        risk:
          kind: native
          module: reputation
          targets: [{action: filter}]
          produced_facts: [plugin.reputation.risk_score]
          failure: continue
          timeout: 50ms
          diagnostics: {public_id: native-risk}
        notifier:
          kind: native
          module: reputation
          targets: [{action: filter}]
          executions: [host_sync, host_post_action]
          failure: indeterminate
          timeout: 50ms
          diagnostics: {public_id: native-notifier}
      effects:
        notify:
          kind: obligation
          provider: mail/plugin.reputation.notifier
          targets: [{action: filter}]
          execution: host_sync
          diagnostics: {public_id: native-notify}
          parameters:
            level: {type: string, max_length: 16, required: true}
        archive:
          kind: obligation
          provider: mail/plugin.reputation.notifier
          targets: [{action: filter}]
          execution: host_post_action
          diagnostics: {public_id: native-archive}
          parameters:
            level: {type: string, max_length: 16, required: true}
      domain_plans:
        default:
          checkpoints:
            final_decision:
              providers:
                - name: risk
                  use: mail/plugin.reputation.risk
      policy_sets:
        default: {rules: []}
  targets:
    - namespace: mail
      action: filter
      schema: mail/filter/v1
      domain_plan: mail/default
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [mail/default]}
`

func TestConfiguredNativeProviderGenerationResolvesExactConfiguredSubset(t *testing.T) {
	bindings := configuredNativeBindings(t, nativeFactDescriptor(), nativeEffectDescriptor(), true)
	configured := decodePolicy(t, configuredNativePolicyFixture).Policy

	before := configured.Namespaces["mail"].Providers["risk"]
	if _, err := Normalize(t.Context(), policyconfig.Document{Policy: configured}); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	preparation, err := PrepareConfiguredNativeGeneration(t.Context(), ConfiguredNativeGenerationInput{
		Policy: configured, Bindings: bindings, PostActionAcceptance: &nativeGenerationAcceptor{},
		NativeModules: []policyruntime.NativeModuleBindingInput{{
			ModuleName: "reputation", ArtifactPath: "/loaded/reputation.so", ArtifactDigest: "sha256:fixture",
		}},
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredNativeGeneration() error = %v", err)
	}

	if !reflect.DeepEqual(before, configured.Namespaces["mail"].Providers["risk"]) {
		t.Fatal("PrepareConfiguredNativeGeneration() mutated caller-owned configuration")
	}

	assertConfiguredNativeGeneration(t, preparation)
}

func TestConfiguredNativeProviderBindingsValidateSharedTargetCatalog(t *testing.T) {
	configured := decodePolicy(t, configuredNativePolicyFixture).Policy
	acceptor := &nativeGenerationAcceptor{}

	normalized, err := Normalize(t.Context(), policyconfig.Document{Policy: configured})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	catalog := compileConfiguredNativeTargetCatalog(t, normalized, acceptor)

	preparation, err := PrepareConfiguredNativeGeneration(t.Context(), ConfiguredNativeGenerationInput{
		Policy:               configured,
		Bindings:             configuredNativeBindings(t, nativeFactDescriptor(), nativeEffectDescriptor(), true),
		PostActionAcceptance: acceptor,
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredNativeGeneration() error = %v", err)
	}

	got := [][]string{
		preparation.Bindings.FactProviderIDs(),
		preparation.Bindings.SyncEffectIDs(),
		preparation.Bindings.PostActionIDs(),
	}

	want := [][]string{
		{"mail/plugin.reputation.risk"},
		{"mail/plugin.reputation.notifier"},
		{"mail/plugin.reputation.notifier"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prepared native binding IDs = %v, want %v", got, want)
	}

	if err = preparation.Bindings.ValidateCatalog(catalog); err != nil {
		t.Fatalf("ValidateCatalog() error = %v", err)
	}
}

func TestConfiguredNativeProviderGenerationRejectsFrozenCapabilityMismatch(t *testing.T) {
	tests := []struct {
		factDescriptor   pluginapi.DecisionFactProviderDescriptor
		effectDescriptor pluginapi.DecisionEffectProviderDescriptor
		includeFact      bool
		name             string
	}{
		{
			name: "missing component", factDescriptor: nativeFactDescriptor(),
			effectDescriptor: nativeEffectDescriptor(), includeFact: false,
		},
		{
			name: "foreign namespace", factDescriptor: func() pluginapi.DecisionFactProviderDescriptor {
				descriptor := nativeFactDescriptor()
				descriptor.Namespace = "foreign"

				return descriptor
			}(), effectDescriptor: nativeEffectDescriptor(), includeFact: true,
		},
		{
			name: "schema mismatch", factDescriptor: func() pluginapi.DecisionFactProviderDescriptor {
				descriptor := nativeFactDescriptor()
				descriptor.Outputs[0].MaxLength = 32

				return descriptor
			}(), effectDescriptor: nativeEffectDescriptor(), includeFact: true,
		},
		{
			name: "target mismatch", factDescriptor: func() pluginapi.DecisionFactProviderDescriptor {
				descriptor := nativeFactDescriptor()
				descriptor.Targets[0].Action = "other"

				return descriptor
			}(), effectDescriptor: nativeEffectDescriptor(), includeFact: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bindings := configuredNativeBindings(t, test.factDescriptor, test.effectDescriptor, test.includeFact)

			_, err := PrepareConfiguredNativeGeneration(t.Context(), ConfiguredNativeGenerationInput{
				Policy:   decodePolicy(t, configuredNativePolicyFixture).Policy,
				Bindings: bindings, PostActionAcceptance: &nativeGenerationAcceptor{},
			})
			if err == nil {
				t.Fatal("PrepareConfiguredNativeGeneration() error = nil, want frozen capability rejection")
			}
		})
	}
}

// TestConfiguredNativeProviderGenerationRejectsFrozenEffectCapabilityMismatch proves exact selected-effect metadata.
func TestConfiguredNativeProviderGenerationRejectsFrozenEffectCapabilityMismatch(t *testing.T) {
	tests := []struct {
		configure func(*pluginapi.DecisionEffectProviderDescriptor)
		name      string
	}{
		{
			name: "target mismatch",
			configure: func(descriptor *pluginapi.DecisionEffectProviderDescriptor) {
				descriptor.Effects[0].Targets[0].Action = "other"
			},
		},
		{
			name: "parameter mismatch",
			configure: func(descriptor *pluginapi.DecisionEffectProviderDescriptor) {
				descriptor.Effects[0].Parameters[0].MaxLength = 32
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := nativeEffectDescriptor()
			test.configure(&descriptor)
			bindings := configuredNativeBindings(t, nativeFactDescriptor(), descriptor, true)

			_, err := PrepareConfiguredNativeGeneration(t.Context(), ConfiguredNativeGenerationInput{
				Policy: decodePolicy(t, configuredNativePolicyFixture).Policy, Bindings: bindings,
				PostActionAcceptance: &nativeGenerationAcceptor{},
			})
			if err == nil {
				t.Fatal("PrepareConfiguredNativeGeneration() error = nil, want frozen effect rejection")
			}
		})
	}
}

func TestConfiguredNativeProviderGenerationHonorsPreparationCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := PrepareConfiguredNativeGeneration(ctx, ConfiguredNativeGenerationInput{
		Policy:               decodePolicy(t, configuredNativePolicyFixture).Policy,
		Bindings:             configuredNativeBindings(t, nativeFactDescriptor(), nativeEffectDescriptor(), true),
		PostActionAcceptance: &nativeGenerationAcceptor{},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("PrepareConfiguredNativeGeneration() error = %v, want context.Canceled", err)
	}
}

func TestConfiguredNativeProviderLifecycleDeactivationDoesNotMutatePreparedGeneration(t *testing.T) {
	bindings := configuredNativeBindings(t, nativeFactDescriptor(), nativeEffectDescriptor(), true)
	activePolicy := decodePolicy(t, configuredNativePolicyFixture).Policy

	active, err := PrepareConfiguredNativeGeneration(t.Context(), ConfiguredNativeGenerationInput{
		Policy: activePolicy, Bindings: bindings, PostActionAcceptance: &nativeGenerationAcceptor{},
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredNativeGeneration(active) error = %v", err)
	}

	inactivePolicy := decodePolicy(t, configuredNativePolicyFixture).Policy
	namespace := inactivePolicy.Namespaces["mail"]
	namespace.Providers = nil
	namespace.Effects = nil
	plan := namespace.DomainPlans["default"]
	checkpoint := plan.Checkpoints["final_decision"]
	checkpoint.Providers = nil
	plan.Checkpoints["final_decision"] = checkpoint
	namespace.DomainPlans["default"] = plan
	inactivePolicy.Namespaces["mail"] = namespace

	inactive, err := PrepareConfiguredNativeGeneration(t.Context(), ConfiguredNativeGenerationInput{
		Policy: inactivePolicy, Bindings: bindings, PostActionAcceptance: &nativeGenerationAcceptor{},
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredNativeGeneration(inactive) error = %v", err)
	}

	if len(inactive.Definitions) != 0 || len(inactive.Bindings.FactProviderIDs()) != 0 ||
		len(inactive.Bindings.SyncEffectIDs()) != 0 || len(inactive.Bindings.PostActionIDs()) != 0 {
		t.Fatalf("inactive native preparation retained configured material: %#v", inactive)
	}

	if got := active.Bindings.FactProviderIDs(); !reflect.DeepEqual(got, []string{"mail/plugin.reputation.risk"}) {
		t.Fatalf("active fact bindings changed after deactivation: %v", got)
	}
}

func TestConfiguredNativeProviderRestartRequiredPreservesPreparedGeneration(t *testing.T) {
	bindings := configuredNativeBindings(t, nativeFactDescriptor(), nativeEffectDescriptor(), true)
	configured := decodePolicy(t, configuredNativePolicyFixture).Policy
	acceptor := &nativeGenerationAcceptor{}

	prepared, err := PrepareConfiguredNativeGeneration(t.Context(), ConfiguredNativeGenerationInput{
		Policy: configured, Bindings: bindings, PostActionAcceptance: acceptor,
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredNativeGeneration(initial) error = %v", err)
	}

	artifact := bindings.Modules()[0].ArtifactPath()
	if err = os.WriteFile(artifact, []byte("replaced-native-generation"), 0o600); err != nil {
		t.Fatalf("WriteFile(replacement) error = %v", err)
	}

	_, err = PrepareConfiguredNativeGeneration(t.Context(), ConfiguredNativeGenerationInput{
		Policy: configured, Bindings: bindings, PostActionAcceptance: acceptor,
	})
	if !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("PrepareConfiguredNativeGeneration(replacement) error = %v, want ErrRestartRequired", err)
	}

	if got := prepared.Bindings.FactProviderIDs(); !reflect.DeepEqual(got, []string{"mail/plugin.reputation.risk"}) {
		t.Fatalf("prepared generation changed after replacement: %v", got)
	}
}

// assertConfiguredNativeGeneration verifies exact contribution metadata and frozen binding identities.
func assertConfiguredNativeGeneration(t *testing.T, preparation policyruntime.ExtensionPreparation) {
	t.Helper()
	assertConfiguredNativeContribution(t, preparation)
	assertConfiguredNativeBindingSet(t, preparation)
}

// assertConfiguredNativeContribution verifies exact provider and effect catalog metadata.
func assertConfiguredNativeContribution(t *testing.T, preparation policyruntime.ExtensionPreparation) {
	t.Helper()

	if len(preparation.Definitions) != 1 || preparation.Definitions[0].Ownership().Owner() != "plugin.reputation" {
		t.Fatalf("native definitions = %#v, want one plugin.reputation contribution", preparation.Definitions)
	}

	contribution := preparation.Definitions[0]
	assertConfiguredNativeProviders(t, contribution)
	assertConfiguredNativeEffects(t, contribution)
}

// assertConfiguredNativeProviders verifies exact schedule and diagnostic metadata.
func assertConfiguredNativeProviders(t *testing.T, contribution registry.DefinitionContribution) {
	t.Helper()

	if got := contribution.Providers(); len(got) != 2 ||
		got[0].ID() != "mail/plugin.reputation.notifier" || got[1].ID() != "mail/plugin.reputation.risk" ||
		got[0].Scheduled() || got[1].DiagnosticID() != "native-risk" || len(got[1].Outputs()) != 1 ||
		got[1].Failure() != "continue" || got[1].Timeout() != 50*time.Millisecond {
		t.Fatalf("native providers = %#v, want exact configured definitions", got)
	}
}

// assertConfiguredNativeEffects verifies exact selected effect metadata.
func assertConfiguredNativeEffects(t *testing.T, contribution registry.DefinitionContribution) {
	t.Helper()

	if got := contribution.Effects(); len(got) != 2 || got[0].ID() != "mail/archive" || got[1].ID() != "mail/notify" {
		t.Fatalf("native effects = %#v, want exact configured effects", got)
	}
}

// assertConfiguredNativeBindingSet verifies activated runtime owners and excludes unconfigured components.
func assertConfiguredNativeBindingSet(t *testing.T, preparation policyruntime.ExtensionPreparation) {
	t.Helper()

	if got := preparation.Bindings.FactProviderIDs(); !reflect.DeepEqual(got, []string{"mail/plugin.reputation.risk"}) {
		t.Fatalf("fact bindings = %v", got)
	}

	if got := preparation.Bindings.SyncEffectIDs(); !reflect.DeepEqual(got, []string{"mail/plugin.reputation.notifier"}) {
		t.Fatalf("sync bindings = %v", got)
	}

	if got := preparation.Bindings.PostActionIDs(); !reflect.DeepEqual(got, []string{"mail/plugin.reputation.notifier"}) {
		t.Fatalf("post bindings = %v", got)
	}

	if got := preparation.Bindings.NativeModuleIDs(); !reflect.DeepEqual(got, []string{"reputation"}) {
		t.Fatalf("native modules = %v", got)
	}

	if _, exists := preparation.Bindings.FactProviders()["mail/plugin.reputation.unused"]; exists {
		t.Fatal("unconfigured registered native provider gained a binding")
	}

	binding := preparation.Bindings.FactProviders()["mail/plugin.reputation.risk"]
	if binding.Source != decision.FactSourcePlugin || binding.Authority != "reputation" {
		t.Fatalf("native fact authority = %q/%q", binding.Source, binding.Authority)
	}
}

// configuredNativeBindings captures generic and legacy components in one immutable module generation.
func configuredNativeBindings(
	t *testing.T,
	factDescriptor pluginapi.DecisionFactProviderDescriptor,
	effectDescriptor pluginapi.DecisionEffectProviderDescriptor,
	includeFact bool,
) *pluginruntime.GenerationBindings {
	t.Helper()

	return configuredNativeBindingsWithProviders(
		t,
		&nativeFactProvider{descriptor: factDescriptor},
		&nativeEffectProvider{descriptor: effectDescriptor},
		includeFact,
	)
}

// configuredNativeBindingsWithProviders captures replaceable provider fixtures with shared module setup.
func configuredNativeBindingsWithProviders(
	t *testing.T,
	factProvider *nativeFactProvider,
	effectProvider *nativeEffectProvider,
	includeFact bool,
) *pluginruntime.GenerationBindings {
	t.Helper()

	components := []pluginregistry.Component{
		{
			Value:                            effectProvider,
			DecisionEffectProviderDescriptor: effectProvider.descriptor,
			ModuleName:                       "reputation", LocalName: "notifier",
			Kind: pluginregistry.ComponentKindDecisionEffectProvider, Origin: pluginregistry.ComponentOriginNative,
		},
		{
			Value:                            &nativeEffectProvider{descriptor: unusedNativeEffectDescriptor()},
			DecisionEffectProviderDescriptor: unusedNativeEffectDescriptor(),
			ModuleName:                       "reputation", LocalName: "unused_notifier",
			Kind: pluginregistry.ComponentKindDecisionEffectProvider, Origin: pluginregistry.ComponentOriginNative,
		},
		{
			Value: &struct{}{}, ModuleName: "reputation", LocalName: "legacy_subject",
			Kind: pluginregistry.ComponentKindSubjectSource, Origin: pluginregistry.ComponentOriginNative,
		},
		{
			Value:                          &nativeFactProvider{descriptor: unusedNativeFactDescriptor()},
			DecisionFactProviderDescriptor: unusedNativeFactDescriptor(),
			ModuleName:                     "reputation", LocalName: "unused",
			Kind: pluginregistry.ComponentKindDecisionFactProvider, Origin: pluginregistry.ComponentOriginNative,
		},
	}
	if includeFact {
		components = append(components, pluginregistry.Component{
			Value:                          factProvider,
			DecisionFactProviderDescriptor: factProvider.descriptor,
			ModuleName:                     "reputation", LocalName: "risk",
			Kind: pluginregistry.ComponentKindDecisionFactProvider, Origin: pluginregistry.ComponentOriginNative,
		})
	}

	artifact := filepath.Join(t.TempDir(), "reputation.so")
	if err := os.WriteFile(artifact, []byte("configured-native-generation"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	digest, err := pluginloader.DigestArtifact(artifact)
	if err != nil {
		t.Fatalf("DigestArtifact() error = %v", err)
	}

	bindings, err := pluginruntime.CaptureGenerationBindings([]pluginloader.ModuleInstance{{
		Module:      config.PluginModule{Name: "reputation", Type: config.PluginModuleTypeGo, Path: artifact},
		Descriptors: components, ArtifactPath: artifact, ArtifactDigest: digest,
		ModuleName: "reputation", Status: pluginloader.ModuleStatusRegistered,
	}})
	if err != nil {
		t.Fatalf("CaptureGenerationBindings() error = %v", err)
	}

	return bindings
}

// nativeFactDescriptor returns the exact configured public fact capability.
func nativeFactDescriptor() pluginapi.DecisionFactProviderDescriptor {
	return pluginapi.DecisionFactProviderDescriptor{
		Namespace: "mail", Name: "risk", Timeout: 100 * time.Millisecond,
		Targets: []pluginapi.DecisionTargetSelector{{Namespace: "mail", Action: "filter"}},
		Outputs: []pluginapi.DecisionFactOutputDescriptor{{
			Name: "risk_score", Category: pluginapi.DecisionFactCategoryEnvironment,
			Kind: pluginapi.DecisionValueKindString, MaxLength: 16,
		}},
	}
}

// unusedNativeFactDescriptor returns a valid registered but unconfigured capability.
func unusedNativeFactDescriptor() pluginapi.DecisionFactProviderDescriptor {
	descriptor := nativeFactDescriptor()
	descriptor.Name = "unused"
	descriptor.Outputs[0].Name = "unused"

	return descriptor
}

// nativeEffectDescriptor returns exact configured synchronous and post-action effects.
func nativeEffectDescriptor() pluginapi.DecisionEffectProviderDescriptor {
	parameter := pluginapi.DecisionEffectParameterDescriptor{
		Name: "level", Kind: pluginapi.DecisionValueKindString, MaxLength: 16, Required: true,
	}
	targets := []pluginapi.DecisionTargetSelector{{Namespace: "mail", Action: "filter"}}

	return pluginapi.DecisionEffectProviderDescriptor{
		Namespace: "mail", Name: "notifier",
		Effects: []pluginapi.DecisionEffectDescriptor{
			{Name: "notify", Execution: pluginapi.DecisionEffectExecutionHostSync, Targets: targets, Parameters: []pluginapi.DecisionEffectParameterDescriptor{parameter}},
			{Name: "archive", Execution: pluginapi.DecisionEffectExecutionHostPostAction, Targets: targets, Parameters: []pluginapi.DecisionEffectParameterDescriptor{parameter}},
		},
	}
}

// unusedNativeEffectDescriptor returns a valid registered effect capability selected only by runtime integration tests.
func unusedNativeEffectDescriptor() pluginapi.DecisionEffectProviderDescriptor {
	descriptor := nativeEffectDescriptor()
	descriptor.Name = "unused_notifier"
	descriptor.Effects = descriptor.Effects[:1]
	descriptor.Effects[0].Name = "unselected"

	return descriptor
}

type nativeFactProvider struct {
	descriptor pluginapi.DecisionFactProviderDescriptor
	collect    func(pluginapi.DecisionFactRequest)
}

// Descriptor returns the frozen generic fact capability.
func (p *nativeFactProvider) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	return p.descriptor
}

// Collect returns no facts because generation preparation must not invoke providers.
func (p *nativeFactProvider) Collect(
	_ context.Context,
	request pluginapi.DecisionFactRequest,
) (pluginapi.DecisionFactResult, error) {
	if p.collect != nil {
		p.collect(request)
	}

	return pluginapi.DecisionFactResult{}, nil
}

type nativeEffectProvider struct {
	descriptor pluginapi.DecisionEffectProviderDescriptor
	results    map[string]pluginapi.DecisionEffectResult
}

// Descriptor returns the frozen generic effect capability.
func (p *nativeEffectProvider) Descriptor() pluginapi.DecisionEffectProviderDescriptor {
	return p.descriptor
}

// Execute reports success when a selected effect is invoked after preparation.
func (p *nativeEffectProvider) Execute(
	_ context.Context,
	request pluginapi.DecisionEffectRequest,
) (pluginapi.DecisionEffectResult, error) {
	if result, exists := p.results[request.Effect()]; exists {
		return result, nil
	}

	return pluginapi.DecisionEffectResult{Outcome: pluginapi.DecisionEffectOutcomeSucceeded}, nil
}

type nativeGenerationAcceptor struct{}

// Accept returns a deterministic receipt without starting detached work.
func (*nativeGenerationAcceptor) Accept(
	context.Context,
	effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}
