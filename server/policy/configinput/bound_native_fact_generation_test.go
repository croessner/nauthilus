// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
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
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const boundNativeAuthnPolicyFixture = `policy:
  namespaces:
    authn:
      providers:
        environment:
          kind: native
          module: geoip
          targets:
            - action: authenticate
            - action: lookup_identity
          produced_facts:
            - plugin.geoip.matched
            - plugin.geoip.country_iso
          failure: indeterminate
          timeout: 50ms
          diagnostics: {public_id: geoip-environment}
      domain_plans:
        geoip:
          checkpoints:
            pre_auth:
              providers:
                - name: geoip_environment
                  use: authn/plugin.geoip.environment
                  actions: [authenticate, lookup_identity]
      policy_sets:
        geoip:
          visibility: private
          rules: []
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/geoip
      default_policy: authn/standard_auth
      plans:
        pre_auth: {policy_sets: [authn/geoip]}
    - namespace: authn
      action: lookup_identity
      schema: authn/lookup_identity/v1
      domain_plan: authn/geoip
      default_policy: authn/standard_auth
      plans:
        pre_auth: {policy_sets: [authn/geoip]}
`

// TestBoundNativeFactGenerationProjectsRealAuthnDescriptorBeforeCatalogCompilation proves descriptor-first authority.
func TestBoundNativeFactGenerationProjectsRealAuthnDescriptorBeforeCatalogCompilation(t *testing.T) {
	configured := decodePolicy(t, boundNativeAuthnPolicyFixture).Policy
	if len(configured.Namespaces[policy.AuthnNamespace].SchemaContributions.Static) != 0 {
		t.Fatal("authn fixture contains an authored static schema")
	}

	preparedPolicy, err := PreparePolicy(t.Context(), 23, configured)
	if err != nil {
		t.Fatalf("PreparePolicy() error = %v", err)
	}

	descriptor := boundGeoIPFactDescriptor()
	capability := mustBoundNativeCapability(t, "geoip", descriptor)
	bindings, nativeModule := boundGeoIPGenerationBindings(t, descriptor)
	resource := &boundNativeCandidateResource{}
	acceptor := &nativeGenerationAcceptor{}

	preparation, err := PrepareBoundNativeFactGeneration(t.Context(), BoundNativeFactGenerationInput{
		Policy: configured, Capabilities: []registry.NativeFactProviderCapability{capability},
		Bindings: bindings, PostActionAcceptance: acceptor,
		NativeModules: []policyruntime.NativeModuleBindingInput{nativeModule},
		Resources:     []policyruntime.CandidateResource{resource},
	})
	if err != nil {
		t.Fatalf("PrepareBoundNativeFactGeneration() error = %v", err)
	}

	assertBoundNativeFactPreparation(t, preparation, resource)

	catalog, _, err := preparedPolicy.CompileWithExtensions(t.Context(), acceptor, preparation.Definitions)
	if err != nil {
		t.Fatalf("PreparedPolicy.CompileWithExtensions() error = %v", err)
	}

	assertBoundNativeAuthnCatalog(t, catalog)
}

// TestBoundNativeFactGenerationRejectsConfigurationOutsideCapturedCapability proves exact selection validation.
func TestBoundNativeFactGenerationRejectsConfigurationOutsideCapturedCapability(t *testing.T) {
	for _, test := range boundNativeCapabilityMismatchCases() {
		t.Run(test.name, func(t *testing.T) {
			configured := decodePolicy(t, boundNativeAuthnPolicyFixture).Policy
			test.mutate(&configured)

			descriptor := boundGeoIPFactDescriptor()
			bindings, nativeModule := boundGeoIPGenerationBindings(t, descriptor)

			_, err := PrepareBoundNativeFactGeneration(t.Context(), BoundNativeFactGenerationInput{
				Policy: configured,
				Capabilities: []registry.NativeFactProviderCapability{
					mustBoundNativeCapability(t, "geoip", descriptor),
				},
				Bindings: bindings, PostActionAcceptance: &nativeGenerationAcceptor{},
				NativeModules: []policyruntime.NativeModuleBindingInput{nativeModule},
			})
			if err == nil {
				t.Fatal("PrepareBoundNativeFactGeneration() error = nil, want exact capability rejection")
			}
		})
	}
}

type boundNativePolicyMutation struct {
	mutate func(*policyconfig.PolicyConfig)
	name   string
}

// boundNativeCapabilityMismatchCases returns exact operator-selection violations.
func boundNativeCapabilityMismatchCases() []boundNativePolicyMutation {
	return []boundNativePolicyMutation{
		{
			name: "provider is not scheduled",
			mutate: func(configured *policyconfig.PolicyConfig) {
				namespace := configured.Namespaces[policy.AuthnNamespace]
				plan := namespace.DomainPlans["geoip"]
				checkpoint := plan.Checkpoints["pre_auth"]
				checkpoint.Providers = nil
				plan.Checkpoints["pre_auth"] = checkpoint
				namespace.DomainPlans["geoip"] = plan
				configured.Namespaces[policy.AuthnNamespace] = namespace
			},
		},
		{
			name: "declared target is not scheduled",
			mutate: func(configured *policyconfig.PolicyConfig) {
				namespace := configured.Namespaces[policy.AuthnNamespace]
				provider := namespace.Providers["environment"]
				provider.Targets = append(provider.Targets, policyconfig.TargetReferenceConfig{Action: "list_accounts"})
				namespace.Providers["environment"] = provider
				configured.Namespaces[policy.AuthnNamespace] = namespace
			},
		},
		{
			name: "produced fact is not registered",
			mutate: func(configured *policyconfig.PolicyConfig) {
				namespace := configured.Namespaces[policy.AuthnNamespace]
				provider := namespace.Providers["environment"]
				provider.ProducedFacts[1] = "plugin.geoip.unregistered"
				namespace.Providers["environment"] = provider
				configured.Namespaces[policy.AuthnNamespace] = namespace
			},
		},
		{
			name: "timeout exceeds registered maximum",
			mutate: func(configured *policyconfig.PolicyConfig) {
				namespace := configured.Namespaces[policy.AuthnNamespace]
				provider := namespace.Providers["environment"]
				provider.Timeout = 100 * time.Millisecond
				namespace.Providers["environment"] = provider
				configured.Namespaces[policy.AuthnNamespace] = namespace
			},
		},
	}
}

// TestBoundNativeFactGenerationDoesNotProjectLegacyPluginIdentity keeps legacy authn plugins out of generic native authority.
func TestBoundNativeFactGenerationDoesNotProjectLegacyPluginIdentity(t *testing.T) {
	configured := decodePolicy(t, boundNativeAuthnPolicyFixture).Policy
	namespace := configured.Namespaces[policy.AuthnNamespace]
	delete(namespace.Providers, "environment")
	namespace.Providers["plugin.geoip.environment"] = policyconfig.ProviderConfig{
		Kind: "plugin", Module: "geoip",
	}
	configured.Namespaces[policy.AuthnNamespace] = namespace

	descriptor := boundGeoIPFactDescriptor()
	bindings, nativeModule := boundGeoIPGenerationBindings(t, descriptor)

	preparation, err := PrepareBoundNativeFactGeneration(t.Context(), BoundNativeFactGenerationInput{
		Policy: configured,
		Capabilities: []registry.NativeFactProviderCapability{
			mustBoundNativeCapability(t, "geoip", descriptor),
		},
		Bindings: bindings, PostActionAcceptance: &nativeGenerationAcceptor{},
		NativeModules: []policyruntime.NativeModuleBindingInput{nativeModule},
	})
	if err != nil {
		t.Fatalf("PrepareBoundNativeFactGeneration() error = %v", err)
	}

	if len(preparation.Definitions) != 0 || len(preparation.Bindings.FactProviderIDs()) != 0 {
		t.Fatalf("legacy plugin gained generic native authority: %#v", preparation)
	}
}

// boundGeoIPFactDescriptor returns a small GeoIP-like generic native capability.
func boundGeoIPFactDescriptor() pluginapi.DecisionFactProviderDescriptor {
	return pluginapi.DecisionFactProviderDescriptor{
		Namespace: policy.AuthnNamespace, Name: "environment", Timeout: 75 * time.Millisecond,
		Targets: []pluginapi.DecisionTargetSelector{
			{Namespace: policy.AuthnNamespace, Action: string(policy.OperationAuthenticate)},
			{Namespace: policy.AuthnNamespace, Action: string(policy.OperationLookupIdentity)},
		},
		Outputs: []pluginapi.DecisionFactOutputDescriptor{
			{Name: "matched", Category: pluginapi.DecisionFactCategoryEnvironment, Kind: pluginapi.DecisionValueKindBoolean},
			{Name: "country_iso", Category: pluginapi.DecisionFactCategoryEnvironment, Kind: pluginapi.DecisionValueKindString, MaxLength: 2},
		},
	}
}

// mustBoundNativeCapability projects one frozen public descriptor into the inward neutral capability DTO.
func mustBoundNativeCapability(
	t *testing.T,
	moduleName string,
	descriptor pluginapi.DecisionFactProviderDescriptor,
) registry.NativeFactProviderCapability {
	t.Helper()

	targets := make([]decision.Target, 0, len(descriptor.Targets))
	for _, selector := range descriptor.Targets {
		target, err := decision.NewTarget(selector.Namespace, selector.Action)
		if err != nil {
			t.Fatalf("decision.NewTarget() error = %v", err)
		}

		targets = append(targets, target)
	}

	outputs := make([]registry.NativeFactOutputCapabilityInput, 0, len(descriptor.Outputs))
	for _, output := range descriptor.Outputs {
		outputs = append(outputs, registry.NativeFactOutputCapabilityInput{
			Name: output.Name, Category: decision.FactCategory(output.Category), Kind: decision.ValueKind(output.Kind),
			MaxLength: output.MaxLength, MaxItems: output.MaxItems, MaxBytes: output.MaxBytes,
		})
	}

	capability, err := registry.NewNativeFactProviderCapability(registry.NativeFactProviderCapabilityInput{
		ModuleName: moduleName, Namespace: descriptor.Namespace, ComponentName: descriptor.Name,
		Targets: targets, Outputs: outputs, MaximumTimeout: descriptor.Timeout,
	})
	if err != nil {
		t.Fatalf("registry.NewNativeFactProviderCapability() error = %v", err)
	}

	return capability
}

// boundGeoIPGenerationBindings captures the real descriptor and provider owner used by native binding preparation.
func boundGeoIPGenerationBindings(
	t *testing.T,
	descriptor pluginapi.DecisionFactProviderDescriptor,
) (*pluginruntime.GenerationBindings, policyruntime.NativeModuleBindingInput) {
	t.Helper()

	provider := &nativeFactProvider{descriptor: descriptor}
	component := pluginregistry.Component{
		Value: provider, DecisionFactProviderDescriptor: descriptor,
		ModuleName: "geoip", LocalName: "environment",
		Kind: pluginregistry.ComponentKindDecisionFactProvider, Origin: pluginregistry.ComponentOriginNative,
	}

	artifact := filepath.Join(t.TempDir(), "geoip.so")
	if err := os.WriteFile(artifact, []byte("bound-native-authn-generation"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	digest, err := pluginloader.DigestArtifact(artifact)
	if err != nil {
		t.Fatalf("pluginloader.DigestArtifact() error = %v", err)
	}

	bindings, err := pluginruntime.CaptureGenerationBindings([]pluginloader.ModuleInstance{{
		Module:      config.PluginModule{Name: "geoip", Type: config.PluginModuleTypeGo, Path: artifact},
		Descriptors: []pluginregistry.Component{component}, ArtifactPath: artifact, ArtifactDigest: digest,
		ModuleName: "geoip", Status: pluginloader.ModuleStatusRegistered,
	}})
	if err != nil {
		t.Fatalf("pluginruntime.CaptureGenerationBindings() error = %v", err)
	}

	return bindings, policyruntime.NativeModuleBindingInput{
		ModuleName: "geoip", ArtifactPath: artifact, ArtifactDigest: "sha256:geoip-fixture",
		Components: []policyruntime.NativeComponentBindingInput{{
			Value: provider, QualifiedName: "geoip/environment", Kind: string(pluginregistry.ComponentKindDecisionFactProvider),
		}},
	}
}

// assertBoundNativeFactPreparation verifies exact real contribution, binding, module, and resource ownership.
func assertBoundNativeFactPreparation(
	t *testing.T,
	preparation policyruntime.ExtensionPreparation,
	resource policyruntime.CandidateResource,
) {
	t.Helper()

	assertBoundNativeDefinition(t, preparation.Definitions)
	assertBoundNativeBindings(t, preparation.Bindings)

	if len(preparation.Resources) != 1 || preparation.Resources[0] != resource {
		t.Fatalf("bound native resources = %#v, want exact candidate resource", preparation.Resources)
	}
}

// assertBoundNativeDefinition verifies exact descriptor-derived contribution metadata.
func assertBoundNativeDefinition(t *testing.T, definitions []registry.DefinitionContribution) {
	t.Helper()

	if len(definitions) != 1 || definitions[0].Ownership().Owner() != "plugin.geoip" {
		t.Fatalf("bound native definitions = %#v, want one plugin.geoip contribution", definitions)
	}

	providers := definitions[0].Providers()
	if len(providers) != 1 || providers[0].ID() != "authn/plugin.geoip.environment" ||
		!reflect.DeepEqual(providers[0].ProducedFacts(), []string{"plugin.geoip.matched", "plugin.geoip.country_iso"}) ||
		providers[0].Failure() != registry.ProviderFailureIndeterminate ||
		providers[0].Timeout() != 50*time.Millisecond || providers[0].DiagnosticID() != "geoip-environment" {
		t.Fatalf("bound native provider = %#v, want exact configured descriptor selection", providers)
	}
}

// assertBoundNativeBindings verifies runtime binding and native module identities.
func assertBoundNativeBindings(t *testing.T, bindings *policyruntime.BindingSet) {
	t.Helper()

	if got := bindings.FactProviderIDs(); !reflect.DeepEqual(got, []string{"authn/plugin.geoip.environment"}) {
		t.Fatalf("bound native fact IDs = %v", got)
	}

	if got := bindings.NativeModuleIDs(); !reflect.DeepEqual(got, []string{"geoip"}) {
		t.Fatalf("bound native module IDs = %v", got)
	}
}

// assertBoundNativeAuthnCatalog verifies output schemas reach only their exact configured builtin actions.
func assertBoundNativeAuthnCatalog(t *testing.T, catalog *policyruntime.TargetCatalog) {
	t.Helper()

	for _, action := range []string{string(policy.OperationAuthenticate), string(policy.OperationLookupIdentity)} {
		assertBoundNativeAuthnTarget(t, catalog, action)
	}

	assertBoundNativeAuthnFactAbsence(t, catalog, string(policy.OperationListAccounts))
}

// assertBoundNativeAuthnTarget verifies one exact action contains the descriptor-derived fact shapes.
func assertBoundNativeAuthnTarget(t *testing.T, catalog *policyruntime.TargetCatalog, action string) {
	t.Helper()

	target := mustBoundNativeAuthnTarget(t, action)

	compiled, exists := catalog.Lookup(target)
	if !exists {
		t.Fatalf("catalog target %s is missing", target.String())
	}

	facts := make(map[string]registry.FactSchema)
	for _, fact := range compiled.Schema().Facts() {
		facts[fact.ID()] = fact
	}

	matched := facts["plugin.geoip.matched"]

	country := facts["plugin.geoip.country_iso"]
	if matched.Kind() != decision.ValueKindBoolean || country.Kind() != decision.ValueKindString ||
		country.MaxLength() != 2 ||
		!reflect.DeepEqual(country.AllowedSources(), []decision.FactSource{decision.FactSourcePlugin}) {
		t.Fatalf("catalog target %s facts = %#v, want exact GeoIP descriptor shapes", target.String(), facts)
	}
}

// assertBoundNativeAuthnFactAbsence verifies descriptor facts do not leak into an unselected action.
func assertBoundNativeAuthnFactAbsence(t *testing.T, catalog *policyruntime.TargetCatalog, action string) {
	t.Helper()

	target := mustBoundNativeAuthnTarget(t, action)

	compiled, exists := catalog.Lookup(target)
	if !exists {
		t.Fatalf("catalog target %s is missing", target.String())
	}

	for _, fact := range compiled.Schema().Facts() {
		if fact.ID() == "plugin.geoip.matched" || fact.ID() == "plugin.geoip.country_iso" {
			t.Fatalf("GeoIP fact %s leaked into unselected %s schema", fact.ID(), action)
		}
	}
}

// mustBoundNativeAuthnTarget constructs one exact builtin authn target.
func mustBoundNativeAuthnTarget(t *testing.T, action string) decision.Target {
	t.Helper()

	target, err := decision.NewTarget(policy.AuthnNamespace, action)
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	return target
}

type boundNativeCandidateResource struct{}

// Dispose implements candidate ownership without side effects for focused preparation tests.
func (*boundNativeCandidateResource) Dispose(context.Context) error {
	return nil
}
