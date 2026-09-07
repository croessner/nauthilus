package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/policy/catalogcompile"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"github.com/croessner/nauthilus/v4/server/policy/testsupport"
	"gopkg.in/yaml.v3"
)

// TestDKIM2CompositionConfiguredDependenciesAndVisibility validates the actual composition provider against the merged operator schema.
func TestDKIM2CompositionConfiguredDependenciesAndVisibility(t *testing.T) {
	document := compositionPolicyDocument(t, false)

	supervisor, err := effectsupervisor.New(effectsupervisor.Config{Lifetime: t.Context(), Capacity: 1, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := supervisor.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})

	for _, broken := range []string{"", "dependency", "visibility", "owner"} {
		t.Run(broken, func(t *testing.T) {
			configured := compositionPolicyDocument(t, broken == "visibility")
			ns := configured.Policy.Namespaces["dkim2"]
			provider := ns.Providers["intelligence_assessment"]

			switch broken {
			case "dependency":
				provider.Requires = nil
			case "owner":
				provider.Requires = []string{"dkim2/plugin.geoip.smtp_peer"}
			}

			ns.Providers["intelligence_assessment"] = provider
			configured.Policy.Namespaces["dkim2"] = ns
			bindings := compositionNativeBindings(t, document)

			normalized, err := configinput.Normalize(t.Context(), configured)
			if err != nil {
				t.Fatal(err)
			}

			catalog := compositionConfiguredCatalog(t, normalized, supervisor)

			preparation, err := configinput.PrepareConfiguredNativeGeneration(t.Context(), configinput.ConfiguredNativeGenerationInput{Policy: normalized.Policy, Bindings: bindings, PostActionAcceptance: supervisor})
			if err == nil {
				err = preparation.Bindings.ValidateCatalog(catalog)
			}

			if (err != nil) != (broken != "") {
				t.Fatalf("dependency boundary %q: %v", broken, err)
			}
		})
	}
}

// compositionPolicyDocument composes the examples and isolates facts-only activation from the legacy decision rules.
func compositionPolicyDocument(t *testing.T, badVisibility bool) policyconfig.Document {
	t.Helper()
	base := compositionYAML(t, "policy_dkim2_rspamd_verifier.yml")
	addition := compositionYAML(t, "go_plugin_dkim2_intelligence.yml")
	merged := testsupport.MergeExample(base, addition).(map[string]any)

	ns := merged["policy"].(map[string]any)["namespaces"].(map[string]any)["dkim2"].(map[string]any)
	if badVisibility {
		facts := ns["schema_contributions"].(map[string]any)["static"].(map[string]any)["accept-message-instance"].(map[string]any)["versions"].(map[string]any)["v1"].(map[string]any)["facts"].([]any)
		for _, item := range facts {
			fact := item.(map[string]any)
			if fact["attribute"] != "resource.dkim2.chain" {
				continue
			}

			for _, field := range fact["record_schema"].(map[string]any)["fields"].([]any) {
				f := field.(map[string]any)
				if f["name"] == "hop_binding" {
					f["provider_visibility"] = []string{"dkim2/plugin.reputation.assessment"}
				}
			}
		}
	}

	delete(ns["providers"].(map[string]any), "assessment")
	ns["policy_sets"] = map[string]any{"verifier": map[string]any{"visibility": "private", "rules": []any{}}}
	checkpoint := ns["domain_plans"].(map[string]any)["verifier"].(map[string]any)["checkpoints"].(map[string]any)["final_decision"].(map[string]any)
	providers := checkpoint["providers"].([]any)

	kept := make([]any, 0, len(providers))
	for _, p := range providers {
		if p.(map[string]any)["name"] != "assessment" {
			kept = append(kept, p)
		}
	}

	checkpoint["providers"] = kept

	raw, err := yaml.Marshal(map[string]any{"policy": merged["policy"]})
	if err != nil {
		t.Fatal(err)
	}

	document, err := policyconfig.Decode("yaml", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	return document
}

// compositionYAML reads the tracked fragment without replacing production credentials or opening services.
func compositionYAML(t *testing.T, name string) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("../../../server/docs/examples", name))
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err = yaml.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}

	return result
}

type compositionUpstream struct {
	descriptor pluginapi.DecisionFactProviderDescriptor
}

// Descriptor freezes the deterministic upstream fixture contract.
func (p compositionUpstream) Descriptor() pluginapi.DecisionFactProviderDescriptor {
	return p.descriptor
}

// Collect does not simulate storage or geographic evidence in the activation-only test.
func (compositionUpstream) Collect(context.Context, pluginapi.DecisionFactRequest) (pluginapi.DecisionFactResult, error) {
	return pluginapi.DecisionFactResult{}, nil
}

// compositionNativeBindings captures the real composition factory and explicitly identified upstream test doubles.
func compositionNativeBindings(t *testing.T, document policyconfig.Document) *pluginruntime.GenerationBindings {
	t.Helper()

	registry := pluginregistry.NewRegistry()
	instances := []pluginloader.ModuleInstance{}

	for alias, provider := range document.Policy.Namespaces["dkim2"].Providers {
		module := config.PluginModule{Name: provider.Module, Type: config.PluginModuleTypeGo, Config: testConfigMap()}
		registrar := registry.NewRegistrar(module)

		if provider.Module == "dkim2_intelligence" {
			cfg, err := decodeConfig(pluginregistry.NewConfigView(testConfigMap()))
			if err != nil {
				t.Fatal(err)
			}

			composer := decisionProvider{plugin: &Plugin{config: cfg}, config: cfg}
			if err = registrar.RegisterDecisionFactProvider(composer); err != nil {
				t.Fatal(err)
			}
		} else {
			descriptor := compositionUpstreamDescriptor(provider.NativeComponent(alias), provider.Module, provider.ProducedFacts, document)
			if err := registrar.RegisterDecisionFactProvider(compositionUpstream{descriptor}); err != nil {
				t.Fatal(err)
			}
		}

		if err := registrar.Commit(); err != nil {
			t.Fatal(err)
		}

		artifact := filepath.Join(t.TempDir(), module.Name+".so")
		if err := os.WriteFile(artifact, []byte("in-process-binding-test"), 0600); err != nil {
			t.Fatal(err)
		}

		digest, err := pluginloader.DigestArtifact(artifact)
		if err != nil {
			t.Fatal(err)
		}

		module.Path = artifact
		instances = append(instances, pluginloader.ModuleInstance{Module: module, Descriptors: registrar.Components(), ArtifactPath: artifact, ArtifactDigest: digest, ModuleName: module.Name, Status: pluginloader.ModuleStatusRegistered})
	}

	bindings, err := pluginruntime.CaptureGenerationBindings(instances)
	if err != nil {
		t.Fatal(err)
	}

	return bindings
}

// compositionUpstreamDescriptor derives only fixture output types from the existing typed contracts.
func compositionUpstreamDescriptor(name, module string, outputs []string, document policyconfig.Document) pluginapi.DecisionFactProviderDescriptor {
	descriptor := pluginapi.DecisionFactProviderDescriptor{Name: name, Namespace: "dkim2", Timeout: time.Second, Targets: []pluginapi.DecisionTargetSelector{{Namespace: "dkim2", Action: "accept-message-instance"}}}

	facts := document.Policy.Namespaces["dkim2"].SchemaContributions.Static["accept-message-instance"].Versions["v1"].Facts
	for _, id := range outputs {
		for _, fact := range facts {
			if fact.Attribute != id {
				continue
			}

			descriptor.Outputs = append(descriptor.Outputs, pluginapi.DecisionFactOutputDescriptor{Name: strings.TrimPrefix(id, "plugin."+module+"."), Category: pluginapi.DecisionFactCategory(fact.Category), Kind: pluginapi.DecisionValueKind(fact.Type), MaxLength: fact.MaxLength, MaxItems: fact.MaxItems, MaxBytes: fact.MaxBytes})
		}
	}

	return descriptor
}

// compositionConfiguredCatalog compiles only the exact DKIM2 target against the complete normalized contributor set.
func compositionConfiguredCatalog(t *testing.T, normalized configinput.UnifiedPolicyInput, supervisor *effectsupervisor.Supervisor) *policyruntime.TargetCatalog {
	t.Helper()

	contributors, err := normalized.Contributors(t.Context(), supervisor)
	if err != nil {
		t.Fatal(err)
	}

	activations := []registry.TargetActivation{}

	for _, activation := range normalized.Activations {
		if activation.Target().String() == "dkim2/accept-message-instance" {
			activations = append(activations, activation)
		}
	}

	catalog, err := catalogcompile.NewTargetCatalogCompiler(contributors...).Compile(t.Context(), activations)
	if err != nil {
		t.Fatal(err)
	}

	return catalog
}
