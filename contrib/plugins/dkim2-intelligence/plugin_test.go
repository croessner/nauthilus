package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"testing"
)

// TestPluginRegistersOnlyExactCompositionFactsAndUpstreamInputs prevents hidden decision or storage authority.
func TestPluginRegistersOnlyExactCompositionFactsAndUpstreamInputs(t *testing.T) {
	registry := pluginregistry.NewRegistry()
	registrar := registry.NewRegistrar(config.PluginModule{Name: "dkim2_intelligence", Type: config.PluginModuleTypeGo, Config: testConfigMap()})

	plugin := NewPlugin()
	if err := plugin.Register(registrar); err != nil {
		t.Fatal(err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatal(err)
	}

	providers := registry.DecisionFactProviders()
	if len(providers) != 1 || len(registry.DecisionEffectProviders()) != 0 {
		t.Fatal("unexpected provider authority")
	}

	descriptor := providers[0].DecisionFactProviderDescriptor
	if len(descriptor.Outputs) != 3 || len(descriptor.Targets) != 1 || descriptor.Targets[0].Namespace != "dkim2" {
		t.Fatal("wrong composition target or outputs")
	}

	if err := pluginapi.ValidateDecisionFactProviderDescriptor(descriptor); err != nil {
		t.Fatal(err)
	}

	owners := map[string]bool{}
	for _, input := range descriptor.Inputs {
		owners[input.Provider] = true
	}

	if !owners["dkim2/plugin.geoip.smtp_peer"] || !owners["dkim2/plugin.reputation.assessment"] {
		t.Fatal("exact upstream ownership not declared")
	}
}

// testConfigMap keeps the conservative composition fixture free of invented provider identity allowlists.
func testConfigMap() map[string]any {
	return map[string]any{"reputation_provider": "dkim2/plugin.reputation.assessment", "reputation_fact": "plugin.reputation.dkim2_subjects", "geoip_provider": "dkim2/plugin.geoip.smtp_peer", "decision_profile": "operational"}
}
