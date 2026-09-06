// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"strings"
	"testing"
)

func TestDecisionBindingRegistrationRequiresExplicitContract(t *testing.T) {
	module := testModule(testDatabasePath(t, "geoip.json"))
	delete(module.Config, "decision_bindings")

	registry := pluginregistry.NewRegistry()
	if err := NewPlugin().Register(registry.NewRegistrar(module)); err == nil {
		t.Fatal("implicit authentication binding was accepted")
	}
}

func TestDecisionBindingRegistersNeutralTarget(t *testing.T) {
	module := testModule(testDatabasePath(t, "geoip.json"))
	module.Config["decision_bindings"] = []any{map[string]any{
		"component": "edge", "targets": []string{"inventory/inspect"},
		"input":         map[string]any{"fact": "resource.peer_ip", "category": "resource"},
		"output_schema": "geoip.facts.v1",
	}}
	registry, _ := registerTestPlugin(t, module)

	providers := registry.DecisionFactProviders()
	if len(providers) != 1 || providers[0].DecisionFactProviderDescriptor.Namespace != "inventory" || providers[0].LocalName != "edge" {
		t.Fatal("exact neutral provider was not registered")
	}
}

const (
	decisionInputClientIP   = "input.auth.client_ip"
	decisionPolicyNamespace = "authn"
)

// testDecisionBindings returns the explicit authentication fixture used by existing lookup tests.
func testDecisionBindings() []any {
	return []any{map[string]any{
		"component": componentSource, "targets": []string{"authn/authenticate", "authn/lookup_identity"},
		"input":         map[string]any{"fact": decisionInputClientIP, "category": "environment"},
		"output_schema": geoIPFactsSchema,
	}}
}

// testDecisionProvider compiles the test binding through the production configuration parser.
func testDecisionProvider(t *testing.T, plugin *Plugin) geoIPDecisionFactProvider {
	t.Helper()

	config, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{
		"database_path": testDatabasePath(t, "geoip.json"), "decision_bindings": testDecisionBindings(),
	}))
	if err != nil {
		t.Fatal(err)
	}

	return geoIPDecisionFactProvider{plugin: plugin, binding: config.DecisionBindings[0]}
}

var _ pluginapi.DecisionFactProvider = geoIPDecisionFactProvider{}

func TestDecisionBindingRejectsAmbiguousConfig(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "duplicate component", mutate: func(config map[string]any) {
			config["decision_bindings"] = append(testDecisionBindings(), testDecisionBindings()...)
		}},
		{name: "undeclared schema", mutate: func(config map[string]any) {
			config["decision_bindings"].([]any)[0].(map[string]any)["output_schema"] = "custom"
		}},
		{name: "unknown field", mutate: func(config map[string]any) {
			config["decision_bindings"].([]any)[0].(map[string]any)["fallback"] = true
		}},
		{name: "mixed namespace", mutate: func(config map[string]any) {
			config["decision_bindings"].([]any)[0].(map[string]any)["targets"] = []string{"authn/authenticate", "inventory/inspect"}
		}},
		{name: "wildcard", mutate: func(config map[string]any) {
			config["decision_bindings"].([]any)[0].(map[string]any)["targets"] = []string{"inventory/*"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			module := testModule(testDatabasePath(t, "geoip.json"))
			test.mutate(module.Config)

			if err := NewPlugin().Register(pluginregistry.NewRegistry().NewRegistrar(module)); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}

func TestDecisionBindingCannotChangeDuringReconfigure(t *testing.T) {
	module := testModule(testDatabasePath(t, "geoip.json"))
	_, plugin := registerTestPlugin(t, module)

	module.Config["decision_bindings"].([]any)[0].(map[string]any)["input"] = map[string]any{"fact": "resource.other_ip", "category": "resource"}
	if _, _, _, err := plugin.loadConfigAndDatabases(t.Context(), pluginregistry.NewConfigView(module.Config)); err == nil {
		t.Fatal("restart-bound input identity was changed by reload")
	}
}

func TestDecisionBindingCurrentPeerDoesNotAttributeHistoricalHops(t *testing.T) {
	for _, target := range []string{"inventory/inspect", "dkim2/accept-message-instance"} {
		t.Run(target, func(t *testing.T) {
			namespace, action, _ := strings.Cut(target, "/")
			module := testModule(testDatabasePath(t, "geoip.json"))
			module.Config["decision_bindings"] = []any{map[string]any{
				"component": "current_peer", "targets": []string{target}, "output_schema": geoIPFactsSchema,
				"input": map[string]any{"fact": "environment.rspamd.smtp_client_ip", "category": "environment"},
			}}
			registry, plugin := registerTestPlugin(t, module)

			runner := newRunnerForPlugin(registry, plugin, module, newRecordingMetrics(), &recordingTracer{})
			if err := runner.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			defer stopRunner(t, runner)

			provider := registry.DecisionFactProviders()[0].Value.(pluginapi.DecisionFactProvider)
			admitted := decisionFactView(t, "environment.rspamd.smtp_client_ip", pluginapi.DecisionFactCategoryEnvironment, decisionStringValue(t, testClientIP))
			historical := decisionFactView(t, "resource.dkim2.historical_ip", pluginapi.DecisionFactCategoryResource, decisionStringValue(t, "198.51.100.8"))
			forged := decisionFactView(t, "plugin.geoip.asn", pluginapi.DecisionFactCategoryEnvironment, decisionStringValue(t, "12345"))

			result, err := provider.Collect(t.Context(), newDecisionFactRequest(t, pluginapi.DecisionTargetSelector{Namespace: namespace, Action: action}, []pluginapi.DecisionFactView{*admitted, *historical, *forged}))
			if err != nil {
				t.Fatal(err)
			}

			assertDecisionOutput(t, result, factInputIP, testClientIP)
			assertDecisionOutput(t, result, factASN, int64(64500))

			missing, err := provider.Collect(t.Context(), newDecisionFactRequest(t, pluginapi.DecisionTargetSelector{Namespace: namespace, Action: action}, []pluginapi.DecisionFactView{*historical, *forged}))
			if err != nil || missing.ErrorClass != pluginapi.DecisionErrorClassInvalidInput {
				t.Fatal("historical or forged fact replaced the exact admitted input")
			}
		})
	}
}
