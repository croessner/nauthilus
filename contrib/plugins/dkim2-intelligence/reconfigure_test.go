package main

import (
	"context"
	"errors"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// TestReconfigureSeparatesOperatorContractsFromRestartBoundProviders keeps provider identity fixed after registration.
func TestReconfigureSeparatesOperatorContractsFromRestartBoundProviders(t *testing.T) {
	registry := pluginregistry.NewRegistry()
	plugin := NewPlugin()

	if err := plugin.Register(registry.NewRegistrar(config.PluginModule{
		Name: "dkim2_intelligence", Type: config.PluginModuleTypeGo, Config: testConfigMap(),
	})); err != nil {
		t.Fatal(err)
	}

	contracts := testConfigMap()
	contracts["signer_sets"] = map[string]any{"example": []any{"example.test"}}

	profile := testConfigMap()
	profile["decision_profile"] = "fast"

	invalid := testConfigMap()
	invalid["decision_profile"] = "unknown"

	tests := []struct {
		config       map[string]any
		name         string
		wantErr      bool
		restartBound bool
	}{
		{name: "operator contracts", config: contracts},
		{name: "decision profile", config: profile, wantErr: true, restartBound: true},
		{name: "invalid", config: invalid, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view := pluginregistry.NewConfigView(test.config)

			err := plugin.ValidateReconfigure(context.Background(), view)
			if (err != nil) != test.wantErr || errors.Is(err, pluginapi.ErrRestartRequired) != test.restartBound {
				t.Fatalf("ValidateReconfigure() error = %v, want error %v restart-bound %v", err, test.wantErr, test.restartBound)
			}

			if plugin.snapshot().raw.DecisionProfile != "operational" || len(plugin.snapshot().raw.SignerSets) != 0 {
				t.Fatal("ValidateReconfigure changed the running configuration")
			}
		})
	}

	if err := plugin.Reconfigure(context.Background(), pluginregistry.NewConfigView(contracts)); err != nil {
		t.Fatalf("Reconfigure(operator contracts) error = %v", err)
	}

	if len(plugin.snapshot().raw.SignerSets) != 1 {
		t.Fatal("Reconfigure did not apply the operator contracts")
	}
}
