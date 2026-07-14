// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import (
	"path/filepath"
	"strings"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

func TestCompatibilityObservabilityRemainsVisibleInConfigDump(t *testing.T) {
	output, err := RenderNonDefaultConfigDump(map[string]any{
		"plugins": map[string]any{
			"modules": []map[string]any{{
				"name": "rns_auth",
				"compatibility": map[string]any{
					"trace_scopes": []string{"nauthilus/lua/blocklist"},
					"metrics": []map[string]any{{
						"type": "counter",
						"name": "legacy_requests_total",
						"help": "Legacy requests",
					}},
				},
			}},
		},
	})
	if err != nil {
		t.Fatalf("RenderNonDefaultConfigDump() error = %v", err)
	}

	for _, expected := range []string{"compatibility", "trace_scopes", "nauthilus/lua/blocklist", "legacy_requests_total"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("config dump missing %q: %s", expected, output)
		}
	}
}

func TestValidatePluginsAcceptsSignedCompatibilityAllowlist(t *testing.T) {
	plugins := compatibilityTestPlugins(t)

	if err := ValidatePlugins(plugins); err != nil {
		t.Fatalf("ValidatePlugins() error = %v", err)
	}

	definition := plugins.Modules[0].Compatibility.Metrics[0].Definition()

	definition.Labels[0] = "mutated"

	if got := plugins.Modules[0].Compatibility.Metrics[0].Labels[0]; got != "service" {
		t.Fatalf("config label after public copy mutation = %q, want service", got)
	}
}

func TestValidatePluginsRejectsUnsignedCompatibilityAllowlist(t *testing.T) {
	plugins := compatibilityTestPlugins(t)
	plugins.Modules[0].Signature = ""
	plugins.Modules[0].Signer = ""

	err := ValidatePlugins(plugins)
	assertPluginConfigError(t, err, "plugins.modules[0].compatibility")
}

func TestValidatePluginsRejectsCompatibilityWhenVerificationIsDisabled(t *testing.T) {
	plugins := compatibilityTestPlugins(t)
	plugins.VerificationPolicy = PluginVerificationPolicyOff

	err := ValidatePlugins(plugins)
	assertPluginConfigError(t, err, "plugins.modules[0].compatibility")
}

func TestValidatePluginsRejectsDuplicateExactCompatibilityMetric(t *testing.T) {
	plugins := compatibilityTestPlugins(t)
	second := plugins.Modules[0]
	second.Name = "rns_auth_shadow"
	second.Path = filepath.Join(t.TempDir(), "rns_auth_shadow.so")
	second.Signature = "minisign:" + filepath.Join(t.TempDir(), "rns_auth_shadow.so.minisig")
	plugins.AllowedDirs = append(plugins.AllowedDirs, filepath.Dir(second.Path))
	plugins.Modules = append(plugins.Modules, second)

	err := ValidatePlugins(plugins)
	assertPluginConfigError(t, err, "plugins.modules[1].compatibility.metrics[0].name")
}

// compatibilityTestPlugins returns a signed module with exact observability allowlists.
func compatibilityTestPlugins(t *testing.T) *PluginsSection {
	t.Helper()

	directory := t.TempDir()

	return &PluginsSection{
		AllowedDirs: []string{directory},
		Trust: PluginTrustSection{Signers: []PluginTrustSigner{{
			ID:        "release_key",
			Format:    PluginSignatureFormatMinisign,
			PublicKey: "trusted-key-material",
		}}},
		Modules: []PluginModule{{
			Name:      "rns_auth",
			Type:      PluginModuleTypeGo,
			Path:      filepath.Join(directory, "rns_auth.so"),
			Signature: "minisign:" + filepath.Join(directory, "rns_auth.so.minisig"),
			Signer:    "release_key",
			Compatibility: PluginCompatibility{
				Metrics: []PluginCompatibilityMetric{{
					Type:    pluginapi.MetricTypeHistogram,
					Name:    "legacy_request_duration_seconds",
					Help:    "Legacy request duration",
					Labels:  []string{"service"},
					Buckets: []float64{0.01, 0.1, 1},
				}},
				TraceScopes: []string{"nauthilus/lua/blocklist"},
			},
		}},
	}
}
