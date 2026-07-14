// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginloader

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
)

func TestLoaderPropagatesVerifiedSignerProvenance(t *testing.T) {
	artifact := writeLoaderArtifact(t)
	opener := fakeFactoryOpener(artifact, func() (pluginapi.Plugin, error) {
		return fakePlugin{metadata: validLoaderMetadata()}, nil
	})
	verified := verifiedLoaderModule("rns_auth", artifact, nil)
	verified.Signer = &config.PluginTrustSigner{ID: "release_key"}

	state, err := NewLoader(WithOpener(opener)).Load([]VerifiedModule{verified})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	instances := state.Instances()
	if got := instances[0].VerifiedSigner; got != "release_key" {
		t.Fatalf("VerifiedSigner = %q, want release_key", got)
	}
}

func TestDiscoveryExposesVerifiedCompatibilityWithDefensiveCopies(t *testing.T) {
	instance := ModuleInstance{
		ModuleName:     "rns_auth",
		VerifiedSigner: "release_key",
		Module: config.PluginModule{
			Signer:    "release_key",
			Signature: "minisign:/plugins/rns_auth.so.minisig",
			Compatibility: config.PluginCompatibility{
				TraceScopes: []string{"nauthilus/lua/blocklist"},
				Metrics: []config.PluginCompatibilityMetric{{
					Type:    pluginapi.MetricTypeHistogram,
					Name:    "legacy_duration_seconds",
					Help:    "Legacy duration",
					Labels:  []string{"service"},
					Buckets: []float64{0.01, 0.1},
				}},
			},
		},
	}

	discovered := discoveryModule(instance)
	if !discovered.SignatureVerified || discovered.VerifiedSigner != "release_key" {
		t.Fatalf("verified provenance = %#v, want release_key", discovered)
	}

	discovered.Compatibility.TraceScopes[0] = "mutated"

	discovered.Compatibility.Metrics[0].Labels[0] = "mutated"

	if got := instance.Module.Compatibility.TraceScopes[0]; got != "nauthilus/lua/blocklist" {
		t.Fatalf("instance trace scope after discovery mutation = %q", got)
	}

	if got := instance.Module.Compatibility.Metrics[0].Labels[0]; got != "service" {
		t.Fatalf("instance metric label after discovery mutation = %q", got)
	}
}

func TestDiscoveryHidesCompatibilityWithoutVerifiedSigner(t *testing.T) {
	instance := ModuleInstance{
		ModuleName: "rns_auth",
		Module: config.PluginModule{Compatibility: config.PluginCompatibility{
			TraceScopes: []string{"nauthilus/lua/blocklist"},
		}},
	}

	discovered := discoveryModule(instance)
	if len(discovered.Compatibility.TraceScopes) != 0 {
		t.Fatalf("unsigned discovery scopes = %#v, want none", discovered.Compatibility.TraceScopes)
	}
}

func TestDiscoveryHidesCompatibilityForFailedModule(t *testing.T) {
	instance := ModuleInstance{
		ModuleName:     "rns_auth",
		VerifiedSigner: "release_key",
		Status:         ModuleStatusFailed,
		Module: config.PluginModule{Compatibility: config.PluginCompatibility{
			TraceScopes: []string{"nauthilus/lua/blocklist"},
		}},
	}

	discovered := discoveryModule(instance)
	if len(discovered.Compatibility.TraceScopes) != 0 {
		t.Fatalf("failed-module discovery scopes = %#v, want none", discovered.Compatibility.TraceScopes)
	}
}
