// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

func TestProviderDescriptorUsesOnlyGenericPolicyExtension(t *testing.T) {
	descriptor := (decisionFactProvider{}).Descriptor()

	if err := pluginapi.ValidateDecisionFactProviderDescriptor(descriptor); err != nil {
		t.Fatalf("ValidateDecisionFactProviderDescriptor() error = %v", err)
	}

	if descriptor.Namespace != providerNamespace || descriptor.Name != providerName ||
		len(descriptor.Targets) != 1 || descriptor.Targets[0] != exactTarget {
		t.Fatalf("descriptor identity = %#v", descriptor)
	}

	if len(descriptor.Outputs) != 1 || descriptor.Outputs[0].Name != outputAssessedChain ||
		descriptor.Outputs[0].Kind != pluginapi.DecisionValueKindRecords {
		t.Fatalf("descriptor outputs = %#v", descriptor.Outputs)
	}
}

func TestPluginRegistersExactlyOneDecisionFactProvider(t *testing.T) {
	registry := pluginregistry.NewRegistry()
	module := config.PluginModule{Name: pluginName, Type: config.PluginModuleTypeGo, Path: "/plugins/dkim2-reputation.so", Config: testConfigMap()}
	plugin := NewPlugin()
	registrar := registry.NewRegistrar(module)

	if err := plugin.Register(registrar); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if err := registrar.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}

	if providers := registry.DecisionFactProviders(); len(providers) != 1 {
		t.Fatalf("DecisionFactProviders() length = %d, want 1", len(providers))
	}

	if len(registry.EnvironmentSources()) != 0 || len(registry.PolicyAttributes()) != 0 {
		t.Fatal("plugin must not register legacy environment or policy-attribute surfaces")
	}
}

func TestConfigRejectsNonCanonicalAndAmbiguousEntries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "uppercase domain", mutate: func(config map[string]any) {
			config["domains"] = []map[string]any{{"domain": "Relay.Example", "reputation": reputationTrusted}}
		}},
		{name: "host bits", mutate: func(config map[string]any) {
			config["client_networks"] = []map[string]any{{"cidr": "203.0.113.7/24", "reputation": reputationTrusted}}
		}},
		{name: "unsorted changes", mutate: func(config map[string]any) {
			config["contracts"] = []map[string]any{{
				"signer_domain": "relay.example", "allowed_client_cidrs": []string{"203.0.113.0/24"},
				"permitted_change_classes": []string{"header.rewrite", "body.rewrite"},
			}}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testConfigMap()
			test.mutate(config)

			if _, err := decodeAssessmentConfig(pluginregistry.NewConfigView(config)); err == nil {
				t.Fatal("decodeAssessmentConfig() error = nil")
			}
		})
	}
}

func TestAssessmentUsesCurrentSMTPPeerOnlyForTargetHop(t *testing.T) {
	config := mustTestConfig(t)
	projection := verifierProjection{
		clientIP: netip.MustParseAddr("203.0.113.7"), verificationState: "PASS", authenticationState: "PASS",
		disposition: "continue", targetSequence: 2, targetMessageInstance: 2,
		chain: []verifierHop{
			{sequence: 1, messageInstance: 1, signerDomain: "origin.example", historyHeaderState: "matched", historyBodyState: "matched", bodyAvailability: "known"},
			{sequence: 2, messageInstance: 2, signerDomain: "relay.example", historyHeaderState: "matched", historyBodyState: "matched", bodyAvailability: "known"},
		},
	}

	assessments := assessProjection(config, projection)
	if assessments[0].contractState != contractMatched || !assessments[0].acceptable {
		t.Fatalf("historical assessment = %#v, want signer/Recipe-only match", assessments[0])
	}

	if assessments[1].contractState != contractMatched || !assessments[1].acceptable {
		t.Fatalf("target assessment = %#v, want current-peer match", assessments[1])
	}

	projection.clientIP = netip.MustParseAddr("198.51.100.10")

	assessments = assessProjection(config, projection)
	if !assessments[0].acceptable || assessments[0].contractState != contractMatched {
		t.Fatalf("historical assessment must not correlate current peer: %#v", assessments[0])
	}

	if assessments[1].acceptable || assessments[1].contractState != contractPeerMismatch ||
		!slices.Contains(assessments[1].violations, "contract_peer_mismatch") {
		t.Fatalf("target assessment must reject peer mismatch: %#v", assessments[1])
	}
}

func TestTerminalNextDomainCannotBecomeAcceptable(t *testing.T) {
	config := mustTestConfig(t)
	projection := verifierProjection{
		clientIP: netip.MustParseAddr("203.0.113.7"), verificationState: "PASS", authenticationState: "PASS",
		disposition: "out_of_band_required", targetSequence: 1, targetMessageInstance: 1,
		chain: []verifierHop{{
			sequence: 1, messageInstance: 1, signerDomain: "relay.example", custodyTransition: "terminal_next_domain",
			historyHeaderState: "matched", historyBodyState: "matched", bodyAvailability: "known",
		}},
	}

	assessment := assessProjection(config, projection)[0]
	if assessment.acceptable || !slices.Contains(assessment.violations, "terminal_oob_required") ||
		!slices.Contains(assessment.violations, "upstream_nonpermittable") {
		t.Fatalf("terminal assessment = %#v", assessment)
	}
}

func TestCollectRejectsMalformedPeerAndEmitsExactRecord(t *testing.T) {
	plugin := NewPlugin()
	plugin.swapConfig(mustTestConfig(t))
	provider := decisionFactProvider{plugin: plugin}

	valid := testDecisionRequest(t, "203.0.113.7")

	result, err := provider.Collect(context.Background(), valid)
	if err != nil || result.ErrorClass != "" || len(result.Facts) != 1 {
		t.Fatalf("Collect(valid) = %#v, %v", result, err)
	}

	list, ok := result.Facts[0].Value.Records()
	if !ok || len(list.Records()) != 1 || len(list.Records()[0].Fields()) != 10 {
		t.Fatalf("assessed_chain value = %#v", result.Facts[0].Value)
	}

	malformed := testDecisionRequest(t, "::ffff:203.0.113.7")

	result, err = provider.Collect(context.Background(), malformed)
	if err != nil || result.ErrorClass != pluginapi.DecisionErrorClassInvalidInput || len(result.Facts) != 0 {
		t.Fatalf("Collect(mapped peer) = %#v, %v", result, err)
	}
}

// mustTestConfig decodes the canonical reference snapshot.
func mustTestConfig(t *testing.T) *assessmentConfig {
	t.Helper()

	config, err := decodeAssessmentConfig(pluginregistry.NewConfigView(testConfigMap()))
	if err != nil {
		t.Fatalf("decodeAssessmentConfig() error = %v", err)
	}

	return config
}

// testConfigMap returns a detached valid operator-owned configuration.
func testConfigMap() map[string]any {
	return map[string]any{
		"domains": []map[string]any{
			{"domain": "example.test", "reputation": reputationTrusted},
			{"domain": "origin.example", "reputation": reputationNeutral},
			{"domain": "relay.example", "reputation": reputationTrusted},
		},
		"client_networks": []map[string]any{
			{"cidr": "203.0.113.0/24", "reputation": reputationTrusted},
			{"cidr": "198.51.100.0/24", "reputation": reputationNeutral},
		},
		"contracts": []map[string]any{
			{"signer_domain": "example.test", "allowed_client_cidrs": []string{"203.0.113.0/24"}, "permitted_change_classes": []string{"body.rewrite", "header.rewrite"}},
			{"signer_domain": "origin.example", "allowed_client_cidrs": []string{"192.0.2.0/24"}, "permitted_change_classes": []string{}},
			{"signer_domain": "relay.example", "allowed_client_cidrs": []string{"203.0.113.0/24"}, "permitted_change_classes": []string{"body.rewrite", "header.rewrite"}},
		},
	}
}
