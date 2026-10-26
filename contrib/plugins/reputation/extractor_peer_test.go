package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"testing"
)

// TestAssessmentPeerExtractorsDeriveConfiguredNetworksAndAcceptTypedASN keeps geographic absence independent of other subjects.
func TestAssessmentPeerExtractorsDeriveConfiguredNetworksAndAcceptTypedASN(t *testing.T) {
	cfg := testConfig(t)
	address := "192.0.2.3"
	ip, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{String: &address})
	requireNoError(t, err)
	network, err := cfg.extractedValue(extractorConfig{Role: "peer_network", Kind: kindNetwork, Derive: "network_from_ip"}, ip, nil)
	requireNoError(t, err)

	if network.value != "192.0.2.0/24" {
		t.Fatalf("derived network=%s", network.value)
	}

	asn := int64(64500)
	number, err := pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Integer: &asn})
	requireNoError(t, err)
	subject, err := cfg.extractedValue(extractorConfig{Role: "peer_asn", Kind: kindASN, InputKind: pluginapi.DecisionValueKindInteger}, number, nil)
	requireNoError(t, err)

	if subject.value != "64500" {
		t.Fatal("typed provider ASN was not canonicalized")
	}
}

// TestAssessmentOptionalPeerInputProducesUnavailableWithoutDroppingOtherSubjects keeps absence explicit.
func TestAssessmentOptionalPeerInputProducesUnavailableWithoutDroppingOtherSubjects(t *testing.T) {
	cfg := testConfig(t)
	target := pluginapi.DecisionTargetSelector{Namespace: "workflow", Action: "inspect"}
	cfg.bindings[target] = targetBindingConfig{Subjects: []extractorConfig{{Attribute: "plugin.geoip.asn", Role: "peer_asn", Kind: kindASN, InputKind: pluginapi.DecisionValueKindInteger, Optional: true}}}
	subjects, err := cfg.extractSubjects(target, nil)
	requireNoError(t, err)

	if len(subjects) != 1 || !subjects[0].unavailable || subjects[0].value != "" {
		t.Fatal("missing input invented a subject or disappeared")
	}
}

// TestAssessmentExtractorDeclaresExactUpstreamOwnerAndInputKind fixes scheduling authority before requests.
func TestAssessmentExtractorDeclaresExactUpstreamOwnerAndInputKind(t *testing.T) {
	binding := targetBindingConfig{Subjects: []extractorConfig{{Attribute: "plugin.geoip.asn", Provider: "mail/plugin.geoip.smtp_peer", Category: pluginapi.DecisionFactCategoryEnvironment, InputKind: pluginapi.DecisionValueKindInteger, Role: "smtp_peer_asn", Kind: kindASN, Optional: true}}}
	inputs, err := assessmentInputs(binding.Subjects)
	requireNoError(t, err)

	if len(inputs) != 1 || inputs[0].Provider != "mail/plugin.geoip.smtp_peer" || inputs[0].Kind != pluginapi.DecisionValueKindInteger {
		t.Fatal("exact ASN provider contract lost")
	}
}

// TestAssessmentCombinesAuthenticationAndRecordBindingWithoutComponentCollision composes namespace-bound bindings.
func TestAssessmentCombinesAuthenticationAndRecordBindingWithoutComponentCollision(t *testing.T) {
	raw := learningConfigMap(t)
	raw["target_bindings"] = append(raw["target_bindings"].([]any), recordTargetBinding())

	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)

	if len(cfg.bindings) != 2 {
		t.Fatal("consumer binding dropped during composition")
	}

	auth := cfg.bindings[pluginapi.DecisionTargetSelector{Namespace: "authn", Action: "authenticate"}]

	inventory := cfg.bindings[pluginapi.DecisionTargetSelector{Namespace: "inventory", Action: "inspect-shipment"}]
	if auth.Component == inventory.Component || auth.Component != "authentication" || inventory.Component != "assessment" {
		t.Fatal("namespace-bound component collision")
	}
}

// recordTargetBinding returns an operator binding with correlated record, current-peer and upstream ASN subjects.
func recordTargetBinding() map[string]any {
	return map[string]any{
		"component": "assessment", "decision_profile": "operational", "output_fact": "inventory_subjects",
		"target": "inventory/inspect-shipment",
		"subjects": []any{
			map[string]any{
				"attribute": "resource.inventory.legs", "category": "resource", "field": "carrier", "kind": "dns_domain", "role": "carrier",
				"correlation_fields": []any{"sequence", "leg_binding", "carrier"},
				"correlation_types":  map[string]any{"sequence": "integer", "leg_binding": "bytes", "carrier": "string"},
			},
			map[string]any{"attribute": "environment.warehouse.dock_ip", "category": "environment", "kind": "ip", "role": "dock_ip"},
			map[string]any{
				"attribute": "environment.warehouse.dock_ip", "category": "environment", "derive": "network_from_ip",
				"kind": "network", "role": "dock_network",
			},
			map[string]any{
				"attribute": "plugin.geoip.asn", "category": "environment", "input_kind": "integer", "kind": "asn",
				"optional": true, "provider": "inventory/plugin.geoip.dock_peer", "role": "dock_asn",
			},
		},
	}
}
