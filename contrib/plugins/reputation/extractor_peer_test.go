package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
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
	binding := targetBindingConfig{Subjects: []extractorConfig{{Attribute: "plugin.geoip.asn", Provider: "dkim2/plugin.geoip.smtp_peer", Category: pluginapi.DecisionFactCategoryEnvironment, InputKind: pluginapi.DecisionValueKindInteger, Role: "smtp_peer_asn", Kind: kindASN, Optional: true}}}
	inputs, err := assessmentInputs(binding.Subjects)
	requireNoError(t, err)

	if len(inputs) != 1 || inputs[0].Provider != "dkim2/plugin.geoip.smtp_peer" || inputs[0].Kind != pluginapi.DecisionValueKindInteger {
		t.Fatal("exact ASN provider contract lost")
	}
}
