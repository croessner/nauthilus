package main

import (
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"testing"
)

// TestPeerRecordRejectsPartialTuplesAndInvalidContractStrength exercises semantic checks beyond the host kind schema.
func TestPeerRecordRejectsPartialTuplesAndInvalidContractStrength(t *testing.T) {
	builder := newRecordBuilder()
	builder.text("reputation_profile", "operational")

	for _, role := range []string{"ip", "network", "asn"} {
		builder.tuple(role, view.Tuple{State: view.Unavailable, Profile: "operational", Band: view.Unavailable, Override: view.NoOverride})
	}

	builder.text("geoip_state", "unavailable")
	builder.text("target_contract_state", "unavailable")
	builder.text("target_contract_strength", "none")

	if _, err := builder.record(peerFields(), maximumPeerBytes); err != nil {
		t.Fatal(err)
	}

	builder.text("target_contract_strength", "cidr")

	if _, err := builder.record(peerFields(), maximumPeerBytes); err == nil {
		t.Fatal("unavailable contract acquired network strength")
	}

	builder.text("target_contract_strength", "none")

	number := .2
	builder.add("ip_risk_score", pluginapi.DecisionValueInput{Double: &number})

	if _, err := builder.record(peerFields(), maximumPeerBytes); err == nil {
		t.Fatal("unavailable tuple acquired measurements")
	}
}

// TestChainContractCannotPromoteHistoricalEvidence rejects invalid state/target combinations at the record boundary.
func TestChainContractCannotPromoteHistoricalEvidence(t *testing.T) {
	for _, tc := range []struct {
		target          bool
		state, strength string
	}{
		{false, "matched", "cidr"}, {false, "matched", "asn"}, {true, "domain_only", "domain_only"},
	} {
		b := newRecordBuilder()
		b.boolean("is_target", tc.target)
		b.text("identity_contract_state", tc.state)
		b.text("identity_contract_strength", tc.strength)

		if validateChainContract(b.fields) == nil {
			t.Fatal("inconsistent historical identity accepted")
		}
	}
}
