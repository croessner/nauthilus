package main

import (
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"net/netip"
	"testing"
)

// TestIdentityContractHistoricalAndCurrentEvidenceStayDistinct covers exact CIDR, broader ASN and missing evidence.
func TestIdentityContractHistoricalAndCurrentEvidenceStayDistinct(t *testing.T) {
	raw := map[string]any{
		"reputation_provider": "dkim2/plugin.reputation.assessment", "reputation_fact": "plugin.reputation.dkim2_subjects",
		"geoip_provider": "dkim2/plugin.geoip.smtp_peer", "decision_profile": "operational",
		"signer_sets": map[string]any{"providers": []string{"asn.example"}},
		"identity_contracts": []any{
			map[string]any{"name": "cidr", "signer_domains": []string{"relay.example"}, "current_peer_cidrs": []string{"192.0.2.0/24"}},
			map[string]any{"name": "asn", "signer_sets": []string{"providers"}, "current_peer_asns": []int{64500}},
		},
	}

	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		domain          string
		target          bool
		asn             int64
		available       bool
		state, strength string
	}{
		{"relay.example", true, 0, false, "matched", "cidr"},
		{"relay.example", false, 64500, true, "domain_only", "domain_only"},
		{"asn.example", false, 0, false, "domain_only", "domain_only"},
		{"asn.example", true, 64500, true, "matched", "asn"},
		{"asn.example", true, 64501, true, "mismatch", "none"},
		{"asn.example", true, 0, false, "unavailable", "none"},
		{"missing.example", true, 64500, true, "missing", "none"},
	} {
		got := cfg.matchIdentity(tc.domain, tc.target, netip.MustParseAddr("192.0.2.1"), tc.asn, tc.available)
		if got.state != tc.state || got.strength != tc.strength {
			t.Fatalf("%+v => %+v", tc, got)
		}
	}

	raw["unknown"] = true
	if _, err := decodeConfig(pluginregistry.NewConfigView(raw)); err == nil {
		t.Fatal("unknown settings accepted")
	}
}
