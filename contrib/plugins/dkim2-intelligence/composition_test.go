package main

import (
	"fmt"
	projection "github.com/croessner/nauthilus/v4/contrib/plugins/internal/dkim2projection"
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	"net/netip"
	"strings"
	"testing"
)

// TestAssessedChainAndPeerKeepHistoricalIdentityAndIndependentFailures proves complete output semantics.
func TestAssessedChainAndPeerKeepHistoricalIdentityAndIndependentFailures(t *testing.T) {
	cfg := &configuration{raw: rawConfig{DecisionProfile: "operational"}, contracts: map[string]identityContract{
		"relay.example": {prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
	}}

	hops := []projection.Hop{}
	for i := 1; i <= 2; i++ {
		hops = append(hops, projection.Hop{Sequence: int64(i), MessageInstance: int64(i), SignerDomain: "relay.example", HopBinding: make([]byte, 32), SignatureState: "pass", CustodyTransition: "ordinary", RecipeMode: "unchanged", RecipeBodyMode: "absent", HistoryHeaderState: "matched", HistoryBodyState: "matched", BodyAvailability: "known"})
	}

	hops[0].CustodyTransition = "origin"
	source := projection.Projection{Chain: hops, TargetSequence: 2, TargetMessageInstance: 2, ClientIP: netip.MustParseAddr("192.0.2.1"), AuthenticationState: "PASS", Disposition: "continue"}
	missing := view.Tuple{State: view.NotFound, Profile: "operational", Band: view.Unknown, Override: view.NoOverride}
	subjects := correlatedSubjects{signers: []view.Tuple{missing, missing}, peers: map[string]view.Tuple{"ip": missing, "network": missing, "asn": {State: view.Unavailable, Profile: "operational", Band: view.Unavailable, Override: view.NoOverride}}}

	result, err := cfg.compose(source, subjects, geographicEvidence{state: "not_found"})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.chain) != 2 {
		t.Fatal("chain coverage changed")
	}

	first, last := recordFields(result.chain[0]), recordFields(result.chain[1])
	historical, _ := first["identity_contract_strength"].Value().StringValue()

	target, _ := last["identity_contract_strength"].Value().StringValue()
	if historical != "domain_only" || target != "cidr" {
		t.Fatal("current peer evidence attributed to historical hop")
	}

	peer := recordFields(result.peer)
	ip, _ := peer["ip_state"].Value().StringValue()

	asn, _ := peer["asn_state"].Value().StringValue()
	if ip != "not_found" || asn != "unavailable" {
		t.Fatal("independent failure states concealed")
	}

	for _, record := range result.chain {
		fields := recordFields(record)

		state, _ := fields["signature_state"].Value().StringValue()
		if state != "pass" {
			t.Fatal("verifier signature state rewritten")
		}

		if _, present := fields["ip"]; present {
			t.Fatal("peer address duplicated")
		}
	}
}

// TestChainBoundsRejectExcessiveCountAndAggregateBeforePublication covers the largest legal chain and oversized controls.
func TestChainBoundsRejectExcessiveCountAndAggregateBeforePublication(t *testing.T) {
	original, err := projection.Decode(trackedRequest(t))
	if err != nil {
		t.Fatal(err)
	}

	cfg := &configuration{raw: rawConfig{DecisionProfile: "operational"}, contracts: map[string]identityContract{}}
	missing := view.Tuple{State: view.NotFound, Profile: "operational", Band: view.Unknown, Override: view.NoOverride}

	for _, tc := range []struct {
		name      string
		count     int
		oversized bool
		valid     bool
	}{{"empty", 0, false, false}, {"maximum", 128, false, true}, {"excess", 129, false, false}, {"aggregate", 128, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			source := original
			source.Chain = nil
			subjects := correlatedSubjects{peers: map[string]view.Tuple{"ip": missing, "network": missing, "asn": missing}}

			for i := 0; i < tc.count; i++ {
				hop := original.Chain[0]
				hop.Sequence = int64(i + 1)

				hop.MessageInstance = int64(i + 1)
				if tc.oversized {
					hop.AffectedHeaders = make([]string, 128)
					for j := range hop.AffectedHeaders {
						hop.AffectedHeaders[j] = fmt.Sprintf("x-%03d-%s", j, strings.Repeat("a", 55))
					}

					hop.AffectedHeaderCount = 128
				}

				source.Chain = append(source.Chain, hop)
				subjects.signers = append(subjects.signers, missing)
			}

			source.TargetSequence = int64(tc.count)
			source.TargetMessageInstance = int64(tc.count)

			result, err := cfg.compose(source, subjects, geographicEvidence{state: "not_found"})
			if (err == nil) != tc.valid {
				t.Fatalf("bound %s: %v", tc.name, err)
			}

			if err != nil && len(result.chain) != 0 {
				t.Fatal("oversized input emitted partial chain")
			}
		})
	}
}
