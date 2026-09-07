package main

import (
	projection "github.com/croessner/nauthilus/v4/contrib/plugins/internal/dkim2projection"
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	"net/netip"
	"testing"
)

// TestChainCorrelationRejectsEveryCrossHopSubstitution prevents partial or reordered signer attribution.
func TestChainCorrelationRejectsEveryCrossHopSubstitution(t *testing.T) {
	chain := []projection.Hop{
		{Sequence: 1, MessageInstance: 4, SignerDomain: "first.example", HopBinding: make([]byte, 32)},
		{Sequence: 2, MessageInstance: 7, SignerDomain: "last.example", HopBinding: append([]byte{1}, make([]byte, 31)...)},
	}
	source := projection.Projection{Chain: chain, TargetSequence: 2, TargetMessageInstance: 7, ClientIP: netip.MustParseAddr("192.0.2.1")}

	tuples := []assessedSubject{
		{role: "signer", kind: "dns_domain", domain: chain[0].SignerDomain, sequence: 1, instance: 4, binding: chain[0].HopBinding, tuple: view.Tuple{State: view.NotFound, Profile: "operational", Band: view.Unknown, Override: view.NoOverride}},
		{role: "signer", kind: "dns_domain", domain: chain[1].SignerDomain, sequence: 2, instance: 7, binding: chain[1].HopBinding, tuple: view.Tuple{State: view.NotFound, Profile: "operational", Band: view.Unknown, Override: view.NoOverride}},
	}
	if _, err := correlateSubjects(source, tuples, "operational"); err != nil {
		t.Fatal(err)
	}

	for _, mutation := range []string{"count", "sequence", "instance", "binding", "domain", "profile", "order", "role"} {
		t.Run(mutation, func(t *testing.T) {
			changed := append([]assessedSubject(nil), tuples...)

			switch mutation {
			case "count":
				changed = changed[:1]
			case "sequence":
				changed[0].sequence = 2
			case "instance":
				changed[0].instance = 7
			case "binding":
				changed[0].binding = chain[1].HopBinding
			case "domain":
				changed[0].domain = chain[1].SignerDomain
			case "profile":
				changed[0].tuple.Profile = "fast"
			case "order":
				changed[0], changed[1] = changed[1], changed[0]
			case "role":
				changed[0].role = "unknown"
			}

			if _, err := correlateSubjects(source, changed, "operational"); err == nil {
				t.Fatal("uncorrelated signer input accepted")
			}
		})
	}
}
