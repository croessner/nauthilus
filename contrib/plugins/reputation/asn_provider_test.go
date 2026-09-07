package main

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"testing"
)

func TestGeoIPASNResolverRequiresExactFreshCorrelatedEvidence(t *testing.T) {
	source := testASNObservationConfig(t).apiSources["ScanWriter"]
	for _, test := range []struct {
		name, state, ip, provider string
		age, asn                  int64
		valid                     bool
	}{
		{name: "fresh", state: "fresh", ip: "192.0.2.3", age: 1, asn: 64500, provider: source.config.ASNProvider, valid: true},
		{name: "acceptable stale", state: "stale", ip: "192.0.2.3", age: 50 * 86400, asn: 64500, provider: source.config.ASNProvider, valid: true},
		{name: "too stale", state: "stale", ip: "192.0.2.3", age: 100 * 86400, asn: 64500, provider: source.config.ASNProvider},
		{name: "missing", state: "not_found", ip: "192.0.2.3", age: 1, provider: source.config.ASNProvider},
		{name: "unavailable", state: "unavailable", ip: "192.0.2.3", age: 1, asn: 64500, provider: source.config.ASNProvider},
		{name: "wrong IP", state: "fresh", ip: "192.0.2.4", age: 1, asn: 64500, provider: source.config.ASNProvider},
		{name: "wrong provider", state: "fresh", ip: "192.0.2.3", age: 1, asn: 64500, provider: "reputation/plugin.other.peer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, err := recordInputs([]outputInput{stringOutput("lookup_state", test.state), stringOutput("ip", test.ip),
				{name: "asn", input: pluginapi.DecisionValueInput{Integer: &test.asn}},
				{name: "data_age_seconds", input: pluginapi.DecisionValueInput{Integer: &test.age}},
			})
			requireNoError(t, err)

			resolver := providerASNResolver{source: source, records: []pluginapi.DecisionRecord{record}}

			asn, err := resolver.lookupASN(t.Context(), test.provider, "192.0.2.3")
			if test.valid {
				requireNoError(t, err)

				if asn != "64500" {
					t.Fatal("wrong ASN")
				}
			} else {
				requireError(t, err)
			}
		})
	}
}

func TestGeoIPASNSourceRequiresExactProviderFactAndAge(t *testing.T) {
	for _, field := range []string{"asn_fact", "asn_provider", "asn_max_age"} {
		t.Run(field, func(t *testing.T) {
			raw := testGeoIPReputationConfig(t)
			raw["sources"].(map[string]any)["scan"].(map[string]any)[field] = "invalid"
			_, err := decodeConfig(pluginregistry.NewConfigView(raw))
			requireError(t, err)
		})
	}
}

// TestObservationWithoutASNRetainsIndependentPeerEvidence distinguishes a verified miss from unavailable attribution.
func TestObservationWithoutASNRetainsIndependentPeerEvidence(t *testing.T) {
	cfg := testASNObservationConfig(t)
	source := cfg.apiSources["ScanWriter"]
	input := testObservation()

	for _, test := range []struct {
		name, state string
		age, asn    int64
		duplicate   bool
		omitASN     bool
		accepted    bool
	}{
		{name: "verified miss", state: "not_found", age: 1, accepted: true},
		{name: "verified miss without ASN field", state: "not_found", age: 1, omitASN: true, accepted: true},
		{name: "outage", state: "unavailable", age: 1},
		{name: "expired miss", state: "not_found", age: 100 * 86400},
		{name: "contradictory miss", state: "not_found", age: 1, asn: 64500},
		{name: "duplicate miss", state: "not_found", age: 1, duplicate: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			inputs := []outputInput{stringOutput("lookup_state", test.state), stringOutput("ip", "192.0.2.3"),
				{name: "data_age_seconds", input: pluginapi.DecisionValueInput{Integer: &test.age}}}
			if !test.omitASN {
				inputs = append(inputs, outputInput{name: "asn", input: pluginapi.DecisionValueInput{Integer: &test.asn}})
			}

			record, err := recordInputs(inputs)
			requireNoError(t, err)

			resolver := providerASNResolver{source: source, records: []pluginapi.DecisionRecord{record}}
			if test.duplicate {
				resolver.records = append(resolver.records, record)
			}

			admitted, reason, err := cfg.admitObservation(t.Context(), source, input, input.observedAt, testTagger(t), resolver)
			if !test.accepted {
				requireError(t, err)

				return
			}

			requireNoError(t, err)

			if reason != reasonValid || len(admitted.subjects) != 2 {
				t.Fatal("verified ASN absence discarded independent IP/network evidence")
			}

			for _, subject := range admitted.subjects {
				if subject.kind == kindASN {
					t.Fatal("verified absence invented ASN evidence")
				}
			}
		})
	}
}
