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
